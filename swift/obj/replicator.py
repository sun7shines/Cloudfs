# Copyright (c) 2010-2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
from os.path import basename, dirname, isdir, join
import random
import shutil
import time
import logging
import hashlib
import itertools
import cPickle as pickle
import errno
import uuid

import eventlet
from eventlet import GreenPool, tpool, Timeout, sleep, hubs
from eventlet.green import subprocess
from eventlet.support.greenlets import GreenletExit

from swift.common.ring import Ring
from swift.common.utils import whataremyips, unlink_older_than, lock_path, \
        compute_eta, get_logger, write_pickle, renamer, dump_recon_cache, \
        rsync_ip
from swift.common.bufferedhttp import http_connect
from swift.common.daemon import Daemon
from swift.common.http import HTTP_OK, HTTP_INSUFFICIENT_STORAGE

hubs.use_hub('poll')

PICKLE_PROTOCOL = 2
ONE_WEEK = 604800
HASH_FILE = 'hashes.pkl'


def quarantine_renamer(device_path, corrupted_file_path):
    """
    In the case that a file is corrupted, move it to a quarantined
    area to allow replication to fix it.

    :params device_path: The path to the device the corrupted file is on.
    :params corrupted_file_path: The path to the file you want quarantined.

    :returns: path (str) of directory the file was moved to
    :raises OSError: re-raises non errno.EEXIST / errno.ENOTEMPTY
                     exceptions from rename
    """
    from_dir = dirname(corrupted_file_path)
    to_dir = join(device_path, 'quarantined', 'objects', basename(from_dir))
    invalidate_hash(dirname(from_dir))
    try:
        renamer(from_dir, to_dir)
    except OSError, e:
        if e.errno not in (errno.EEXIST, errno.ENOTEMPTY):
            raise
        to_dir = "%s-%s" % (to_dir, uuid.uuid4().hex)
        renamer(from_dir, to_dir)
    return to_dir


def hash_suffix(path, reclaim_age):
    """
    Performs reclamation and returns an md5 of all (remaining) files.

    :param reclaim_age: age in seconds at which to remove tombstones
    """
    md5 = hashlib.md5()
    for hsh in sorted(os.listdir(path)):
        hsh_path = join(path, hsh)
        try:
            files = os.listdir(hsh_path)
        except OSError, err:
            if err.errno == errno.ENOTDIR:
                partition_path = dirname(path)
                objects_path = dirname(partition_path)
                device_path = dirname(objects_path)
                quar_path = quarantine_renamer(device_path, hsh_path)
                logging.exception(
                    _('Quarantined %s to %s because it is not a directory') %
                    (hsh_path, quar_path))
                continue
            raise
        if len(files) == 1:
            if files[0].endswith('.ts'):
                # remove tombstones older than reclaim_age
                ts = files[0].rsplit('.', 1)[0]
                if (time.time() - float(ts)) > reclaim_age:
                    os.unlink(join(hsh_path, files[0]))
                    files.remove(files[0])
        elif files:
            files.sort(reverse=True)
            meta = data = tomb = None
            for filename in list(files):
                if not meta and filename.endswith('.meta'):
                    meta = filename
                if not data and filename.endswith('.data'):
                    data = filename
                if not tomb and filename.endswith('.ts'):
                    tomb = filename
                if (filename < tomb or       # any file older than tomb
                    filename < data or       # any file older than data
                    (filename.endswith('.meta') and
                     filename < meta)):      # old meta
                    os.unlink(join(hsh_path, filename))
                    files.remove(filename)
        if not files:
            os.rmdir(hsh_path)
        for filename in files:
            md5.update(filename)
    try:
        os.rmdir(path)
    except OSError:
        pass
    return md5.hexdigest()


def invalidate_hash(suffix_dir):
    """
    Invalidates the hash for a suffix_dir in the partition's hashes file.

    :param suffix_dir: absolute path to suffix dir whose hash needs
                       invalidating
    """

    suffix = os.path.basename(suffix_dir)
    partition_dir = os.path.dirname(suffix_dir)
    hashes_file = join(partition_dir, HASH_FILE)
    with lock_path(partition_dir):
        try:
            with open(hashes_file, 'rb') as fp:
                hashes = pickle.load(fp)
            if suffix in hashes and not hashes[suffix]:
                return
        except Exception:
            return
        hashes[suffix] = None
        write_pickle(hashes, hashes_file, partition_dir, PICKLE_PROTOCOL)


def get_hashes(partition_dir, recalculate=[], do_listdir=False,
               reclaim_age=ONE_WEEK):
    """
    Get a list of hashes for the suffix dir.  do_listdir causes it to mistrust
    the hash cache for suffix existence at the (unexpectedly high) cost of a
    listdir.  reclaim_age is just passed on to hash_suffix.

    :param partition_dir: absolute path of partition to get hashes for
    :param recalculate: list of suffixes which should be recalculated when got
    :param do_listdir: force existence check for all hashes in the partition
    :param reclaim_age: age at which to remove tombstones

    :returns: tuple of (number of suffix dirs hashed, dictionary of hashes)
    """

    hashed = 0
    hashes_file = join(partition_dir, HASH_FILE)
    modified = False
    hashes = {}
    mtime = -1
    try:
        with open(hashes_file, 'rb') as fp:
            hashes = pickle.load(fp)
        mtime = os.path.getmtime(hashes_file)
    except Exception:
        do_listdir = True
    if do_listdir:
        for suff in os.listdir(partition_dir):
            if len(suff) == 3 and isdir(join(partition_dir, suff)):
                hashes.setdefault(suff, None)
        modified = True
    hashes.update((hash_, None) for hash_ in recalculate)
    for suffix, hash_ in hashes.items():
        if not hash_:
            suffix_dir = join(partition_dir, suffix)
            if isdir(suffix_dir):
                try:
                    hashes[suffix] = hash_suffix(suffix_dir, reclaim_age)
                    hashed += 1
                except OSError:
                    logging.exception(_('Error hashing suffix'))
            else:
                del hashes[suffix]
            modified = True
    if modified:
        with lock_path(partition_dir):
            if not os.path.exists(hashes_file) or \
                        os.path.getmtime(hashes_file) == mtime:
                write_pickle(
                    hashes, hashes_file, partition_dir, PICKLE_PROTOCOL)
                return hashed, hashes
        return get_hashes(partition_dir, recalculate, do_listdir,
                          reclaim_age)
    else:
        return hashed, hashes


def tpool_reraise(func, *args, **kwargs):
    """
    Hack to work around Eventlet's tpool not catching and reraising Timeouts.
    """
    def inner():
        try:
            return func(*args, **kwargs)
        except BaseException, err:
            return err
    resp = tpool.execute(inner)
    if isinstance(resp, BaseException):
        raise resp
    return resp
