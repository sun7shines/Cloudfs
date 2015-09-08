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

""" Object Server for Swift """

from __future__ import with_statement
import cPickle as pickle
import errno
import os
import time
import traceback
from datetime import datetime
from hashlib import md5
from tempfile import mkstemp
from urllib import unquote
from contextlib import contextmanager

from webob import Request, Response, UTC
from webob.exc import HTTPAccepted, HTTPBadRequest, HTTPCreated, \
    HTTPInternalServerError, HTTPNoContent, HTTPNotFound, \
    HTTPNotModified, HTTPPreconditionFailed, \
    HTTPRequestTimeout, HTTPUnprocessableEntity, HTTPMethodNotAllowed
from xattr import getxattr, setxattr
from eventlet import sleep, Timeout, tpool

from swift.common.utils import mkdirs, normalize_timestamp, public, \
    storage_directory, hash_path, renamer, fallocate, \
    split_path, drop_buffer_cache, get_logger, write_pickle, \
    TRUE_VALUES, validate_device_partition
from swift.common.bufferedhttp import http_connect,jresponse
from swift.common.constraints import check_object_creation, check_mount, \
    check_float, check_utf8

from swift.obj.replicator import tpool_reraise, invalidate_hash, \
    quarantine_renamer, get_hashes
    
from swift.common.exceptions import ConnectionTimeout, DiskFileError, \
    DiskFileNotExist

from swift.common.http import is_success, HTTPInsufficientStorage, \
    HTTPClientDisconnect


DATADIR = 'objects'
ASYNCDIR = 'async_pending'
PICKLE_PROTOCOL = 2
METADATA_KEY = 'user.swift.metadata'
MAX_OBJECT_NAME_LENGTH = 1024
# keep these lower-case
DISALLOWED_HEADERS = set('content-length content-type deleted etag'.split())


class DiskLink(object):
   
    def __iter__(self):
        """Returns an iterator over the data file."""
        try:
            dropped_cache = 0
            read = 0
            self.started_at_0 = False
            self.read_to_eof = False
            if self.fp.tell() == 0:
                self.started_at_0 = True
                self.iter_etag = md5()
            while True:
                chunk = self.fp.read(self.disk_chunk_size)
                if chunk:
                    if self.iter_etag:
                        self.iter_etag.update(chunk)
                    read += len(chunk)
                    if read - dropped_cache > (1024 * 1024):
                        self.drop_cache(self.fp.fileno(), dropped_cache,
                            read - dropped_cache)
                        dropped_cache = read
                    yield chunk
                    if self.iter_hook:
                        self.iter_hook()
                else:
                    self.read_to_eof = True
                    self.drop_cache(self.fp.fileno(), dropped_cache,
                        read - dropped_cache)
                    break
        finally:
            self.close()

class LinkController(object):
    
    def __init__(self, app,conf):
        
        self.app = app
        
        self.logger = get_logger(conf, log_route='object-server')
        self.devices = conf.get('devices', '/mnt/cloudfs-object')
        self.mount_check = conf.get('mount_check', 'true').lower() in \
            TRUE_VALUES
        self.node_timeout = int(conf.get('node_timeout', 3000))
        self.conn_timeout = float(conf.get('conn_timeout', 50))
        self.disk_chunk_size = int(conf.get('disk_chunk_size', 65536))
        self.network_chunk_size = int(conf.get('network_chunk_size', 65536))
        self.keep_cache_size = int(conf.get('keep_cache_size', 5242880))
        self.keep_cache_private = \
            conf.get('keep_cache_private', 'false').lower() in TRUE_VALUES
        self.log_requests = \
            conf.get('log_requests', 'true').lower() in TRUE_VALUES
        self.max_upload_time = int(conf.get('max_upload_time', 86400))
        self.slow = int(conf.get('slow', 0))
        
        
    @public
    def PUT(self, request):
        
        try:
            device, partition, account, src_container, src_link = \
                split_path(unquote(request.path), 5, 5, True)
            validate_device_partition(device, partition)
        except ValueError, err:
            return jresponse('-1', 'bad request', request,400) 
    
        try:
            dst_path = request.headers.get('x-link-dst')
            dst_container, dst_link = split_path(
                unquote(dst_path), 1, 2, True)
        except ValueError, err:
            return jresponse('-1', 'bad request', request,400) 
            
        if self.mount_check and not check_mount(self.devices, device):
            return jresponse('-1', 'insufficient storage', request,507) 
        
       
        src_file = DiskLink(self.devices, device, partition, account, src_container,
                        src_link)
        dst_file = DiskLink(self.devices, device, partition, account, dst_container,
                        dst_link)
        
        if not dst_file.cnt_flag:
            return jresponse('-1', 'container not found', request,404) 
        
        if src_file.is_deleted():
            return jresponse('-1', 'not found', request,404) 
        
        if not dst_file.is_deleted():
            return jresponse('-1', 'conflict', request,409) 
                                
        dst_file.link(src_file.data_file)
        
        if dst_file.is_deleted():
            return jresponse('-1', 'conflict', request,409) 
            
        resp = jresponse('0', '', request,201) 
        return resp


    def __call__(self, env, start_response):
        """WSGI Application entry point for the Swift Object Server."""
        
        start_time = time.time()
        req = Request(env)
        if 'l' != req.headers.get('X-Ftype'):
            return self.app(env,start_response)
        
        self.logger.txn_id = req.headers.get('x-trans-id', None)
        
        if not check_utf8(req.path_info):
            res =jresponse('-1', 'Invalid UTF8', req,412) 
        else:
            try:
                # disallow methods which have not been marked 'public'
                try:
                    method = getattr(self, req.method)
                    getattr(method, 'publicly_accessible')
                except AttributeError:
                    res = jresponse('-1', 'method not allowed', req,405) 
                else:
                    res = method(req)
            except (Exception, Timeout):
                self.logger.exception(_('ERROR __call__ error with %(method)s'
                    ' %(path)s '), {'method': req.method, 'path': req.path})
                res = jresponse('-1', 'InternalServerError', req,500)
        trans_time = time.time() - start_time
        
        if req.method in ('PUT', 'DELETE'):
            slow = self.slow - trans_time
            if slow > 0:
                sleep(slow)
        return res(env, start_response)

def filter_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating WSGI container server apps"""
    conf = global_conf.copy()
    conf.update(local_conf)

    def link_filter(app):
        return LinkController(app,conf)
    return link_filter

