# Copyright (c) 2012 Red Hat, Inc.
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

import os, errno
import syslog

from cloud.swift.common.utils import clean_metadata, dir_empty, rmdirs, \
     mkdirs, validate_account, validate_container, is_marker,do_unlink, \
     get_container_details, get_account_details, get_container_metadata, \
     DEFAULT_GID, \
     DEFAULT_UID, validate_object, X_CONTENT_TYPE, X_CONTENT_LENGTH, X_TIMESTAMP, \
     X_PUT_TIMESTAMP, X_TYPE, X_ETAG, X_OBJECTS_COUNT, X_BYTES_USED, X_FILE_TYPE,\
     X_CONTAINER_COUNT, CONTAINER,meta_write_metadata,meta_read_metadata,\
     meta_create_object_metadata,meta_create_account_metadata,\
     meta_clean_metadata,meta_create_container_metadata
     
from cloud.swift.common import Cloudfs 

from swift.common.constraints import CONTAINER_LISTING_LIMIT
from swift.common.utils import normalize_timestamp, TRUE_VALUES

from cloud.swift.common.path_utils import parent_path,GetPathSize,path_std


DATADIR = 'containers'

# Create a dummy db_file in /etc/swift
_unittests_enabled = os.getenv('GLUSTER_UNIT_TEST_ENABLED', 'no')
if _unittests_enabled in TRUE_VALUES:
    _tmp_dir = '/tmp/gluster_unit_tests'
    try:
        os.mkdir(_tmp_dir)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
    _db_file = os.path.join(_tmp_dir, 'db_file.db')
else:
    _db_file = '/etc/swift/db_file.db'
if not os.path.exists(_db_file):
    file(_db_file, 'w+')

class DiskCommon(object):
    def is_deleted(self):
        return not os.path.exists(self.datadir)

    def filter_prefix(self, objects, prefix):
        """
        Accept sorted list.
        """
        found = 0
        filtered_objs = []
        for object_name in objects:
            if object_name.startswith(prefix):
                filtered_objs.append(object_name)
                found = 1
            else:
                if found:
                    break
        return filtered_objs

    def filter_delimiter(self, objects, delimiter, prefix):
        """
        Accept sorted list.
        Objects should start with prefix.
        """
        filtered_objs=[]
        for object_name in objects:
            tmp_obj = object_name.replace(prefix, '', 1)
            sufix = tmp_obj.split(delimiter, 1)
            new_obj = prefix + sufix[0]
            if new_obj and new_obj not in filtered_objs:
                filtered_objs.append(new_obj)

        return filtered_objs

    def filter_marker(self, objects, marker):
        """
        TODO: We can traverse in reverse order to optimize.
        Accept sorted list.
        """
        filtered_objs=[]
        found = 0
        if objects[-1] < marker:
            return filtered_objs
        for object_name in objects:
            if object_name > marker:
                filtered_objs.append(object_name)

        return filtered_objs

    def filter_end_marker(self, objects, end_marker):
        """
        Accept sorted list.
        """
        filtered_objs=[]
        for object_name in objects:
            if object_name < end_marker:
                filtered_objs.append(object_name)
            else:
                break

        return filtered_objs

    def filter_limit(self, objects, limit):
        filtered_objs=[]
        for i in range(0, limit):
            filtered_objs.append(objects[i])

        return filtered_objs


class CommonMeta(DiskCommon):
    """
    Manage object files on disk.

    :param path: path to devices on the node
    :param account: account name for the object
    :param container: container name for the object
    :param logger: account or container server logging object
    :param uid: user ID container object should assume
    :param gid: group ID container object should assume
    """

    def __init__(self, path, drive, account, container, logger,
                 uid=DEFAULT_UID, gid=DEFAULT_GID):
        self.root = path
        
        self.datadir = os.path.join(path, drive)
        
        self.account = account
        assert logger is not None
        self.logger = logger
        self.metadata = {}
        self.container_info = None
        self.object_info = None
        self.uid = int(uid)
        self.gid = int(gid)
        self.db_file = _db_file
        self.dir_exists = os.path.exists(self.datadir)
        
        self.metauuid = 'ff89f933b2ca8df40'
        self.fhr_path = parent_path(self.datadir)
        
        self.metafile = os.path.join(path, self.metauuid,drive)
        self.meta_fhr_path = parent_path(self.metafile) 
            
        if self.meta_fhr_dir_is_deleted():
            self.create_dir_object(self.meta_fhr_path)
            
        if not os.path.exists(self.datadir):
            return
        if self.dir_exists:
            self.metadata = meta_read_metadata(self.metafile)    
        else:
            return
        
        if not self.metadata:
            meta_create_account_metadata(self.datadir,self.metafile)
            self.metadata = meta_read_metadata(self.metafile)
        else:
            if not validate_account(self.metadata):
                meta_create_account_metadata(self.datadir,self.metafile)
                self.metadata = meta_read_metadata(self.metafile)

    def empty(self):
        return dir_empty(self.datadir)

    def delete(self):
        if self.empty():
            #For delete account.
            if os.path.ismount(self.datadir):
                meta_clean_metadata(self.datadir)
            else:
                rmdirs(self.datadir)
            self.dir_exists = False

    def put_metadata(self, metadata):
        """
        Write metadata to directory/container.
        """
        meta_write_metadata(self.metafile, metadata)
        self.metadata = metadata

    def put(self, metadata):
        """
        Create and write metatdata to directory/container.
        :param metadata: Metadata to write.
        """
        if not self.dir_exists:
            mkdirs(self.datadir)

        os.chown(self.datadir, self.uid, self.gid)
        meta_write_metadata(self.metafile, metadata)
        self.metadata = metadata
        self.dir_exists = True

    def meta_fhr_dir_is_deleted(self):
        
        return not os.path.exists(self.meta_fhr_path)
    
    def put_obj(self, content_length, timestamp):
        ocnt = self.metadata[X_OBJECTS_COUNT]
        self.metadata[X_OBJECTS_COUNT] = int(ocnt) + 1
        self.metadata[X_PUT_TIMESTAMP] = timestamp
        bused = self.metadata[X_BYTES_USED]
        self.metadata[X_BYTES_USED] = int(bused) + int(content_length)
        #TODO: define update_metadata instad of writing whole metadata again.
        self.put_metadata(self.metadata)

    def delete_obj(self, content_length):
        ocnt = self.metadata[X_OBJECTS_COUNT]
        self.metadata[X_OBJECTS_COUNT] = int(ocnt) - 1
        bused = self.metadata[X_BYTES_USED]
        self.metadata[X_BYTES_USED] = int(bused) - int(content_length)
        self.put_metadata(self.metadata)

    def put_container(self, container, put_timestamp, del_timestamp, object_count, bytes_used):
        """
        For account server.
        """
        self.metadata[X_OBJECTS_COUNT] = 0
        self.metadata[X_BYTES_USED] = 0
        ccnt = self.metadata[X_CONTAINER_COUNT]
        self.metadata[X_CONTAINER_COUNT] = int(ccnt) + 1
        self.metadata[X_PUT_TIMESTAMP] = 1
        self.put_metadata(self.metadata)

    def delete_container(self, object_count, bytes_used):
        """
        For account server.
        """
        self.metadata[X_OBJECTS_COUNT] = 0
        self.metadata[X_BYTES_USED] = 0
        ccnt = self.metadata[X_CONTAINER_COUNT]
        self.metadata[X_CONTAINER_COUNT] = int(ccnt) - 1
        self.put_metadata(self.metadata)

    def meta_del(self):
        
        if os.path.exists(self.metafile):
            do_unlink(self.metafile)
            
    def unlink(self):
        """
        Remove directory/container if empty.
        """
        if dir_empty(self.datadir):
            rmdirs(self.datadir)
            self.meta_del()

    def update_object_count(self):
        if not self.object_info:
            self.object_info = get_container_details(self.datadir)

        objects, object_count, bytes_used = self.object_info

        if X_OBJECTS_COUNT not in self.metadata \
                or int(self.metadata[X_OBJECTS_COUNT]) != object_count \
                or X_BYTES_USED not in self.metadata \
                or int(self.metadata[X_BYTES_USED]) != bytes_used:
            self.metadata[X_OBJECTS_COUNT] = object_count
            self.metadata[X_BYTES_USED] = bytes_used
            meta_write_metadata(self.metafile, self.metadata)

    def update_container_count(self):
        if not self.container_info:
            self.container_info = get_account_details(self.datadir)

        containers, container_count = self.container_info
        if X_CONTAINER_COUNT not in self.metadata \
                or int(self.metadata[X_CONTAINER_COUNT]) != container_count:
            self.metadata[X_CONTAINER_COUNT] = container_count
            meta_write_metadata(self.metafile, self.metadata)

    def get_info(self, include_metadata=False):
        """
        Get global data for the container.
        :returns: dict with keys: account, container, object_count, bytes_used,
                      hash, id, created_at, put_timestamp, delete_timestamp,
                      reported_put_timestamp, reported_delete_timestamp,
                      reported_object_count, and reported_bytes_used.
                  If include_metadata is set, metadata is included as a key
                  pointing to a dict of tuples of the metadata
        """
        # TODO: delete_timestamp, reported_put_timestamp
        #       reported_delete_timestamp, reported_object_count,
        #       reported_bytes_used, created_at
        if not Cloudfs.OBJECT_ONLY:
            # If we are not configured for object only environments, we should
            # update the object counts in case they changed behind our back.
            self.update_object_count()

        data = {'account' : self.account, 'container' : self.container,
                'object_count' : self.metadata.get(X_OBJECTS_COUNT, '0'),
                'bytes_used' : self.metadata.get(X_BYTES_USED, '0'),
                'hash': '', 'id' : '', 'created_at' : '1',
                'put_timestamp' : self.metadata.get(X_PUT_TIMESTAMP, '0'),
                'delete_timestamp' : '1',
                'reported_put_timestamp' : '1', 'reported_delete_timestamp' : '1',
                'reported_object_count' : '1', 'reported_bytes_used' : '1'}
        if include_metadata:
            data['metadata'] = self.metadata
        return data

    def update_put_timestamp(self, timestamp):
        """
        Create the container if it doesn't exist and update the timestamp
        """
        if not os.path.exists(self.datadir):
#            print '00000000000000000000000016' + '  ' +self.datadir
            self.put(self.metadata)
#        else:
#            print '00000000000000000000000018' + '  ' +self.datadir
            
    def delete_db(self, timestamp):
        """
        Delete the container
        """
        self.unlink()
        self.meta_del()
        
    def update_metadata(self, metadata):
        assert self.metadata, "Valid container/account metadata should have been created by now"
        
        if metadata:
            new_metadata = self.metadata.copy()
            
            if metadata.has_key('X-Account-Meta-Bytes-Add'):
                content_length = metadata.get('X-Account-Meta-Bytes-Add')
                bused = new_metadata[X_BYTES_USED]
                new_metadata[X_BYTES_USED] = int(str(bused)) + int(content_length)
                
            elif metadata.has_key('X-Account-Meta-Bytes-Del'):
                content_length = metadata.get('X-Account-Meta-Bytes-Del')
                bused = new_metadata[X_BYTES_USED]
                new_metadata[X_BYTES_USED] = int(str(bused)) - int(content_length)
                
            else:
                new_metadata.update(metadata)
                
            del_keys = ['X-Account-Meta-Bytes-Del','X-Account-Meta-Bytes-Add']
            for dkey in del_keys:
                if  new_metadata.has_key(dkey):
                    new_metadata.pop(dkey)
                      
            if new_metadata != self.metadata:
                meta_write_metadata(self.metafile, new_metadata)
                self.metadata = new_metadata

    def create_dir_object(self, dir_path):
        
        if os.path.exists(dir_path) and not os.path.isdir(dir_path):
            self.logger.error("Deleting file %s", dir_path)
            self.del_dir(dir_path)
       
        mkdirs(dir_path)
        os.chown(dir_path, self.uid, self.gid)
        
        return True
    

class AccountMeta(CommonMeta):
    def __init__(self, root, drive, account, logger):
        super(AccountMeta, self).__init__(root, drive, account, None, logger)
        assert self.dir_exists

    def list_containers_iter(self, limit, marker, end_marker,
                             prefix, delimiter):
        """
        Return tuple of name, object_count, bytes_used, 0(is_subdir).
        Used by account server.
        """
        if delimiter and not prefix:
            prefix = ''

        self.update_container_count()

        containers, container_count = self.container_info

        if containers:
            containers.sort()

        if containers and prefix:
            containers = self.filter_prefix(containers, prefix)

        if containers and delimiter:
            containers = self.filter_delimiter(containers, delimiter, prefix)

        if containers and marker:
            containers = self.filter_marker(containers, marker)

        if containers and end_marker:
            containers = self.filter_end_marker(containers, end_marker)

        if containers and limit:
            if len(containers) > limit:
                containers = self.filter_limit(containers, limit)

        account_list = []
        if containers:
            for cont in containers:
                list_item = []
                metadata = None
                list_item.append(cont)
                cont_path = path_std(os.path.join(self.datadir, cont))
                cont_meta_path = '/'.join(cont_path.split('/')[:-1])+ '/' + self.metauuid+ '/' + cont_path.split('/')[-1]
                metadata = meta_read_metadata(cont_meta_path)
                if not metadata or not validate_container(metadata):
                    metadata = meta_create_container_metadata(cont_path,cont_meta_path)

                if metadata:
                    list_item.append(metadata[X_OBJECTS_COUNT])
                    list_item.append(metadata[X_BYTES_USED])
                    list_item.append(0)
                account_list.append(list_item)

        return account_list

    def get_info(self, include_metadata=False):
        """
        Get global data for the account.
        :returns: dict with keys: account, created_at, put_timestamp,
                  delete_timestamp, container_count, object_count,
                  bytes_used, hash, id
        """
        if not Cloudfs.OBJECT_ONLY:
            # If we are not configured for object only environments, we should
            # update the container counts in case they changed behind our back.
            self.update_container_count()

        data = {'account' : self.account, 'created_at' : '1',
                'put_timestamp' : '1', 'delete_timestamp' : '1',
                'container_count' : self.metadata.get(X_CONTAINER_COUNT, 0),
                'object_count' : self.metadata.get(X_OBJECTS_COUNT, 0),
                'bytes_used' : self.metadata.get(X_BYTES_USED, 0),
                'hash' : '', 'id' : ''}

        if include_metadata:
            data['metadata'] = self.metadata
        return data

    def get_container_timestamp(self, container):
        cont_path = path_std(os.path.join(self.datadir, container))
        cont_meta_path = '/'.join(cont_path.split('/')[:-1])+ '/' + self.metauuid+ '/' + cont_path.split('/')[-1]
        metadata = meta_read_metadata(cont_meta_path)

        return int(metadata.get(X_PUT_TIMESTAMP, '0')) or None
    
    
