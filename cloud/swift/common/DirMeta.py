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
import subprocess
from cloud.swift.common.utils import clean_metadata, dir_empty, rmdirs, \
     mkdirs, do_unlink,validate_account, validate_container, is_marker, \
     get_container_details, get_account_details, get_container_metadata, \
     create_container_metadata, create_account_metadata, DEFAULT_GID, \
     DEFAULT_UID, validate_object, create_object_metadata, read_metadata, \
     write_metadata, X_CONTENT_TYPE, X_CONTENT_LENGTH, X_TIMESTAMP, X_FILE_TYPE,\
     X_PUT_TIMESTAMP, X_TYPE, X_ETAG, X_OBJECTS_COUNT, X_BYTES_USED, \
     X_CONTAINER_COUNT, CONTAINER,meta_write_metadata,meta_read_metadata,\
     meta_create_object_metadata
          
from swift.common.constraints import CONTAINER_LISTING_LIMIT
from swift.common.utils import normalize_timestamp, TRUE_VALUES

from cloud.swift.common.path_utils import parent_path,GetPathSize

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

class DirMeta(DiskCommon):
    """
    Manage object files on disk.

    :param path: path to devices on the node
    :param drive:  volume drive name
    :param account: account name for the object
    :param container: container name for the object
    :param logger: account or container server logging object
    :param uid: user ID container object should assume
    :param gid: group ID container object should assume
    """

    def __init__(self, path, drive, account, container,direr, logger,
                 uid=DEFAULT_UID, gid=DEFAULT_GID,recycle_uuid=''):
        self.root = path
        self.container = container
        self.datadir = os.path.join(path, drive,container,direr)
        
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
       
        self.fhr_path = parent_path(self.datadir)
       
        if 'recycle' == container:
            self.recycle_uuid = recycle_uuid
            self.metafile = os.path.join(path, drive,container +'/'+'meta',self.recycle_uuid)
            self.meta_fhr_path = parent_path(self.metafile) 
            
        if self.meta_fhr_dir_is_deleted():
            # self.create_dir_object(self.meta_fhr_path)
            self.tmp_meta_fhr_path = self.meta_fhr_path
            while not os.path.exists(self.tmp_meta_fhr_path):
                self.create_dir_object(self.tmp_meta_fhr_path)
                self.tmp_meta_fhr_path = parent_path(parent_path(self.tmp_meta_fhr_path)) + '/' +self.metauuid
                
        if not os.path.exists(self.datadir):
            return
                  
        self.metadata = meta_read_metadata(self.metafile)
        
    def empty(self):
        return dir_empty(self.datadir)

    def put(self):
        """
        Create and write metatdata to directory/container.
        :param metadata: Metadata to write.
        """
        if not self.dir_exists:
            mkdirs(self.datadir)
            
        os.chown(self.datadir, self.uid, self.gid)
        self.dir_exists = True

    def move(self,srcdir):
        
        # cmd = 'mv %s %s' % (srcdir,self.datadir)
        # os.system(cmd)
        
        cmd = ['mv',srcdir,self.datadir]
        ps = subprocess.Popen(cmd)
        ps.wait()
        
        os.chown(self.datadir, self.uid, self.gid)
        self.dir_exists = True
        

    def copy(self,srcdir):
        
        # cmd = 'cp -rf %s %s' % (srcdir,self.datadir)
        # os.system(cmd)
        
        cmd = ['cp','-rf',srcdir,self.datadir]
        ps = subprocess.Popen(cmd)
        ps.wait()
        
        os.chown(self.datadir, self.uid, self.gid)
        self.dir_exists = True
        
    def unlink(self):
        """
        Remove directory/container if empty.
        """
        
        cmd = ['rm','-rf',self.datadir]
        ps = subprocess.Popen(cmd)
        ps.wait()


    def del_dir(self,dir_path):
        
        # cmd = 'rm -rf %s' % (dir_path)
        # os.system(cmd)
        
        cmd = ['rm','-rf',dir_path]
        ps = subprocess.Popen(cmd)
        ps.wait()
        
    def list_objects_meta_iter(self,start,limit):
        
        self.update_object_count()
        objects, object_count, bytes_used = self.object_info

        if objects:
            objects.sort()

        container_list = []
        if objects:
            for obj in objects:
                list_item = []
                list_item.append(obj)
                obj_path = os.path.join(self.datadir, obj)
                metadata = meta_read_metadata(obj_path)
                if metadata:
                    list_item.append(metadata[X_TIMESTAMP])
                    list_item.append(int(metadata[X_CONTENT_LENGTH]))
                    list_item.append(metadata[X_ETAG])
                    list_item.append(metadata[X_FILE_TYPE])
                    if 'recycle' == self.container:
                        list_item.append(metadata['user_path'])
                        list_item.append(metadata['recycle_uuid'])
                        list_item.append(metadata['ftype'])
                container_list.append(list_item)

        if 'recycle' == self.container:
            container_list.sort(key=lambda x:float(x[1]))
            container_list.reverse()
            
            if start:
                start = int(start)
                if limit:
                    limit = int(limit)
                    return container_list[start:start+limit]
                else:
                    return container_list[start:]
                
        return container_list
    
    def update_object_count(self):
        if not self.object_info:
            self.object_info = get_container_details(self.datadir)

    def update_put_timestamp(self):
        """
        Create the container if it doesn't exist and update the timestamp
        """
        if not os.path.exists(self.datadir):
#            print '00000000000000000000000026' + '  ' +self.datadir
            self.put()
#        else:
#            print '00000000000000000000000028' + '  ' +self.datadir
    def delete_db(self):
        """
        Delete the container
        """
        self.unlink()


    def create_dir_object(self, dir_path):
        
        if os.path.exists(dir_path) and not os.path.isdir(dir_path):
            self.logger.error("Deleting file %s", dir_path)
            self.del_dir(dir_path)
       
        mkdirs(dir_path)
        os.chown(dir_path, self.uid, self.gid)
        
        return True
    
    def fhr_dir_is_deleted(self):
        
        return not os.path.exists(self.fhr_path)
    
    def meta_fhr_dir_is_deleted(self):
        
        return not os.path.exists(self.meta_fhr_path)
    
    def update_metadata(self, metadata):
        
        meta_write_metadata(self.metafile, metadata)
        self.metadata = metadata
        
    def meta_del(self):
        
        if os.path.exists(self.metafile):
            do_unlink(self.metafile)
            
    def get_data_dir_size(self):
        
        return GetPathSize(self.datadir)
