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

import subprocess
import os
import os.path
from eventlet import tpool
from tempfile import mkstemp
from contextlib import contextmanager
from swift.common.utils import normalize_timestamp, renamer
from cloud.swift.common.utils import mkdirs, rmdirs, validate_object, \
     create_object_metadata,  do_open, do_close, do_unlink, do_chown, \
     do_stat, do_listdir, read_metadata, write_metadata
from cloud.swift.common.utils import X_CONTENT_TYPE, X_CONTENT_LENGTH, \
     X_TIMESTAMP, X_PUT_TIMESTAMP, X_TYPE, X_ETAG, X_OBJECTS_COUNT, \
     X_BYTES_USED, X_OBJECT_TYPE, FILE, DIR, MARKER_DIR, OBJECT, DIR_TYPE, \
     FILE_TYPE, DEFAULT_UID, DEFAULT_GID

import logging
from swift.link.server import DiskLink


class Gluster_DiskLink(DiskLink):
    
    def __init__(self, path, device, partition, account, container, link):
        
        self.data_file = os.path.join(path,device,container,link)
        self.cntpath =  os.path.join(path,device,container)
        
        self.cnt_flag = self.cnt_exists()
        if not self.cnt_flag:
            return
        
    def is_deleted(self):

        return not os.path.exists(self.data_file)

    def cnt_exists(self):
        
        return os.path.exists(self.cntpath)
    
    def link(self,src_file):
        
        # cmd = 'ln -s %s %s' % (src_file,self.data_file)
        # os.system(cmd)
        
        cmd = ['ln','-s',src_file,self.data_file]
        ps = subprocess.Popen(cmd)
        ps.wait()
        
        return True

