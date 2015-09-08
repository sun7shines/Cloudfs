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

import syslog
import array
import cPickle as pickle
from collections import defaultdict
from gzip import GzipFile
from os.path import getmtime, join as pathjoin
import struct
from time import time
import os
from io import BufferedReader

from swift.common.utils import hash_path, validate_configuration
from swift.common.ring.utils import tiers_for_dev

try:
    import simplejson as json
except ImportError:
    import json

class Ring(object):
    """
    Partitioned consistent hashing ring.

    :param serialized_path: path to serialized RingData instance
    :param reload_time: time interval in seconds to check for a ring change
    """

    def __init__(self, serialized_path, reload_time=15, ring_name=None):
        # can't use the ring unless HASH_PATH_SUFFIX is set
        validate_configuration()
        if ring_name:
            self.serialized_path = os.path.join(serialized_path,
                                                ring_name + '.ring.gz')
            self.ring_name = ring_name
            
        else:
            self.serialized_path = os.path.join(serialized_path)
            
        self.reload_time = reload_time
        self._reload()

    def _reload(self,):
        self._rtime = time() + self.reload_time
       
        if self.ring_name == 'account':
            self._devs = [{'zone': 1, 'weight': 100.0, 'ip': '127.0.0.1', 'id': 0, 'meta': '', 'device': 'glfs1', 'port': 6012}]
            
        elif self.ring_name == 'container':
            self._devs = [{'zone': 1, 'weight': 100.0, 'ip': '127.0.0.1', 'id': 0, 'meta': '', 'device': 'glfs1', 'port': 6011}]
        elif self.ring_name == 'direr':
            self._devs = [{'zone': 1, 'weight': 100.0, 'ip': '127.0.0.1', 'id': 0, 'meta': '', 'device': 'glfs1', 'port': 6011}]
            
        elif self.ring_name == 'object':
            self._devs = [{'zone': 1, 'weight': 100.0, 'ip': '127.0.0.1', 'id': 0, 'meta': '', 'device': 'glfs1', 'port': 6010}]
        elif self.ring_name == 'link': 
            self._devs = [{'zone': 1, 'weight': 100.0, 'ip': '127.0.0.1', 'id': 0, 'meta': '', 'device': 'glfs1', 'port': 6010}]
        
            
    @property
    def devs(self):
        """devices in the ring"""
        return self._devs
    
    
