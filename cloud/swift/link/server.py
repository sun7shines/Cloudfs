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


# Simply importing this monkey patches the constraint handling to fit our
# needs
import cloud.swift.common.constraints

from swift.link import server
from cloud.swift.common.DiskLink import Gluster_DiskLink

server.DiskLink = Gluster_DiskLink

# def app_factory(global_conf, **local_conf):
    
#    conf = global_conf.copy()
#    conf.update(local_conf)
#    return server.LinkController(conf)

def filter_factory(global_conf, **local_conf):
    
    conf = global_conf.copy()
    conf.update(local_conf)

    def link_filter(app):
        return server.LinkController(app,conf)
    return link_filter

