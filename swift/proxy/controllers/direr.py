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

# NOTE: swift_conn
# You'll see swift_conn passed around a few places in this file. This is the
# source httplib connection of whatever it is attached to.
#   It is used when early termination of reading from the connection should
# happen, such as when a range request is satisfied but there's still more the
# source connection would like to send. To prevent having to read all the data
# that could be left, the source connection can be .close() and then reads
# commence to empty out any buffers.
#   These shenanigans are to ensure all related objects can be garbage
# collected. We've seen objects hang around forever otherwise.

import time
from urllib import unquote
from random import shuffle
import syslog

from webob.exc import HTTPBadRequest, HTTPForbidden, HTTPNotFound

from swift.common.utils import normalize_timestamp, public
from swift.common.constraints import  MAX_CONTAINER_NAME_LENGTH
from swift.common.http import HTTP_ACCEPTED
from swift.proxy.controllers.base import Controller, delay_denial

from swift.common.env_utils import *
from swift.common.bufferedhttp import jresponse 

class DirerController(Controller):
    
    server_type = 'Container'

    def __init__(self, app, account_name, container_name, direr_name,**kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)
        self.direr_name = unquote(direr_name)

    def GETorHEAD(self, req):
        """Handler for HTTP GET/HEAD requests."""
        
        if not self.container_info(self.account_name,self.container_name)[1]:
            return jresponse('-1','not found',req,404)
        
        part, nodes = self.app.direr_ring.get_nodes(self.account_name, self.container_name,self.direr_name)
        
        shuffle(nodes)
        
        req.headers['x-ftype'] = req.GET['ftype']
        
        if req.GET.get('start'):
            req.headers['x-start'] = req.GET.get('start')
            if req.GET.get('limit'):
                req.headers['x-limit'] = req.GET.get('limit')
                
        resp = self.GETorHEAD_base(req, _('Direr'), part, nodes,
                req.path_info, len(nodes))

        return resp

    @public
    @delay_denial
    def GET(self, req):
        
        return self.GETorHEAD(req)

    @public
    @delay_denial
    def HEAD(self, req):
        """Handler for HTTP HEAD requests."""
        
        return self.GETorHEAD(req)

    @public
    def PUT(self, req):
        
        (container_partition, containers,_) = self.container_info(self.account_name, self.container_name,
                account_autocreate=self.app.account_autocreate)
        
        if not containers:
            return jresponse('-1', 'not found', req,404) 
        
        direr_partition, direr_nodes = self.app.direr_ring.get_nodes(self.account_name, self.container_name, self.direr_name)
        
        headers = []
        for container in containers:
            
            nheaders = {'X-Timestamp': normalize_timestamp(time.time()),
                        'x-trans-id': self.trans_id,
                        'X-Container-Host': '%(ip)s:%(port)s' % container,
                        'X-Container-Partition': container_partition,
                        'X-Container-Device': container['device'],
                        'x-ftype':req.GET['ftype'],
                        'Connection': 'close'}
                 
            self.transfer_headers(req.headers, nheaders)
            headers.append(nheaders)
            
       
        resp = self.make_requests(self.account_name,req, self.app.direr_ring,
                direr_partition, 'PUT', req.path_info, headers)
        return resp
        
    @public
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        
        # env_comment(req.environ, 'delete dir')
    
        account_partition, accounts = self.account_info(self.account_name,autocreate=False)
        account = accounts[0]
        
        (container_partition, containers,object_versions) = self.container_info(self.account_name, self.container_name,
                account_autocreate=self.app.account_autocreate)
        
        if not containers:
            
            return jresponse('-1', 'not found', req,404)
        
        direr_partition, dirers = self.app.direr_ring.get_nodes(self.account_name, self.container_name,self.direr_name)
        headers = []
        
        for container in containers:
            new_header = {'X-Timestamp': normalize_timestamp(time.time()),
                           'X-Trans-Id': self.trans_id,
                           'X-Container-Host': '%(ip)s:%(port)s' % container,
                           'X-Container-Partition': container_partition,
                           'X-Container-Device': container['device'],
                           'x-ftype':req.GET['ftype'],
                           'Connection': 'close'}
        
            new_header['X-Account-Host'] = '%(ip)s:%(port)s' % account
            new_header['X-Account-Partition'] = account_partition
            new_header['X-Account-Device'] = self.account_name
            
            if object_versions:
                new_header['x-versions-location'] = object_versions
                
            headers.append(new_header)
                
        resp = self.make_requests(self.account_name,req, self.app.direr_ring,
                    direr_partition, 'DELETE_RECYCLE', req.path_info, headers)
        
        return resp
        
    

    @public
    def RESET(self, req):
        """HTTP DELETE request handler."""
        
        account_partition, accounts = self.account_info(self.account_name,autocreate=False)
        account = accounts[0]
        
        (container_partition, containers,object_versions) = self.container_info(self.account_name, self.container_name,
                account_autocreate=self.app.account_autocreate)
        
        if not containers:
            return jresponse('-1', 'not found', req,404)  
        
        direr_partition, dirers = self.app.direr_ring.get_nodes(self.account_name, self.container_name,self.direr_name)
        headers = []
        
        for container in containers:
            new_header = {'X-Timestamp': normalize_timestamp(time.time()),
                           'X-Trans-Id': self.trans_id,
                           'X-Container-Host': '%(ip)s:%(port)s' % container,
                           'X-Container-Partition': container_partition,
                           'X-Container-Device': container['device'],
                           'x-ftype':req.GET['ftype'],
                           'Connection': 'close'}
        
            new_header['X-Account-Host'] = '%(ip)s:%(port)s' % account
            new_header['X-Account-Partition'] = account_partition
            new_header['X-Account-Device'] = self.account_name
                                    
            if object_versions:
                new_header['x-versions-location'] = object_versions
                
            headers.append(new_header)
                
        resp = self.make_requests(self.account_name,req, self.app.direr_ring,
                    direr_partition, 'RESET', req.path_info, headers)
        
        return resp
    

    @public
    def MKDIRS(self,req):
        
        return self.PUT(req)
    
    @public
    @delay_denial
    def LIST(self, req):
        
        old_method = req.method
        req.method = 'GET'
        resp = self.GETorHEAD(req)
        req.method = old_method
        return resp

    @public
    @delay_denial
    def LISTDIR(self,req):
        
        req.headers['x-recursive']=str(req.GET.get('recursive','False')).lower()
        return self.LIST(req)
        
    @public
    def COPY(self,req):    
        
        account_partition, accounts = self.account_info(self.account_name,autocreate=False)
        account = accounts[0]
        
        (container_partition, containers,object_versions) = self.container_info(self.account_name, self.container_name,
                account_autocreate=self.app.account_autocreate)
        
        if not containers:
            return jresponse('-1', 'not found', req,404) 
        
        direr_partition, direr_nodes = self.app.direr_ring.get_nodes(self.account_name, self.container_name, self.direr_name)
        
        headers = []
        for container in containers:
            
            nheaders = {'X-Timestamp': normalize_timestamp(time.time()),
                        'x-trans-id': self.trans_id,
                        'X-Container-Host': '%(ip)s:%(port)s' % container,
                        'X-Container-Partition': container_partition,
                        'X-Container-Device': container['device'],
                        'x-copy-dst':req.headers['Destination'],
                        'x-ftype':req.GET['ftype'],
                        'Connection': 'close'}
                
            nheaders['X-Account-Host'] = '%(ip)s:%(port)s' % account
            nheaders['X-Account-Partition'] = account_partition
            nheaders['X-Account-Device'] = account['device']
                                    
            if object_versions:
                nheaders['x-versions-location'] = object_versions
                 
            self.transfer_headers(req.headers, nheaders)
            headers.append(nheaders)
            
       
        resp = self.make_requests(self.account_name,req, self.app.direr_ring,
                direr_partition, 'COPY', req.path_info, headers)
        return resp
    
    @public
    def MOVE(self,req):
        
        (container_partition, containers,object_versions) = self.container_info(self.account_name, self.container_name,
                account_autocreate=self.app.account_autocreate)
        
        if not containers:
            return jresponse('-1', 'not found', req,404) 
        
        direr_partition, direr_nodes = self.app.direr_ring.get_nodes(self.account_name, self.container_name, self.direr_name)
        
        headers = []
        for container in containers:
            
            nheaders = {'X-Timestamp': normalize_timestamp(time.time()),
                        'x-trans-id': self.trans_id,
                        'X-Container-Host': '%(ip)s:%(port)s' % container,
                        'X-Container-Partition': container_partition,
                        'X-Container-Device': container['device'],
                        'x-move-dst':req.headers['Destination'],
                        'x-ftype':req.GET['ftype'],
                        'Connection': 'close'}
                 
            if object_versions:
                nheaders['x-versions-location'] = object_versions
                
            self.transfer_headers(req.headers, nheaders)
            headers.append(nheaders)
            
       
        resp = self.make_requests(self.account_name,req, self.app.direr_ring,
                direr_partition, 'MOVE', req.path_info, headers)
        return resp
    
    @public
    def RENAME(self,req):
        
        return self.MOVE(req)
    
    
