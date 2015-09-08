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

import time
from urllib import unquote
from random import shuffle
import syslog

from webob.exc import HTTPBadRequest, HTTPForbidden, HTTPNotFound

from swift.common.utils import normalize_timestamp, public
from swift.common.constraints import MAX_CONTAINER_NAME_LENGTH
from swift.common.http import HTTP_ACCEPTED
from swift.proxy.controllers.base import Controller, delay_denial
from swift.common.env_utils import *
from swift.common.bufferedhttp import jresponse

class ContainerController(Controller):
    """WSGI controller for container requests"""
    server_type = 'Container'

    # Ensure these are all lowercase
    pass_through_headers = ['x-container-read', 'x-container-write',
                            'x-container-sync-key', 'x-container-sync-to',
                            'x-versions-location']

    def __init__(self, app, account_name, container_name, **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)


    def GETorHEAD(self, req):

        """Handler for HTTP GET/HEAD requests."""
        if not self.account_info(self.account_name)[1]:
            return jresponse('-1', 'not found', req,404) 
        part, nodes = self.app.container_ring.get_nodes(self.account_name, self.container_name)
        
        shuffle(nodes)
        resp = self.GETorHEAD_base(req, _('Container'), part, nodes,
                req.path_info, len(nodes))

        if not req.environ.get('swift_owner', False):
            for key in ('x-container-read', 'x-container-write',
                        'x-container-sync-key', 'x-container-sync-to'):
                if key in resp.headers:
                    del resp.headers[key]
        return resp

    @public
    @delay_denial
    def GET(self, req):
        
        return self.GETorHEAD(req)

    @public
    @delay_denial
    def LISTDIR(self, req):
        """Handler for HTTP GET requests."""
        
        old_method = req.method
        req.method = 'GET'
        req.headers['x-recursive']=str(req.GET.get('recursive','False')).lower()
        resp = self.GETorHEAD(req)
        req.method = old_method
        return resp
    
    @public
    @delay_denial
    def HEAD(self, req):
        
        return self.GETorHEAD(req)

    @public
    @delay_denial
    def META(self, req):
        
        
        """Handler for HTTP META requests."""
        if not self.account_info(self.account_name)[1]:
            return jresponse('-1', 'not found', req,404)
        part, nodes = self.app.container_ring.get_nodes(self.account_name, self.container_name)
        
        shuffle(nodes)
        resp = self.META_base(req, _('Container'), part, nodes,
                req.path_info, len(nodes))

        if not req.environ.get('swift_owner', False):
            for key in ('x-container-read', 'x-container-write',
                        'x-container-sync-key', 'x-container-sync-to'):
                if key in resp.headers:
                    del resp.headers[key]
        return resp
    

    @public
    def PUT(self, req):
        """HTTP PUT request handler."""
        if len(self.container_name) > MAX_CONTAINER_NAME_LENGTH:
            
            respbody = 'Container name length of %d longer than %d' % \
                        (len(self.container_name), MAX_CONTAINER_NAME_LENGTH)
            return jresponse('-1', respbody, req,400)
        
        account_partition, accounts = \
            self.account_info(self.account_name,
                              autocreate=self.app.account_autocreate)
        
        if not accounts:
            return jresponse('-1', 'not found', req,404)
        
        container_partition, containers = self.app.container_ring.get_nodes(self.account_name, self.container_name)
        headers = []
        for account in accounts:
            
            nheaders = {'X-Timestamp': normalize_timestamp(time.time()),
                        'x-trans-id': self.trans_id,
                        'X-Account-Host': '%(ip)s:%(port)s' % account,
                        'X-Account-Partition': account_partition,
                        'X-Account-Device': self.account_name,
                        'Connection': 'close'}
            self.transfer_headers(req.headers, nheaders)
            headers.append(nheaders)
        
        resp = self.make_requests(self.account_name,req, self.app.container_ring,
                container_partition, 'PUT', req.path_info, headers)
        return resp

    @public
    def POST(self, req):
        """HTTP POST request handler."""
            
        account_partition, accounts = \
            self.account_info(self.account_name,
                              autocreate=self.app.account_autocreate)
        if not accounts:
            return jresponse('-1', 'not found', req,404)
        container_partition, containers = self.app.container_ring.get_nodes(self.account_name, self.container_name)
        headers = {'X-Timestamp': normalize_timestamp(time.time()),
                   'x-trans-id': self.trans_id,
                   'Connection': 'close'}
        self.transfer_headers(req.headers, headers)
       
        resp = self.make_requests(self.account_name,req, self.app.container_ring,
                container_partition, 'POST', req.path_info,
                [headers] * len(containers))
        return resp

    @public
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        account_partition, accounts = self.account_info(self.account_name)
        if not accounts:
            return jresponse('-1', 'not found', req,404)
        container_partition, containers = self.app.container_ring.get_nodes(self.account_name, self.container_name)
        headers = []
        for account in accounts:
            headers.append({'X-Timestamp': normalize_timestamp(time.time()),
                           'X-Trans-Id': self.trans_id,
                           'X-Account-Host': '%(ip)s:%(port)s' % account,
                           'X-Account-Partition': account_partition,
                           'X-Account-Device': self.account_name,
                           'Connection': 'close'})
        
        resp = self.make_requests(self.account_name,req, self.app.container_ring,
                    container_partition, 'DELETE', req.path_info, headers)
        
        return resp
