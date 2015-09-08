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

from __future__ import with_statement

import os
import time
import traceback
from urllib import unquote
from xml.sax import saxutils

from eventlet import Timeout
from webob import Request, Response
from webob.exc import HTTPAccepted, HTTPBadRequest, \
    HTTPCreated, HTTPForbidden, HTTPInternalServerError, \
    HTTPMethodNotAllowed, HTTPNoContent, HTTPNotFound, \
    HTTPPreconditionFailed, HTTPConflict,HTTPOk

from swift.common.utils import get_logger, get_param, hash_path, public, \
    normalize_timestamp, split_path, storage_directory, TRUE_VALUES, \
    validate_device_partition, json
from swift.common.constraints import ACCOUNT_LISTING_LIMIT, \
    check_mount, check_float, check_utf8, FORMAT2CONTENT_TYPE

from swift.common.http import HTTPInsufficientStorage
from swift.common.bufferedhttp import jresponse


DATADIR = 'accounts'

class AccountController(object):
    """WSGI controller for the account server."""

    def __init__(self, conf):
        self.logger = get_logger(conf, log_route='account-server')
        self.root = conf.get('devices', '/mnt/cloudfs-object')
        self.mount_check = conf.get('mount_check', 'true').lower() in \
                              ('true', 't', '1', 'on', 'yes', 'y')
        
        self.auto_create_account_prefix = \
            conf.get('auto_create_account_prefix') or '.'

    def _get_account_broker(self, drive, part, account):
        return None
    
    @public
    def DELETE(self, req):
        """Handle HTTP DELETE request."""
        start_time = time.time()
        
        try:
            drive, part, account = split_path(unquote(req.path), 3)
            validate_device_partition(drive, part)
        except ValueError, err:
            return jresponse('-1', 'bad request',req,400) 
        
        if self.mount_check and not check_mount(self.root, drive):    
            return jresponse('-1', 'insufficient storage', req,507)
        
        broker = self._get_account_broker(drive, part, account)
        if broker.is_deleted():
            return jresponse('-1', 'not found', req,404)
        
        broker.delete_db(req.headers['x-timestamp'])
        return jresponse('0', '', req,204)

    @public
    def PUT(self, req):
        """Handle HTTP PUT request."""
        start_time = time.time()
        try:
            drive, part, account, container = split_path(unquote(req.path),
                                                         3, 4)
            validate_device_partition(drive, part)
        except ValueError, err:
            return jresponse('-1', 'bad request', req,400)
        
        if self.mount_check and not check_mount(self.root, drive):
            return jresponse('-1', 'insufficient storage', req,507)
        
        broker = self._get_account_broker(drive, part, account)
        if container:   # put account container
            
            if account.startswith(self.auto_create_account_prefix) and \
                    not os.path.exists(broker.db_file):
                pass
           
            if req.headers.get('x-account-override-deleted', 'no').lower() != \
                    'yes' and broker.is_deleted():
                return jresponse('-1', 'not found', req,404)
            broker.put_container(container, req.headers['x-put-timestamp'],
                req.headers['x-delete-timestamp'],
                req.headers['x-object-count'],
                req.headers['x-bytes-used'])
            
            if req.headers['x-delete-timestamp'] > req.headers['x-put-timestamp']:
                return jresponse('0', '', req,204)
            else:
                return jresponse('0', '', req,201)
            
        else:   # put account
            timestamp = normalize_timestamp(req.headers['x-timestamp'])
    
            if True:
                created = broker.is_deleted()
                broker.update_put_timestamp(timestamp)
                if broker.is_deleted():
                    return jresponse('-1', 'conflict', req,409)
            metadata = {}
            metadata.update((key, value)
                for key, value in req.headers.iteritems()
                if key.lower().startswith('x-account-meta-'))
            if metadata:
                broker.update_metadata(metadata)
            
            return jresponse('0', '', req,201)

    @public
    def HEAD(self, req):
        """Handle HTTP HEAD request."""
        start_time = time.time()
        try:
            drive, part, account, container = split_path(unquote(req.path),
                                                         3, 4)
            validate_device_partition(drive, part)
        except ValueError, err:
            return jresponse('-1', 'bad request', req,400)
        
        if self.mount_check and not check_mount(self.root, drive):
            return jresponse('-1', 'insufficient storage', req,507)
        
        broker = self._get_account_broker(drive, part, account)
        
        if broker.is_deleted():
            return jresponse('-1', 'not found', req,404)
        info = broker.get_info()
        headers = {
            'X-Account-Container-Count': info['container_count'],
            'X-Account-Object-Count': info['object_count'],
            'X-Account-Bytes-Used': info['bytes_used'],
            'X-Timestamp': info['created_at'],
            'X-PUT-Timestamp': info['put_timestamp']}
        if container:
            container_ts = broker.get_container_timestamp(container)
            if container_ts is not None:
                headers['X-Container-Timestamp'] = container_ts
        headers.update((key, value)
            for key, value in broker.metadata.iteritems()
            if value != '')
        
        response = jresponse('0', '', req,204,headers)
        return response
    
    
    @public
    def META(self, req):
        
        start_time = time.time()
        try:
            drive, part, account, container = split_path(unquote(req.path),
                                                         3, 4)
            validate_device_partition(drive, part)
        except ValueError, err:
            return jresponse('-1', 'bad request', req,400)
        
        if self.mount_check and not check_mount(self.root, drive):
            return jresponse('-1','insufficient storage',req,507)
            
        broker = self._get_account_broker(drive, part, account)
        
        if broker.is_deleted():
            return jresponse('-1', 'not found', req,404)
        
        info = broker.get_info()
        headers = {
            'X-Account-Container-Count': info['container_count'],
            'X-Account-Object-Count': info['object_count'],
            'X-Account-Bytes-Used': info['bytes_used'],
            'X-Timestamp': info['created_at'],
            'X-PUT-Timestamp': info['put_timestamp']}
        if container:
            container_ts = broker.get_container_timestamp(container)
            if container_ts is not None:
                headers['X-Container-Timestamp'] = container_ts
        headers.update((key, value)
            for key, value in broker.metadata.iteritems()
            if value != '')
        
        hdata = json.dumps(headers)
        ret = Response(body=hdata, request=req)
        
        ret.charset = 'utf-8'
        return ret
    
    @public
    def GET(self, req):
        """Handle HTTP GET request."""
        
        start_time = time.time()
        try:
            drive, part, account = split_path(unquote(req.path), 3)
            validate_device_partition(drive, part)
        except ValueError, err:
            return jresponse('-1', 'bad request', req,400)
        
        if self.mount_check and not check_mount(self.root, drive):
            return jresponse('-1', 'insufficient storage', req,507)
        
        broker = self._get_account_broker(drive, part, account)
        
        if broker.is_deleted():
            return jresponse('-1', 'not found', req,404)
        info = broker.get_info()
        
        try:
            prefix = get_param(req, 'prefix')
            delimiter = get_param(req, 'delimiter')
            if delimiter and (len(delimiter) > 1 or ord(delimiter) > 254):
                # delimiters can be made more flexible later
                return jresponse('-1', 'bad delimiter', req,412)
            
            limit = ACCOUNT_LISTING_LIMIT
            given_limit = get_param(req, 'limit')
            if given_limit and given_limit.isdigit():
                limit = int(given_limit)
                if limit > ACCOUNT_LISTING_LIMIT:
                    
                    respbody='Maximum limit is %d' % ACCOUNT_LISTING_LIMIT
                    jresponse('-1', respbody, req,412)
                    
            marker = get_param(req, 'marker', '')
            end_marker = get_param(req, 'end_marker')
            query_format = get_param(req, 'format')
        except UnicodeDecodeError, err:
            return jresponse('-1', 'parameters not utf8', req,400)
        
        if query_format:
            req.accept = FORMAT2CONTENT_TYPE.get(query_format.lower(),
                                                 FORMAT2CONTENT_TYPE['plain'])
            
        req.accept = out_content_type = 'application/json'
        
        account_list = broker.list_containers_iter(limit, marker, end_marker,
                                                   prefix, delimiter)
        
        data = []
        for (name, object_count, bytes_used, is_subdir) in account_list:
            # all containers is dir,no file exists
            data.append({'name': name, 'last_modified': str(int(time.time()))})
            
        account_list = json.dumps(data)
        
        if not account_list:
            return jresponse('0', '', req,204)
            
        ret = Response(body=account_list, request=req)
        ret.content_type = out_content_type
        ret.charset = 'utf-8'
        return ret

    @public
    def POST(self, req):
        
        """Handle HTTP POST request."""
        start_time = time.time()
        try:
            drive, part, account = split_path(unquote(req.path), 3)
            validate_device_partition(drive, part)
        except ValueError, err:
            return jresponse('-1', 'bad request', req,400)
        
        if 'x-timestamp' not in req.headers or \
                not check_float(req.headers['x-timestamp']):
            return jresponse('-1', 'Missing or bad timestamp', req,400) 
        
        if self.mount_check and not check_mount(self.root, drive):
            return jresponse('-1', 'insufficient storage', req,507)
        
        broker = self._get_account_broker(drive, part, account)
        if broker.is_deleted():
            return jresponse('-1', 'not found', req,404)
        
        timestamp = normalize_timestamp(req.headers['x-timestamp'])
        metadata = {}
        metadata.update((key, value)
            for key, value in req.headers.iteritems()
            if key.lower().startswith('x-account-meta-'))
        if metadata:
            broker.update_metadata(metadata)
        return jresponse('0', '', req,204)

    def __call__(self, env, start_response):
        start_time = time.time()
        req = Request(env)
        
        self.logger.txn_id = req.headers.get('x-trans-id', None)
        if not check_utf8(req.path_info):
            res = jresponse('-1', 'invalid utf8', req,412)
        else:
            try:
                # disallow methods which are not publicly accessible
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
                
        trans_time = '%.4f' % (time.time() - start_time)
        additional_info = ''
        if res.headers.get('x-container-timestamp') is not None:
            additional_info += 'x-container-timestamp: %s' % \
                res.headers['x-container-timestamp']
        
        return res(env, start_response)


def app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating WSGI account server apps"""
    conf = global_conf.copy()
    conf.update(local_conf)
    return AccountController(conf)
