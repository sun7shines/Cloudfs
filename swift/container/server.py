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
from datetime import datetime

from eventlet import Timeout
from webob import Request, Response
from webob.exc import HTTPAccepted, HTTPBadRequest, HTTPConflict, \
    HTTPCreated, HTTPInternalServerError, HTTPNoContent, \
    HTTPNotFound, HTTPPreconditionFailed, HTTPMethodNotAllowed

from swift.common.utils import get_logger, get_param, hash_path, public, \
    normalize_timestamp, storage_directory, split_path, validate_sync_to, \
    TRUE_VALUES, validate_device_partition, json
from swift.common.constraints import CONTAINER_LISTING_LIMIT, \
    check_mount, check_float, check_utf8, FORMAT2CONTENT_TYPE
from swift.common.bufferedhttp import http_connect,jresponse
from swift.common.exceptions import ConnectionTimeout

from swift.common.http import HTTP_NOT_FOUND, is_success, \
    HTTPInsufficientStorage

DATADIR = 'containers'


class ContainerController(object):
    """WSGI Controller for the container server."""

    # Ensure these are all lowercase
    save_headers = ['x-container-read', 'x-container-write',
                    'x-container-sync-key', 'x-container-sync-to','x-versions-location']

    def __init__(self, conf):
        self.logger = get_logger(conf, log_route='container-server')
        self.root = conf.get('devices', '/mnt/cloudfs-object')
        self.mount_check = conf.get('mount_check', 'true').lower() in \
                              TRUE_VALUES
        self.node_timeout = int(conf.get('node_timeout', 3000))
        self.conn_timeout = float(conf.get('conn_timeout', 50))
        self.allowed_sync_hosts = [h.strip()
            for h in conf.get('allowed_sync_hosts', '127.0.0.1').split(',')
            if h.strip()]
          
        self.auto_create_account_prefix = \
            conf.get('auto_create_account_prefix') or '.'
        
        if conf.get('allow_versions', 'f').lower() in TRUE_VALUES:
            self.save_headers.append('x-versions-location')
            
    def _get_container_broker(self, drive, part, account, container):
        
        return None
        
    def account_update(self, req, account, container, broker):
        """
        Update the account server with latest container info.

        :param req: webob.Request object
        :param account: account name
        :param container: container name
        :param borker: container DB broker object
        :returns: if the account request returns a 404 error code,
                  HTTPNotFound response object, otherwise None.
        """
        account_host = req.headers.get('X-Account-Host')
        account_partition = req.headers.get('X-Account-Partition')
        account_device = req.headers.get('X-Account-Device')
        if all([account_host, account_partition, account_device]):
            account_ip, account_port = account_host.rsplit(':', 1)
            new_path = '/' + '/'.join([account, container])
            if isinstance(new_path, unicode):
                new_path = new_path.encode('utf-8')
            
            info = broker.get_info()
            account_headers = {'x-put-timestamp': info['put_timestamp'],
                'x-delete-timestamp': info['delete_timestamp'],
                'x-object-count': info['object_count'],
                'x-bytes-used': info['bytes_used'],
                'x-trans-id': req.headers.get('x-trans-id', '-')}
            if req.headers.get('x-account-override-deleted', 'no').lower() == \
                    'yes':
                account_headers['x-account-override-deleted'] = 'yes'
            try:
                with ConnectionTimeout(self.conn_timeout):
                    conn = http_connect(account_ip, account_port,
                        account_device, account_partition, 'PUT', new_path,
                        account_headers)
                with Timeout(self.node_timeout):
                    account_response = conn.getresponse()
                    account_response.read()
                    if account_response.status == HTTP_NOT_FOUND:
                        return jresponse('-1','not found',req,404)
                    elif not is_success(account_response.status):
                        self.logger.error(_('ERROR Account update failed '
                            'with %(ip)s:%(port)s/%(device)s (will retry '
                            'later): Response %(status)s %(reason)s'),
                            {'ip': account_ip, 'port': account_port,
                             'device': account_device,
                             'status': account_response.status,
                             'reason': account_response.reason})
            except (Exception, Timeout):
                self.logger.exception(_('ERROR account update failed with '
                    '%(ip)s:%(port)s/%(device)s (will retry later)'),
                    {'ip': account_ip, 'port': account_port,
                     'device': account_device})
        return None

    @public
    def DELETE(self, req):
        
        """Handle HTTP DELETE request."""
        start_time = time.time()
        try:
            drive, part, account, container, obj = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return jresponse('-1', 'bad request', req,400)
         
        if 'x-timestamp' not in req.headers or \
                    not check_float(req.headers['x-timestamp']):
            return jresponse('-1', 'Missing timestamp', req, 400)
            
        if self.mount_check and not check_mount(self.root, drive):
            return jresponse('-1', 'insufficient storage', req,507)
         
        broker = self._get_container_broker(drive, part, account, container)
        
        if account.startswith(self.auto_create_account_prefix) and obj and \
                not os.path.exists(broker.db_file):
            pass
        
        if obj:     # delete object
            return jresponse('0', '', req,204) 
        else:
            # delete container
            if not broker.empty():
                return jresponse('-1', 'conflict', req,409) 
            existed = float(broker.get_info()['put_timestamp']) and \
                      not broker.is_deleted()
            broker.delete_db(req.headers['X-Timestamp'])
            if not broker.is_deleted():
                return jresponse('-1', 'conflict', req,409) 
            resp = self.account_update(req, account, container, broker)
            if resp:
                return resp
            if existed:
                return jresponse('0', '', req,204) 
            return jresponse('-1', 'not found', req,404) 

    @public
    def PUT(self, req):
        """Handle HTTP PUT request."""
        
        start_time = time.time()
        try:
            drive, part, account, container, obj = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return jresponse('-1', 'bad request', req,400)
         
        if 'x-timestamp' not in req.headers or \
                    not check_float(req.headers['x-timestamp']):
            return jresponse('-1', 'bad request', req,400)
         
        if 'x-container-sync-to' in req.headers:
            err = validate_sync_to(req.headers['x-container-sync-to'],
                                   self.allowed_sync_hosts)
            if err:
                return jresponse('-1', 'bad request', req,400)
             
        if self.mount_check and not check_mount(self.root, drive):
            return jresponse('-1', 'insufficient storage', req,507)
         
        timestamp = normalize_timestamp(req.headers['x-timestamp'])
        broker = self._get_container_broker(drive, part, account, container)
        if obj:     # put container object
#            print '00000000000000000000000000' + '   '+  req.path
            return jresponse('0', '', req,201) 
        else:   # put container
            if True:
                created = broker.is_deleted()
#                print '00000000000000000000000004' +'    '+ req.path
                broker.update_put_timestamp(timestamp)
#                print '00000000000000000000000074' +'    '+ req.path
                if broker.is_deleted():
#                    print '00000000000000000000000084' +'    '+ req.path
                    return jresponse('-1', 'conflict', req,409) 
                
            metadata = {}
            metadata.update((key, value)
                for key, value in req.headers.iteritems()
                if key.lower() in self.save_headers or
                   key.lower().startswith('x-container-meta-'))
            if metadata:
                if 'X-Container-Sync-To' in metadata:
                    if 'X-Container-Sync-To' not in broker.metadata or \
                            metadata['X-Container-Sync-To'] != \
                            broker.metadata['X-Container-Sync-To']:
                        broker.set_x_container_sync_points(-1, -1)
                broker.update_metadata(metadata)
            resp = self.account_update(req, account, container, broker)
            if resp:
#                print '00000000000000000000000001' +'    '+ req.path
                return resp
#            print '00000000000000000000000002' +'    '+ req.path
            return jresponse('0', '', req,201) 

    @public
    def HEAD(self, req):
        """Handle HTTP HEAD request."""
        start_time = time.time()
        try:
            drive, part, account, container, obj = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return jresponse('-1', 'bad request', req,400)
         
        if self.mount_check and not check_mount(self.root, drive):
            return jresponse('-1', 'insufficient storage', req,507) 
        broker = self._get_container_broker(drive, part, account, container)
        
        if broker.is_deleted():
            return jresponse('-1', 'not found', req,404) 
        
        info = broker.get_info()
        headers = {
            'X-Container-Object-Count': info['object_count'],
            'X-Container-Bytes-Used': info['bytes_used'],
            'X-Timestamp': info['created_at'],
            'X-PUT-Timestamp': info['put_timestamp'],
        }
        headers.update((key, value)
            for key, value in broker.metadata.iteritems()
            if value != '' and (key.lower() in self.save_headers or
                                key.lower().startswith('x-container-meta-')))
        
        
        return jresponse('0', '', req,204,headers)
        
    @public
    def META(self, req):
        """Handle HTTP HEAD request."""
        
        start_time = time.time()
        try:
            drive, part, account, container, obj = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return jresponse('-1', 'bad request', req,400)
         
        if self.mount_check and not check_mount(self.root, drive):
            return jresponse('-1', 'insufficient storage', req,507) 
        broker = self._get_container_broker(drive, part, account, container)
        
        if broker.is_deleted():
            return jresponse('-1', 'not found', req,404) 
        info = broker.get_info()
        headers = {
            'X-Container-Object-Count': info['object_count'],
            'X-Container-Bytes-Used': info['bytes_used'],
            'X-Timestamp': info['created_at'],
            'X-PUT-Timestamp': info['put_timestamp'],
        }
        headers.update((key, value)
            for key, value in broker.metadata.iteritems()
            if value != '' and (key.lower() in self.save_headers or
                                key.lower().startswith('x-container-meta-')))
        
        hdata = json.dumps(headers)
        ret = Response(body=hdata, request=req)
        
        ret.charset = 'utf-8'
        return ret
    
    @public
    def GET(self, req):
        """Handle HTTP GET request."""
        start_time = time.time()
        try:
            drive, part, account, container, obj = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return jresponse('-1', 'bad request', req,400)
         
        if self.mount_check and not check_mount(self.root, drive):
            return jresponse('-1', 'insufficient storage', req,507) 
        broker = self._get_container_broker(drive, part, account, container)
        
        if broker.is_deleted():
            return jresponse('-1', 'not found', req,404) 
        info = broker.get_info()
        
        try:
            path = get_param(req, 'path')
            prefix = get_param(req, 'prefix')
            delimiter = get_param(req, 'delimiter')
            if delimiter and (len(delimiter) > 1 or ord(delimiter) > 254):
                # delimiters can be made more flexible later
                return jresponse('-1', 'bad delimiter', req,412)
             
            marker = get_param(req, 'marker', '')
            end_marker = get_param(req, 'end_marker')
            limit = CONTAINER_LISTING_LIMIT
            given_limit = get_param(req, 'limit')
            if given_limit and given_limit.isdigit():
                limit = int(given_limit)
                if limit > CONTAINER_LISTING_LIMIT:
                    bodyresp='Maximum limit is %d' % CONTAINER_LISTING_LIMIT
                    return jresponse('-1', bodyresp, req,412)
                     
            query_format = get_param(req, 'format')
        except UnicodeDecodeError, err:
            respbody = 'parameters not utf8'
            return jresponse('-1', respbody, req,400) 
            
        req.accept = out_content_type = 'application/json'
        recursive = req.headers.get('x-recursive') or req.GET.get('recursive')
        if marker or end_marker or prefix or delimiter or path:
            container_list_data = broker.prefix_list_objects_iter(limit, marker, end_marker,
                                                             prefix, delimiter, path)
        else:
            container_list_data = broker.list_objects_iter(recursive)
            
        container_list = json.dumps(container_list_data)
        
        if not container_list:
            return jresponse('0', '', req,204) 

        ret = Response(body=container_list, request=req)
        ret.content_type = out_content_type
        ret.charset = 'utf-8'
        return ret
    
    @public
    def POST(self, req):
        """Handle HTTP POST request."""
        
        start_time = time.time()
        try:
            drive, part, account, container = split_path(unquote(req.path), 4)
            validate_device_partition(drive, part)
        except ValueError, err:
            return jresponse('-1', 'bad request', req,400) 
        if 'x-timestamp' not in req.headers or \
                not check_float(req.headers['x-timestamp']):
            return jresponse('-1', 'bad request', req,400) 
        if 'x-container-sync-to' in req.headers:
            err = validate_sync_to(req.headers['x-container-sync-to'],
                                   self.allowed_sync_hosts)
            if err:
                return jresponse('-1', 'bad request', req,400) 
        if self.mount_check and not check_mount(self.root, drive):
            return jresponse('-1', 'insufficient storage', req,507) 
        broker = self._get_container_broker(drive, part, account, container)
        if broker.is_deleted():
            return jresponse('-1', 'not found', req,404) 
        timestamp = normalize_timestamp(req.headers['x-timestamp'])
        metadata = {}
        metadata.update((key, value)
            for key, value in req.headers.iteritems()
            if key.lower() in self.save_headers or
               key.lower().startswith('x-container-meta-'))
        
        if metadata:
            if 'X-Container-Sync-To' in metadata:
                if 'X-Container-Sync-To' not in broker.metadata or \
                        metadata['X-Container-Sync-To']!= \
                        broker.metadata['X-Container-Sync-To']:
                    broker.set_x_container_sync_points(-1, -1)
            broker.update_metadata(metadata)
        return jresponse('0', '', req,204) 

    def __call__(self, env, start_response):
        
        start_time = time.time()
        req = Request(env)
        self.logger.txn_id = req.headers.get('x-trans-id', None)
        if not check_utf8(req.path_info):
            res = jresponse('-1','Invalid UTF8',req,412)
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
                    # if req.method == 'PUT':
                    #    print 'path:   '+req.path +  '      status:  '+str(res.status_int) + '  msg: '+res.body
            except (Exception, Timeout):
                self.logger.exception(_('ERROR __call__ error with %(method)s'
                    ' %(path)s '), {'method': req.method, 'path': req.path})
                res = jresponse('-1', 'InternalServerError', req,500)
        
        return res(env, start_response)


def app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating WSGI container server apps"""
    conf = global_conf.copy()
    conf.update(local_conf)
    return ContainerController(conf)
