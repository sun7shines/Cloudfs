# -*- coding: utf-8 -*-
# Copyright (c) 2013 OpenStack, LLC.
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

import tarfile
from urllib import quote, unquote
from xml.sax import saxutils
from webob.exc import  HTTPBadGateway, \
    HTTPCreated, HTTPBadRequest, HTTPNotFound, HTTPUnauthorized, HTTPOk, \
    HTTPPreconditionFailed, HTTPRequestEntityTooLarge, HTTPNotAcceptable, \
    HTTPLengthRequired

from webob import Request

from swift.common.mx_swob import wsgify

from swift.common.utils import json, TRUE_VALUES
from swift.common.constraints import check_utf8, MAX_FILE_SIZE
from swift.common.http import HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED, \
    HTTP_NOT_FOUND
from swift.common.constraints import MAX_OBJECT_NAME_LENGTH, \
    MAX_CONTAINER_NAME_LENGTH

from swift.common.utils import split_path

MAX_PATH_LENGTH = MAX_OBJECT_NAME_LENGTH + MAX_CONTAINER_NAME_LENGTH + 2

from swift.proxy.controllers.base import get_account_info
from swift.common.middleware.userdb import db_init, task_db_init
from swift.common.bufferedhttp import jresponse

class CreateContainerError(Exception):
    def __init__(self, msg, status_int, status):
        self.status_int = status_int
        self.status = status
        Exception.__init__(self, msg)


ACCEPTABLE_FORMATS = ['text/plain', 'application/json', 'application/xml',
                      'text/xml']


def get_response_body(data_format, data_dict, error_list):
    
    data_dict['Errors'] = error_list
    return data_dict
    
def update_req(new_req):
    
    return new_req

def quota_req(new_req):
    
    new_req.headers['X-Account-Meta-Quota-Bytes'] = 1024*1024*1024
    new_req.method = 'POST'
    new_req.GET['op'] = 'POST'
    return new_req

class Userinit(object):
    
    def __init__(self, app, conf):
        self.devices = conf.get('devices', '/mnt/cloudfs-object')
        self.app = app
            
    def handle_new_req(self,req, user_path,new_method='PUT',new_headers = None,new_params=None,qstr=''):
        
        try:
            version, account, _junk = split_path(req.path,2, 3, True)
        except ValueError:
            return '',HTTPNotFound(request=req)

        new_env = req.environ.copy()    
        del(new_env['wsgi.input'])
        new_env['CONTENT_LENGTH'] = 0
    
        new_path = '/' + version + '/' + account+ user_path
        
        if isinstance(new_path, unicode):
            new_path = new_path.encode('utf-8')
                
        if not check_utf8(new_path):
            return ([quote(new_path), HTTPPreconditionFailed().status])
            
        new_env['PATH_INFO'] = new_path    
        if qstr:
            new_env['QUERY_STRING'] = qstr
            
        new_req = Request.blank(new_path, new_env)
        
        new_req.method = new_method
        if new_headers:
            new_req.headers.update(new_headers)
        
        for ikey,ivalue in new_req.headers.items():
            if isinstance(ivalue, unicode):
                ivalue = ivalue.encode('utf-8')
            new_req.headers[ikey] = ivalue
            
        new_req.headers = new_headers
           
        if new_params:
            new_req.GET.update(new_params)
            
        new_req.GET['op'] = new_method
        
        resp = new_req.get_response(self.app)
            
        return new_req.path,resp
    
    def handle_normal(self,req,rdatas):
        
        new_path,resp = self.handle_new_req(req, '/normal' , 'PUT')
        
        if resp.status_int // 100 == 2:
            rdatas['success_count'] = rdatas['success_count'] + 1
        else:
            rdatas['not_found_count'] = 1 + rdatas['not_found_count']
            rdatas['failed_files'].append([quote(new_path), resp.status])
            print 'path:   '+req.path +  '      status:  '+str(resp.status_int) + '  msg: '+resp.body + '  handle' + '  new_path:  '+new_path

    
    def handle_quota(self,req,rdatas):
        
        new_headers = {'X-Account-Meta-Quota-Bytes': 1024*1024*1024}
        new_path,resp=  self.handle_new_req(req, '', 'POST', new_headers)
    
        if resp.status_int // 100 == 2:
            rdatas['success_count'] = rdatas['success_count'] + 1
        else:
            rdatas['not_found_count'] = 1 + rdatas['not_found_count']
            rdatas['failed_files'].append([quote(new_path), resp.status])
            print 'path:   '+req.path +  '      status:  '+str(resp.status_int) + '  msg: '+resp.body + '  handle'+ '  new_path:  '+new_path

 
    def handle_normal_versions(self,req,rdatas):
        
        new_path,resp=  self.handle_new_req(req, '/normal_versions', 'PUT')
        if resp.status_int // 100 == 2:
            rdatas['success_count'] = rdatas['success_count'] + 1
        else:
            rdatas['not_found_count'] = 1 + rdatas['not_found_count']
            rdatas['failed_files'].append([quote(new_path), resp.status])
            print 'path:   '+req.path +  '      status:  '+str(resp.status_int) + '  msg: '+resp.body + '  handle'+ '  new_path:  '+new_path

                    
    def handle_normal_metadata(self,req,rdatas):
        
        new_headers = {'X-Versions-Location': 'normal_versions'}
        new_path,resp=  self.handle_new_req(req, '/normal', 'POST',new_headers)
        if resp.status_int // 100 == 2:
            rdatas['success_count'] = rdatas['success_count'] + 1
        else:
            rdatas['not_found_count'] = 1 + rdatas['not_found_count']
            rdatas['failed_files'].append([quote(new_path), resp.status])
            print 'path:   '+req.path +  '      status:  '+str(resp.status_int) + '  msg: '+resp.body + '  handle'+ '  new_path:  '+new_path

            
    def handle_segments(self,req,rdatas):
        
        new_path,resp=  self.handle_new_req(req, '/segments', 'PUT' )
        if resp.status_int // 100 == 2:
            rdatas['success_count'] = rdatas['success_count'] + 1
        else:
            rdatas['not_found_count'] = 1 + rdatas['not_found_count']
            rdatas['failed_files'].append([quote(new_path), resp.status])
            print 'path:   '+req.path +  '      status:  '+str(resp.status_int) + '  msg: '+resp.body + '  handle'+ '  new_path:  '+new_path

                
    def handle_recycle(self,req,rdatas):
        
        new_path,resp=  self.handle_new_req(req, '/recycle', 'PUT')
        if resp.status_int // 100 == 2:
            rdatas['success_count'] = rdatas['success_count'] + 1
        else:
            rdatas['not_found_count'] = 1 + rdatas['not_found_count']
            rdatas['failed_files'].append([quote(new_path), resp.status])
            print 'path:   '+req.path +  '      status:  '+str(resp.status_int) + '  msg: '+resp.body + '  handle'+ '  new_path:  '+new_path

            
    def handle_recycle_meta(self,req,rdatas):
        
        qstr = 'op=MKDIRS&ftype=d&type=NORMAL'
        new_path,resp=  self.handle_new_req(req, '/recycle/meta', 'MKDIRS',qstr=qstr)
        if resp.status_int // 100 == 2:
            rdatas['success_count'] = rdatas['success_count'] + 1
        else:
            rdatas['not_found_count'] = 1 + rdatas['not_found_count']
            rdatas['failed_files'].append([quote(new_path), resp.status])
            print 'path:   '+req.path +  '      status:  '+str(resp.status_int) + '  msg: '+resp.body + '  handle'+ '  new_path:  '+new_path

            
    def handle_recycle_user(self,req,rdatas):
        
        qstr = 'op=MKDIRS&ftype=d&type=NORMAL'
        new_path,resp=  self.handle_new_req(req, '/recycle/user', 'MKDIRS',qstr=qstr)
        if resp.status_int // 100 == 2:
            rdatas['success_count'] = rdatas['success_count'] + 1
        else:
            rdatas['not_found_count'] = 1 + rdatas['not_found_count']
            rdatas['failed_files'].append([quote(new_path), resp.status])
            print 'path:   '+req.path +  '      status:  '+str(resp.status_int) + '  msg: '+resp.body + '  handle'+ '  new_path:  '+new_path

            
    def handle_private(self,req,rdatas):
        
        new_path,resp=  self.handle_new_req(req, '/private', 'PUT')
        if resp.status_int // 100 == 2:
            rdatas['success_count'] = rdatas['success_count'] + 1
        else:
            rdatas['not_found_count'] = 1 + rdatas['not_found_count']
            rdatas['failed_files'].append([quote(new_path), resp.status])
            print 'path:   '+req.path +  '      status:  '+str(resp.status_int) + '  msg: '+resp.body + '  handle'+ '  new_path:  '+new_path

            
    def handle_private_versions(self,req,rdatas):
        
        new_path,resp=  self.handle_new_req(req, '/private_versions', 'PUT')
        
        if resp.status_int // 100 == 2:
            rdatas['success_count'] = rdatas['success_count'] + 1
        else:
            rdatas['not_found_count'] = 1 + rdatas['not_found_count']
            rdatas['failed_files'].append([quote(new_path), resp.status])
            print 'path:   '+req.path +  '      status:  '+str(resp.status_int) + '  msg: '+resp.body + '  handle'+ '  new_path:  '+new_path

            
    def handle_private_metadata(self,req,rdatas):
        
        new_headers = {'X-Versions-Location': 'private_versions'}
        
        new_path,resp=  self.handle_new_req(req, '/private', 'POST',new_headers)
        
        if resp.status_int // 100 == 2:
            rdatas['success_count'] = rdatas['success_count'] + 1
        else:
            rdatas['not_found_count'] = 1 + rdatas['not_found_count']
            rdatas['failed_files'].append([quote(new_path), resp.status])
            print 'path:   '+req.path +  '      status:  '+str(resp.status_int) + '  msg: '+resp.body + '  handle'+ '  new_path:  '+new_path

    
    def handle_backup(self,req,rdatas):
        
        new_path,resp=  self.handle_new_req(req, '/backup', 'PUT')
        if resp.status_int // 100 == 2:
            rdatas['success_count'] = rdatas['success_count'] + 1
        else:
            rdatas['not_found_count'] = 1 + rdatas['not_found_count']
            rdatas['failed_files'].append([quote(new_path), resp.status])
            print 'path:   '+req.path +  '      status:  '+str(resp.status_int) + '  msg: '+resp.body + '  handle' + '  new_path:  '+new_path
            
    def handle_backup_versions(self,req,rdatas):
        
        new_path,resp=  self.handle_new_req(req, '/backup_versions', 'PUT')
        if resp.status_int // 100 == 2:
            rdatas['success_count'] = rdatas['success_count'] + 1
        else:
            rdatas['not_found_count'] = 1 + rdatas['not_found_count']
            rdatas['failed_files'].append([quote(new_path), resp.status])
            print 'path:   '+req.path +  '      status:  '+str(resp.status_int) + '  msg: '+resp.body + '  handle'+ '  new_path:  '+new_path

            
    def handle_backup_metadata(self,req,rdatas):
        
        new_headers = {'X-Versions-Location': 'backup_versions'}
        new_path,resp=  self.handle_new_req(req, '/backup', 'POST',new_headers)
        
        if resp.status_int // 100 == 2:
            rdatas['success_count'] = rdatas['success_count'] + 1
        else:
            rdatas['not_found_count'] = 1 + rdatas['not_found_count']
            rdatas['failed_files'].append([quote(new_path), resp.status])
            print 'path:   '+req.path +  '      status:  '+str(resp.status_int) + '  msg: '+resp.body + '  handle'+ '  new_path:  '+new_path

            
    def account_exists(self,req):
        
        resp =  self.handle_new_req(req,'/normal','HEAD')[1]
        
        if resp.status_int == HTTP_NOT_FOUND:
            return False
        return True
    
    def handle_register(self, req):

        rdatas = {'failed_files':[],'success_count':0,'not_found_count':0}
        
        req.accept = 'application/json'
        out_content_type = 'application/json'
        
        self.handle_normal(req,rdatas)
    
        self.handle_quota(req,rdatas)
        
        self.handle_normal_versions(req,rdatas)
        
        self.handle_normal_metadata(req,rdatas)
    
        self.handle_segments(req,rdatas)
        
        self.handle_recycle(req,rdatas)
        
        self.handle_recycle_meta(req,rdatas)
        
        self.handle_recycle_user(req,rdatas)
        
        self.handle_private(req,rdatas)
        
        self.handle_private_versions(req,rdatas)
        
        self.handle_private_metadata(req,rdatas)
        
        self.handle_backup(req,rdatas)
        
        self.handle_backup_versions(req,rdatas)
        
        self.handle_backup_metadata(req,rdatas)
        
        resp_body = get_response_body(
            out_content_type,
            {'Number successed': rdatas['success_count'],
             'Number failed': rdatas['not_found_count']},
            rdatas['failed_files'])
        
        if (rdatas['success_count'] or rdatas['not_found_count']) and not rdatas['failed_files']:
            
            return jresponse('0','',req,200,param=resp_body)
        
        if rdatas['failed_files']:
            return jresponse('-1',json.dumps(resp_body), req,400)
            
        return jresponse('-1', 'Invalid userinit register', req, 400) 
    
    @wsgify
    def __call__(self, req):

        _,account,container,_ = split_path(req.path, 1, 4, True)

        dbpath = '%s/%s.db' % (self.devices,account)
        if 'register' == container:
            print dbpath+'register'
            if not self.account_exists(req):
                print dbpath+'start'
                dbpath = '%s/%s.db' % (self.devices,account)
                db_init(dbpath)
                task_db_init(dbpath)
                print dbpath+'end'
                return self.handle_register(req)
            else:
                return jresponse('-1','account user alread exists',req,400)
        else:
            if not self.account_exists(req):
                return jresponse('-1','account user not found',req,404)
        return self.app


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def userinit_filter(app):
        return Userinit(app, conf)
    return userinit_filter
