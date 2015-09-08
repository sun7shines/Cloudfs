# -*- coding: utf-8 -*-
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

from eventlet import Timeout
from webob import Request,Response
from webob.exc import HTTPServerError,HTTPNoContent
import uuid
import time
from swift.common.bufferedhttp import jresponse
from swift.common.utils import get_logger,split_path,json

from swift.common.middleware.userdb import db_insert,db_update,db_delete,db_values,task_db_delete,task_db_values

class UserOpMiddleware(object):

    def __init__(self, app, conf):
        self.app = app
        self.dbdir = conf.get('devices', '/mnt/cloudfs-object').strip()
        self.logger = get_logger(conf, log_route='catch-errors')

    def __call__(self, env, start_response):
        
        if 'swift.trans_id' not in env:
            tx_id = 'tx'+uuid.uuid4().hex
            env['swift.trans_id'] = tx_id

        new_env = env.copy() 
        req = Request(new_env)
        vers,account,container,obj = split_path(req.path,1, 4,True)
                       
        dbpath = '%s/%s.db' % (self.dbdir,account)
        
        if 'GET_OP_HISTORY' == req.GET.get('op'):
            if req.GET.get('recent'):
                desc_flag = True
                limit = int(req.GET.get('recent')) 
                data = db_values(dbpath,desc_flag,limit)
            else:
                data = db_values(dbpath)
                
            op_list = json.dumps(data)
            return Response(body=op_list, request=req)(env,start_response)
        
        elif 'DELETE_HISTORY' == req.GET.get('op'):
            
            if req.GET.get('recent'):
                desc_flag = True
                limit = int(req.GET.get('recent'))
                db_delete(dbpath,desc_flag,limit) 
            else:
                db_delete(dbpath)
            return jresponse('0','',req,204)(env,start_response)
        
        elif 'GET_OP_TASK' == req.GET.get('op'):
            if req.GET.get('tx_id'):
                
                tx_id = req.GET.get('tx_id') 
                data = task_db_values(dbpath,tx_id)
                
                op_list = json.dumps(data)
                return Response(body=op_list, request=req)(env,start_response)
            else:
                return jresponse('-1','error params',req,400)(env,start_response)
            
        if 'register' != container:
            path = ''
            type = ''
            if account and container and obj:
                path = obj
                type = 'object'
            elif account and container:
                path = container
                type = 'container'
            elif account:
                path = account
                type = 'account'
            
            method = req.method
            tenant = account
            swifttime = str(time.time())
            tx_id =  req.environ.get('swift.trans_id')
            url = req.url
            qs = req.environ.get('QUERY_STRING','')
            env['fwuser_info'] = {} 
            env['fwuser_info']['status'] = ''
            env['fwuser_info']['comment'] = ''
            db_insert(dbpath, tx_id, path, type,method, tenant, qs, swifttime, status='', comment='')

        resp = self.app(env, start_response)

        if 'register' != container:
            if env.get('fwuser_info'):
                estatus = env.get('fwuser_info').get('status','')
                comment = env['fwuser_info'].get('comment','')
                db_update(dbpath, estatus, comment, tx_id)
          
        return resp

def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def userop_filter(app):
        return UserOpMiddleware(app, conf)
    return userop_filter
