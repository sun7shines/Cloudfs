# -*- coding: utf-8 -*-
# Copyright (c) 2011 OpenStack, LLC.
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

from time import gmtime, strftime, time
from traceback import format_exc
from urllib import quote, unquote
from uuid import uuid4
from hashlib import sha1
import hmac
import base64

from eventlet import Timeout
from webob import Response, Request
from webob.exc import HTTPBadRequest, HTTPForbidden, HTTPNotFound, \
    HTTPUnauthorized

from swift.common.utils import cache_from_env, get_logger, get_remote_client, \
    split_path, TRUE_VALUES,json
    
from swift.common.http import HTTP_CLIENT_CLOSED_REQUEST
from swift.common.oauth.bridge import *
import hashlib
from swift.common.bufferedhttp import jresponse

def strmd5sum(src):
    
    myMd5 = hashlib.md5()
    myMd5.update(src)
    myMd5_Digest = myMd5.hexdigest()
    return myMd5_Digest

class OAuth(object):

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='tempauth')
        
        self.log_headers = conf.get('log_headers', 'f').lower() in TRUE_VALUES
        self.reseller_prefix = conf.get('reseller_prefix', 'AUTH').strip()
        
        self.auth_prefix = conf.get('auth_prefix', '/oauth/access_token')
        self.verify_prefix = '/oauth/verify_token'
        self.token_life = int(conf.get('token_life', 86400))
        
        self.resourcename = conf.get('resourcename', 'SeAgent').strip()
        self.secret = conf.get('secret', '123456').strip()
        self.oauth_host = conf.get('oauth_host', 'https://124.16.141.142').strip()
        self.oauth_url = self.oauth_host+'/api/token-validation'
        self.oauth_port = int(conf.get('oauth_port', '443').strip())
        
        self.client_id = conf.get('client_id', 'hnuclient1').strip()
        self.client_secret = conf.get('client_secret', '34ulL811ANtS70Te').strip()
        self.token_url = '%s/oauth/access_token' % (self.oauth_host)
        self.grant_type = conf.get('grant_type', 'password').strip()
        self.scope = conf.get('scope', 'user').strip()
        
    def __call__(self, env, start_response):

        if env.get('PATH_INFO', '').startswith(self.auth_prefix):
            return self.handle(env, start_response)
        
        if env.get('PATH_INFO', '').startswith(self.verify_prefix):
            return self.verify(env, start_response)
        
        req = Request(env)
        
        try:
            version, account, container, obj = split_path(req.path_info,
                minsegs=1, maxsegs=4, rest_with_last=True)
        except ValueError:
            self.logger.increment('errors')
            return jresponse('-1','not found',req,404)
        
        token = env.get('HTTP_X_AUTH_TOKEN', env.get('HTTP_X_STORAGE_TOKEN'))
        #################################################
        # return self.app(env, start_response)
        ################################################
        if token :
            
            user_info = self.get_cache_user_info(env, token)
            if user_info:
                
                tenant = 'AUTH_' + user_info.replace('@','').replace('.','')
                if account != tenant:
                    self.logger.increment('unauthorized')
                    return HTTPUnauthorized()(env, start_response)
                
                env['REMOTE_USER'] = user_info
                user = user_info 
                env['HTTP_X_AUTH_TOKEN'] = '%s,%s' % (user, token)
                return self.app(env, start_response)
            else:
               
                self.logger.increment('unauthorized')
                return HTTPUnauthorized()(env, start_response)
                
        else:
            self.logger.increment('unauthorized')
            return HTTPUnauthorized()(env, start_response)
       

    def validateToken(self,token):
        '''Validate token & Get User Information'''
        client = bridgeUtil()
        verify_param = {}
        verify_param['resourcename'] = self.resourcename
        verify_param['secret'] = self.secret
        verify_param['access_token'] = token
        url = self.oauth_url
        port = int(self.oauth_port)
        
        result = client.verify_user(url, port,verify_param)
        return result

    def get_user_info(self, env, token):
        
        user_info = None
        if not user_info:
            user_info = self.validateToken(token)

        return user_info
       
    def get_cache_user_info(self, env, token):
        
        user_info = None
        memcache_client = cache_from_env(env)
        if not memcache_client:
            raise Exception('Memcache required')
        memcache_token_key = '%s/token/%s' % (self.reseller_prefix, token)
        
        cached_auth_data = memcache_client.get(memcache_token_key)
        if cached_auth_data:
            expires,expires_in, user_info = cached_auth_data
            if expires < time():
                user_info = None
                
        return user_info

    def handle(self, env, start_response):
        
        try:
            req = Request(env)
            
            return self.handle_request(req)(env, start_response)
            
        except (Exception, Timeout):
            print "EXCEPTION IN handle: %s: %s" % (format_exc(), env)
            self.logger.increment('errors')
            start_response('500 Server Error',
                           [('Content-Type', 'text/plain')])
            return ['Internal server error.\n']
        
    def verify(self, env, start_response):
        
        req = Request(env)
        
        try:
            
            return self.verify_request(req,env)(env, start_response)
            
        except (Exception, Timeout):
            print "EXCEPTION IN handle: %s: %s" % (format_exc(), env)
            self.logger.increment('errors')
            start_response('500 Server Error',
                           [('Content-Type', 'text/plain')])
            return ['Internal server error.\n']
        
        
    def verify_request(self,req,env):
        
        try:
            version, account, container, obj = split_path(req.path_info,
                minsegs=1, maxsegs=4, rest_with_last=True)
        except ValueError:
            self.logger.increment('errors')
            return jresponse('-1','not found',req,404)
        
        token = env.get('HTTP_X_AUTH_TOKEN', env.get('HTTP_X_STORAGE_TOKEN'))
        verify_flag = False
        if token :
        
            user_info = self.get_cache_user_info(env, token)
            if user_info:
                
                tenant = 'AUTH_' + user_info.replace('@','').replace('.','')
                if account != tenant:
                    self.logger.increment('unauthorized')
                    verify_flag = False

                verify_flag = True
            else:
               
                self.logger.increment('unauthorized')
                verify_flag = False
            
        else:
            self.logger.increment('unauthorized')
            verify_flag = False
        
        oauth_data_list = json.dumps({'verify_flag':str(verify_flag).lower()})
        return Response(body=oauth_data_list,request=req)
        
    def handle_request(self, req):
        
        req.start_time = time()
        
        handler = self.handle_get_token
        
        if not handler:
            self.logger.increment('errors')
            req.response = HTTPBadRequest(request=req)
        else:
            req.response = handler(req)
        return req.response
    
    def get_user_accessToken(self,user_email,user_passwd):
        
        client = bridgeUtil()
        user_param = {}
    
        url = self.token_url
    
        user_param['client_id'] = self.client_id
        user_param['client_secret'] = self.client_secret
        user_param['grant_type'] = self.grant_type
        user_param['scope'] = self.scope
        user_param['email'] = user_email
        user_param['password'] = user_passwd
        
        result = client.get_user_access_token(url,  self.oauth_port,user_param)
        
        return result

    def handle_get_token(self, req):
        
        param = json.loads(req.body)
        user_email = param['email']
        user_passwd = param['password']
    
        if not user_email or not user_passwd:
            return ['email or password error.\n']
        
        account_user = user_email.replace('@','').replace('.','')
        
        datastr = user_passwd+account_user
        md5_account_user = strmd5sum(datastr)
       
	#########################################################
        # token =  u'gPDcsIChk0n5F209fXl6gLGzwa0cdIznMKi88CuM'+account_user
        # expires = '1431328576'
        # oauth_data_list = json.dumps({'access_token':token,'expires':expires,'tanent':account_user})
        # return Response(body=oauth_data_list,request=req)

	########################################################
 
        memcache_client = cache_from_env(req.environ)
        if not memcache_client:
            raise Exception('Memcache required')
        
        token = None
        # get token by memcache by account_user
        memcache_user_key = '%s/user/%s' % (self.reseller_prefix, md5_account_user)
        candidate_token = memcache_client.get(memcache_user_key)
        if candidate_token:
            memcache_token_key = '%s/token/%s' % (self.reseller_prefix, candidate_token)
            cached_auth_data = memcache_client.get(memcache_token_key)
            if cached_auth_data:
                expires,expires_in,user_email = cached_auth_data
                if expires > time():
                    token = candidate_token
        
        if not token:
            
            oauth_data = self.get_user_accessToken(user_email,user_passwd)
            
            if not oauth_data or not oauth_data.get('access_token'):
                return HTTPUnauthorized(request=req)
            
            token = oauth_data["access_token"]
            
            expires_in = int(oauth_data['expires_in'])
            expires = expires_in + time()
            
            cached_auth_data = (expires,expires_in,user_email)
            # get account_user/tenant by token
            memcache_token_key = '%s/token/%s' % (self.reseller_prefix, token)
            memcache_client.set(memcache_token_key, cached_auth_data, timeout=expires_in)
            
            # get token by oauth server by account_user
            memcache_user_key = '%s/user/%s' % (self.reseller_prefix, md5_account_user)
            memcache_client.set(memcache_user_key, token,timeout=expires_in)
            
        oauth_data_list = json.dumps({'access_token':token,'expires':expires,'tanent':account_user})
        return Response(body=oauth_data_list,request=req)
        
def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return OAuth(app, conf)
    return auth_filter
