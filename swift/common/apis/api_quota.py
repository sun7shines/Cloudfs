# -*- coding: utf-8 -*-

from swift.common.utils import split_path,qsparam,newparamqs,json
from cStringIO import StringIO

from swift.common.env_utils import *

def is_get_quota(env):
    method = env.get('REQUEST_METHOD')
    path = env.get('PATH_INFO')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    _, _, container,_ = split_path(path,1, 4,True)
    
    if 'GET' == method and 'info' == param.get('op') and 'quota'==container: 
        return True
    return False

def get_quota_env(env):
    
    env_comment(env, 'quota info')
            
    path = env['PATH_INFO']
    env['REQUEST_METHOD'] = 'META'
    env['PATH_INFO'] = env['RAW_PATH_INFO'] = '/'.join(path.split('/')[:-1])
    env.pop('QUERY_STRING')
    return True

def is_set_quota(env):
    method = env.get('REQUEST_METHOD')
    path = env.get('PATH_INFO')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    _, _, container,_ = split_path(path,1, 4,True)
    
    if 'POST' == method and 'createstorage' == param.get('op') and 'quota'==container: 
        return True
    return False

def set_quota_env(env):
    
    env_comment(env, 'quota set')
        
    path = env['PATH_INFO']
    env['REQUEST_METHOD'] = 'POST'
    env['PATH_INFO'] = env['RAW_PATH_INFO'] = '/'.join(path.split('/')[:-1])
    env.pop('QUERY_STRING')
    return True

def is_list_recycle(env):
            
    method = env.get('REQUEST_METHOD')
    path = env.get('PATH_INFO')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    _, _, container,_ = split_path(path,1, 4,True)
    
    if 'GETRECYCLER' == param.get('op') and 'recycle'==container: 
        return True
    return False

def list_recycle_env(env):
    
    env_comment(env, 'list recycle')
        
    qs = env.get('QUERY_STRING','') 
    path = env['PATH_INFO']
    vers,account, container,_ = split_path(path,1, 4,True)
    
    env['PATH_INFO'] = env['RAW_PATH_INFO'] = '/'.join(['',vers,account,container,'meta'])
    
    param = qsparam(qs)     
    param['op'] = 'LIST'
    param['ftype'] = 'd'
    
    if param.get('start') or param.get('limit'):
        start = param.get('start')
        limit = param.get('limit')
        if not start:
            start = '0'
        if not limit:
            limit = ''
        param['start'] = start
        param['limit'] = limit
        
    env['QUERY_STRING'] = newparamqs(param)
    
    return True

def is_clear_recycle(env):
    method = env.get('REQUEST_METHOD')
    path = env.get('PATH_INFO')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    _, _, container,_ = split_path(path,1, 4,True)
    
    if 'RECYCLER' == param.get('op') and 'clearrecycle'==container: 
        return True
    return False

def clear_recycle_env(env):
    
    env_comment(env, 'clear recycle')
            
    qs = env.get('QUERY_STRING','') 
    path = env['PATH_INFO']
    vers,account, _,_ = split_path(path,1, 4,True)
    
    env['PATH_INFO'] = env['RAW_PATH_INFO'] = '/'.join(['',vers,account,'batch'])
    
    param = qsparam(qs)     
    param['op'] = 'RESET'
    param['ftype'] = 'd'
    env['QUERY_STRING'] = newparamqs(param)
    
    rcy_data = {"list":[{"path":"/recycle/meta","ftype":"d"},{"path":"/recycle/user","ftype":"d"}]}
    json_data = json.dumps(rcy_data)
    env['CONTENT_LENGTH'] = str(len(json_data))
    env['wsgi.input'] = StringIO(json_data)

    return True
