# -*- coding: utf-8 -*-

from swift.common.utils import split_path,qsparam,newparamqs,json
from swift.common.env_utils import *
from webob import Request,Response
from cStringIO import StringIO
import urllib
def is_dir_create(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'PUT' == method and 'MKDIRS' == param.get('op'): 
        return True
    
    return False

def dir_creaet_env(env):

    env_comment(env, 'create dir')
    
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    param['ftype'] = 'd'
    env['QUERY_STRING'] = newparamqs(param)
    
    return True

def is_file_create(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'PUT' == method and 'CREATE' == param.get('op'): 
        return True
    
    return False

def file_creaet_env(env):

    env_comment(env, 'create file')
            
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    param['ftype'] = 'f'
    param.pop('op')
    env['QUERY_STRING'] = newparamqs(param)
    
    return True

def is_file_open(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'GET' == method and 'OPEN' == param.get('op'): 
        return True
    
    return False

def file_open_env(env):
    
    env_comment(env, 'get file content')
        
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    param.pop('op')
    param['ftype'] = 'f'
    env['QUERY_STRING'] = newparamqs(param)
    
    start = param.get('offset')
    length = param.get('length')
    if start or length:
        if not start:
            start = '0'
        if not length:
            length = ''
        
        end = length
        if length:
            end = str(int(start)+int(length)-1)
        env['HTTP_RANGE'] = 'bytes=%s-%s' % (start,end)
    
    return True

def is_link_create(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'PUT' == method and 'CREATESYMLINK' == param.get('op'): 
        return True
    
    return False

def link_creaet_env(env):
    
    env_comment(env, 'create link')
        
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    param['ftype'] = 'l'
    if param.has_key('destination'):
        dst = param.get('destination')
        env['HTTP_DESTINATION'] = dst
        param.pop('destination')
    env['QUERY_STRING'] = newparamqs(param)
    
def is_file_rename(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'PUT' == method and 'RENAME' == param.get('op') and 'f'==param.get('ftype'): 
        return True
    
    return False

def file_rename_env(env):
    
    env_comment(env, 'rename file')
        
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    if param.has_key('destination'):
        dst = param.get('destination')
        env['HTTP_DESTINATION'] = dst
        param.pop('destination')
    param['op'] = 'MOVE'
    env['QUERY_STRING'] = newparamqs(param)
    
    return True

def is_file_move(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'PUT' == method and 'MOVE' == param.get('op') and 'f'==param.get('ftype'): 
        return True
    
    return False

def file_move_env(env):
    
    env_comment(env, 'move file')
    
    env['REQUEST_METHOD'] = 'POST'
    
    qs = env.get('QUERY_STRING','') 
    path = env['PATH_INFO']
    vers,account, src_container,src_obj = split_path(path,1, 4,True)
    
    srcf = '/%s/%s' % (src_container,src_obj)
    
    destination = env['HTTP_DESTINATION']
    dst_path = '/'.join(['',vers,account,destination])
    _,_,dst_container,dst_obj = split_path(dst_path,1, 4,True)
    
    dstf = '/%s/%s' % (dst_container,dst_obj)
    
    srcd = '/%s_versions/%s' % (src_container,src_obj)
    dstd = '/%s_versions/%s' % (dst_container,dst_obj)
    
    env['PATH_INFO'] = env['RAW_PATH_INFO'] = '/'.join(['',vers,account,'batch'])
    
    param = qsparam(qs)     
    param['op'] = 'MOVE'
    param['type'] = 'NORMAL'
    env['QUERY_STRING'] = newparamqs(param)
    
    move_data = {"list":[{"from":srcf,"to":dstf,"ftype":"f"},{"from":srcd,"to":dstd,"ftype":"d"}]}
    json_data = json.dumps(move_data)
    env['CONTENT_LENGTH'] = str(len(json_data))
    env['wsgi.input'] = StringIO(json_data)

    return True

def is_dir_rename(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'PUT' == method and 'RENAME' == param.get('op') and 'd'==param.get('ftype'): 
        return True
    
    return False

def dir_rename_env(env):
    
    env_comment(env, 'rename dir')
        
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    if param.has_key('destination'):
        dst = param.get('destination')
        env['HTTP_DESTINATION'] = dst
        param.pop('destination')
    env['QUERY_STRING'] = newparamqs(param)
    
    return True

def is_file_attr(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'GET' == method and 'GETFILEATTR' == param.get('op'): 
        return True
    
    return False

def file_attr_env(env):
    
    env_comment(env, 'get file attr')
        
    env['REQUEST_METHOD'] = 'META'
    env.pop('QUERY_STRING')
    
    return True

def is_file_permission(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'PUT' == method and 'SETPERMISSION' == param.get('op'): 
        return True
    
    return False

def file_permission_env(env):

    env_comment(env, 'set file versions')
        
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    if param.has_key('permission'):
        dst = param.get('permission')
        env['HTTP_X_OBJECT_PERMISSON'] = dst
        param.pop('permission')
        
    param.pop('op')
    param['ftype'] = 'f'
    env['QUERY_STRING'] = newparamqs(param)
    env['REQUEST_METHOD'] = 'POST'
    return True

def is_file_versions(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'GET' == method and 'GETHISTORY' == param.get('op'): 
        return True
    
    return False

def file_versions_env(env):

    env_comment(env, 'get file versions')
        
    path = env.get('PATH_INFO')
    vers,account, container,obj = split_path(urllib.unquote(path),1, 4,True)
    env['PATH_INFO'] = env['RAW_PATH_INFO'] = '/'.join(['',vers,account,container+'_versions'])
    
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)    
    param.pop('op')
    param['prefix'] = urllib.quote(obj+'/')
    env['QUERY_STRING'] = newparamqs(param)
    
    return True

def set_comment(env):
    
    new_env = env.copy() 
    req = Request(new_env)
    vers,account,container,obj = split_path(req.path,1, 4,True)
    
    if req.GET.get('op'):
        method = req.GET.get('op')
    else:
        method = req.method
        
    if account and container and obj:
        ftype = req.GET.get('ftype')
        if req.method == 'PUT' and req.GET.get('multipart-manifest') == 'put':
            env_comment(env, 'merge files')
            return True
        
        if req.method == 'DELETE' and req.GET.get('multipart-manifest') == 'delete':
            env_comment(env, 'delete merged file')
            return True
        
        if 'l' == ftype and req.GET.get('') == 'CREATESYMLINK':
            env_comment(req.environ, 'create link')
            return True
        
        if 'd' == ftype:
            if 'GET' == method:
                env_comment(env, 'get dir content')
                return True
            if 'HEAD' == method:
                env_comment(env, 'get dir info')
                return True
            if 'PUT' == method:
                env_comment(env, 'create dir')
                return True
            if 'DELETE' == method:
                env_comment(env, 'delete dir')
                return True
            if 'RESET' == method:
                env_comment(env, 'reset dir')
                return True
            if 'MKDIRS' == method:
                env_comment(env, 'create dir')
                return True
            if 'LIST' == method:
                env_comment(env, 'get dir content')
                return True
            if 'LISTDIR' == method:
                env_comment(env, 'get dir content')
                return True
            if 'COPY' == method:
                env_comment(env, 'copy dir')
                return True
            if 'MOVE' == method:
                env_comment(env, 'move dir')
                return True
            if 'RENAME' == method:
                env_comment(env, 'rename dir')
                return True
            
        if 'HEAD' == method:
            env_comment(env, 'get file info')
            return True
        if 'GET' == method:
            env_comment(env, 'get file content')
            return True
        
        if 'META' == method:
            env_comment(env, 'get file info')
            return True
        if 'PUT' == method:
            env_comment(env, 'create file')
            return True
        if 'DELETE' == method:
            env_comment(env, 'delete file')
            return True
        if 'COPY' == method:
            env_comment(env, 'copy file')
            return True
        if 'MOVE' == method:
            env_comment(env, 'move file')
            return True
        if 'POST' == method:
            env_comment(env, 'update file attr')
            return True
        
    if account and container:
        if 'batch' == container:
            if 'DELETE' == req.GET.get('op'):
                env_comment(env, 'batch delete')
                return True
            
            if 'RESET' == req.GET.get('op'):
                env_comment(env, 'batch reset')
                return True
            
            if 'MOVE' == req.GET.get('op'):
                env_comment(env, 'batch move')
                return True
            
            if 'COPY' == req.GET.get('op'):
                env_comment(env, 'batch copy')
                return True
            
            if 'MOVERECYCLE' == req.GET.get('op'):
                env_comment(env, 'batch move from recycle')
                return True
        if 'GET' == method:
            env_comment(env, 'get container content')
            return True
        if 'LISTDIR' == method:
            env_comment(env, 'get container content')
            return True
        if 'HEAD' == method:
            env_comment(env, 'get container info')
            return True
        if 'META' == method:
            env_comment(env, 'get container info')
            return True
        if 'PUT' == method:
            env_comment(env, 'create container')
            return True
        if 'POST' == method:
            env_comment(env, 'update container')
            return True
        if 'DELETE' == method:
            env_comment(env, 'delete container')
            return True
        
    if account:
        if 'META' == method:
            env_comment(env, 'get account attr')
            return True
        
        if 'POST' == method:
            env_comment(env, 'update account attr')
            return True
        
    return True