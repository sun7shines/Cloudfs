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

""" Object Server for Swift """

from __future__ import with_statement
import cPickle as pickle
import errno
import os
import time
import traceback
from datetime import datetime
from hashlib import md5
from tempfile import mkstemp
from urllib import unquote
from contextlib import contextmanager
import syslog
import threading
import multiprocessing

from webob import Request, Response, UTC
from webob.exc import HTTPAccepted, HTTPBadRequest, HTTPCreated, \
    HTTPInternalServerError, HTTPNoContent, HTTPNotFound, HTTPConflict,\
    HTTPNotModified, HTTPPreconditionFailed, \
    HTTPRequestTimeout, HTTPUnprocessableEntity, HTTPMethodNotAllowed
from xattr import getxattr, setxattr
from eventlet import sleep, Timeout, tpool

from swift.common.utils import mkdirs, normalize_timestamp, public, \
    storage_directory, hash_path, renamer, fallocate, \
    split_path, drop_buffer_cache, get_logger, write_pickle, \
    TRUE_VALUES, validate_device_partition
from swift.common.bufferedhttp import http_connect,jresponse
from swift.common.constraints import check_object_creation, check_mount, \
    check_float, check_utf8

from swift.obj.replicator import tpool_reraise, invalidate_hash, \
    quarantine_renamer, get_hashes
    
from swift.common.exceptions import ConnectionTimeout, DiskFileError, \
    DiskFileNotExist

from swift.common.http import is_success, HTTPInsufficientStorage, \
    HTTPClientDisconnect

from swift.common.http import HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED, \
    HTTP_NOT_FOUND

from swift.common.utils import get_uuid,json
from swift.lib.utils import file_decrypt
from swift.common.common.swob import Response as HResponse
from swift.common.common.swob import Range
from swift.common.middleware.userdb import task_db_insert,task_db_update

DATADIR = 'objects'
ASYNCDIR = 'async_pending'
PICKLE_PROTOCOL = 2
METADATA_KEY = 'user.swift.metadata'
MAX_OBJECT_NAME_LENGTH = 1024
# keep these lower-case
DISALLOWED_HEADERS = set('content-length content-type deleted etag'.split())

class DiskFile(object):
    
    def __init__(self):
        
        return
    
class DiskMeta(object):
    
    def __init__(self):
        
        return
    
class SwiftFile(object):
    
    def __iter__(self):
        
        try:
            dropped_cache = 0
            read = 0
            self.started_at_0 = False
            self.read_to_eof = False
            start_time = time.time()
            if self.fp.tell() == 0:
                self.started_at_0 = True
                self.iter_etag = md5()

            while True:
                chunk = self.fp.read(self.disk_chunk_size)
                if chunk:
                    if self.iter_etag:
                        self.iter_etag.update(chunk)
                    read += len(chunk)
                    if read - dropped_cache > (1024 * 1024):
                        self.drop_cache(self.fp.fileno(), dropped_cache,
                            read - dropped_cache)
                        dropped_cache = read

                    dural_time=float(time.time()) - float(start_time)
                    if(dural_time>0):
                        speed = float(read)/float(dural_time)/(1000*1000)
                        while(speed >3):
                            sleep(0.1)
                            dural_time=float(time.time()) - float(start_time)
                            speed = float(read)/float(dural_time)/(1000*1000)

                    yield chunk
                    if self.iter_hook:
                        self.iter_hook()
                else:
                    self.read_to_eof = True
                    self.drop_cache(self.fp.fileno(), dropped_cache,
                        read - dropped_cache)
                    break
        finally:
            self.close()

    def app_iter_range(self, start, stop):
        """Returns an iterator over the data file for range (start, stop)"""
        if start or start == 0:
            self.fp.seek(start)
        if stop is not None:
            length = stop - start
        else:
            length = None
        try:
            for chunk in self:
                if length is not None:
                    length -= len(chunk)
                    if length < 0:
                        # Chop off the extra:
                        yield chunk[:length]
                        break
                yield chunk
        finally:
            self.close()
                
    def _handle_close_quarantine(self):
        
        try:
            obj_size = self.get_data_file_size()
        except DiskFileError, e:
            self.quarantine()
            return
        except DiskFileNotExist:
            return

        if (self.iter_etag and self.started_at_0 and self.read_to_eof and
            'ETag' in self.metadata and
            self.iter_etag.hexdigest() != self.metadata.get('ETag')):
                self.quarantine()


    def drop_cache(self, fd, offset, length):
        
        if not self.keep_cache:
            drop_buffer_cache(fd, offset, length)

    def quarantine(self):
        
        if not (self.is_deleted() or self.quarantined_dir):
            self.quarantined_dir = quarantine_renamer(self.device_path,
                                                      self.data_file)
            return self.quarantined_dir

class ObjectController(object):
    """Implements the WSGI application for the Swift Object Server."""

    def __init__(self, conf):
        """
        Creates a new WSGI application for the Swift Object Server. An
        example configuration is given at
        <source-dir>/etc/object-server.conf-sample or
        /etc/swift/object-server.conf-sample.
        """
        self.logger = get_logger(conf, log_route='object-server')
        self.devices = conf.get('devices', '/mnt/cloudfs-object')
        self.mount_check = conf.get('mount_check', 'true').lower() in \
            TRUE_VALUES
        self.node_timeout = int(conf.get('node_timeout', 3000))
        self.conn_timeout = float(conf.get('conn_timeout', 50))
        self.disk_chunk_size = int(conf.get('disk_chunk_size', 65536))
        self.network_chunk_size = int(conf.get('network_chunk_size', 65536))
        self.keep_cache_size = int(conf.get('keep_cache_size', 5242880))
        self.keep_cache_private = \
            conf.get('keep_cache_private', 'false').lower() in TRUE_VALUES
        self.log_requests = \
            conf.get('log_requests', 'true').lower() in TRUE_VALUES
        self.max_upload_time = int(conf.get('max_upload_time', 86400))
        self.slow = int(conf.get('slow', 0))
        self.bytes_per_sync = int(conf.get('mb_per_sync', 50)) * 1024 * 1024
        
        default_allowed_headers = '''
            x-static-large-object,
        '''
        
        self.allowed_headers = set(
            i.strip().lower() for i in
            conf.get('allowed_headers', default_allowed_headers).split(',')
            if i.strip() and i.strip().lower() not in DISALLOWED_HEADERS)
      
      
    def account_update(self, req, account,bytes_val,add_flag = True):
        
        account_host = req.headers.get('X-Account-Host')
        account_partition = req.headers.get('X-Account-Partition')
        account_device = req.headers.get('X-Account-Device')
        if all([account_host, account_partition, account_device]):
            account_ip, account_port = account_host.rsplit(':', 1)
            new_path = '/' + account
            if isinstance(new_path, unicode):
                new_path = new_path.encode('utf-8')
            
            if add_flag:
                bytes_key = 'x-account-meta-bytes-add'
            else:
                bytes_key = 'x-account-meta-bytes-del'
                
            account_headers = {bytes_key:str(bytes_val),
                'X-Timestamp': normalize_timestamp(time.time()),
                'x-trans-id': req.headers.get('x-trans-id', '-')}
            
            try:
                with ConnectionTimeout(self.conn_timeout):
                    conn = http_connect(account_ip, account_port,
                        account_device, account_partition, 'POST', new_path,
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
    def PUT(self, request):
        """Handle HTTP PUT requests for the Swift Object Server."""
        start_time = time.time()
        try:
            device, partition, account, container, obj = \
                split_path(unquote(request.path), 5, 5, True)
            validate_device_partition(device, partition)
        except ValueError, err:
            return jresponse('-1', 'bad request', request,400)
         
        if self.mount_check and not check_mount(self.devices, device):
            return jresponse('-1', 'insufficient storage', request,507)
        
        if 'x-timestamp' not in request.headers or \
                    not check_float(request.headers['x-timestamp']):
            self.logger.increment('PUT.errors')
            return jresponse('-1', 'Missing timestamp', request,400) 
        
        error_response = check_object_creation(request, obj)
        if error_response:
            return error_response
        
        file = DiskFile(self.devices, device, partition, account, container,
                        obj, self.logger, disk_chunk_size=self.disk_chunk_size)
        
        
        if not file.cnt_flag:
            return jresponse('-1', 'container not found', request,404) 
        
        overwrite = request.headers.get('x-overwrite')
        if overwrite != 'true' and not file.is_deleted():
            return jresponse('-1', 'file exists', request,409) 
        
        upload_expiration = time.time() + self.max_upload_time
        etag = md5()
        upload_size = 0
        last_sync = 0
        hdata = {}
        
        metastr = request.GET.get('metadata')
        metamode = request.GET.get('mode')
        storetype = request.GET.get('storetype')
        
        with file.mkstemp() as (fd, tmppath):
            if 'content-length' in request.headers:
                try:
                    fallocate(fd, int(request.headers['content-length']))
                except OSError:
                    return jresponse('-1', 'insufficient storage', request,507)
                    
            reader = request.environ['wsgi.input'].read
            for chunk in iter(lambda: reader(self.network_chunk_size), ''):
                chunk = file_decrypt(chunk,metamode,storetype)
                upload_size += len(chunk)
                if time.time() > upload_expiration:
                    return jresponse('-1','request timeout',request,408)
                etag.update(chunk)
                while chunk:
                    written = os.write(fd, chunk)
                    chunk = chunk[written:]
                # For large files sync every 512MB (by default) written
                if upload_size - last_sync >= self.bytes_per_sync:
                    tpool.execute(os.fdatasync, fd)
                    drop_buffer_cache(fd, last_sync, upload_size - last_sync)
                    last_sync = upload_size
                sleep()
            etag = etag.hexdigest()
            metadata = {
                'ETag': etag,
                'Content-Length': str(os.fstat(fd).st_size),
                'X-Timestamp': request.headers['x-timestamp'],
                'X-File-Type':'f',
                'X-Object-Permisson':'700'
            }
            
            if metastr:
                metadata.update({'metadata':metastr})
            if metamode:
                metadata.update({'mode':metamode})
            if storetype:
                metadata.update({'storetype':storetype})
                
            for header_key in self.allowed_headers:
                if header_key in request.headers:
                    header_caps = header_key.title()
                    metadata[header_caps] = request.headers[header_key]
            
            file.put(fd, tmppath,metadata)
            
            self.account_update(request, account, metadata['Content-Length'], add_flag=True)
            
            hdata = {'md5':etag,'size':metadata['Content-Length']}
            hdata['ctime'] = hdata['mtime'] = metadata['X-Timestamp']
            hdata['path'] = '/'.join(['',container,obj])
            hdata['X-Object-Permisson'] = metadata['X-Object-Permisson']
            
            hdata = json.dumps(hdata)
        
        resp = HTTPCreated(body=hdata,request=request)
        
        return resp

    @public
    def GET(self, request):
        # request is global , can not be modify
        # response can be modify
        start_time = time.time()
        try:
            device, partition, account, container, obj = \
                split_path(unquote(request.path), 5, 5, True)
            validate_device_partition(device, partition)
        except ValueError, err:
            return jresponse('-1', 'bad request', request,400)
        
        if self.mount_check and not check_mount(self.devices, device):
            return jresponse('-1', 'insufficient storage', request,507)
        
        file = DiskFile(self.devices, device, partition, account, container,
                        obj, self.logger, keep_data_fp=True,
                        disk_chunk_size=self.disk_chunk_size,
                        iter_hook=sleep)
        
        if file.is_deleted():
            return jresponse('-1', 'not found', request,404)
        try:
            file_size = file.get_data_file_size()
        except (DiskFileError, DiskFileNotExist):
            file.quarantine()
            return jresponse('-1', 'not found', request,404)

        range = None
        if request.headers.get('range') and not file.metadata.get('X-Static-Large-Object'):
            # range for plain file,not slo
            range = Range(request.headers.get('range'))
            
        response = HResponse(app_iter=file,
                        request=request, conditional_response=True,range=range)
    
        for key, value in file.metadata.iteritems():
            if key.lower().startswith('x-object-meta-') or \
                    key.lower() in self.allowed_headers:
                response.headers[key] = value
    
        
        response.content_length = file_size
        response.etag = file.metadata['ETag']
        
        return request.get_response(response)

    @public
    def HEAD(self, request):
        
        try:
            device, partition, account, container, obj = \
                split_path(unquote(request.path), 5, 5, True)
            validate_device_partition(device, partition)
        except ValueError, err:
            return jresponse('-1', 'bad request', request,400)
        
        if self.mount_check and not check_mount(self.devices, device):
            return jresponse('-1', 'insufficient storage', request,507)
        
        file = DiskFile(self.devices, device, partition, account, container,
                        obj, self.logger, disk_chunk_size=self.disk_chunk_size)
        
        if file.is_deleted():
            return jresponse('-1', 'not found', request,404)
        
        try:
            file_size = file.get_data_file_size()
        except (DiskFileError, DiskFileNotExist):
            file.quarantine()
            return jresponse('-1', 'not found', request,404)
        
        response = HTTPNoContent(request=request)
        response.etag = file.metadata['ETag']
        response.content_length = file_size
        return response
    
    @public
    def META(self, request):
        
        try:
            device, partition, account, container, obj = \
                split_path(unquote(request.path), 5, 5, True)
            validate_device_partition(device, partition)
        except ValueError, err:
            
            return jresponse('-1', 'bad request', request,400)
        
        if self.mount_check and not check_mount(self.devices, device):
            return jresponse('-1', 'insufficient storage', request,507)
        
        file = DiskFile(self.devices, device, partition, account, container,
                        obj, self.logger, disk_chunk_size=self.disk_chunk_size)
        
        if file.is_deleted():
            return jresponse('-1', 'not found', request,404)
        
        try:
            file_size = file.get_data_file_size()
        except (DiskFileError, DiskFileNotExist):
            file.quarantine()
            return jresponse('-1', 'not found', request,404)
        
        hdata = json.dumps(file.metadata)
        response = Response(body=hdata,request=request)
        response.charset = 'utf-8'
        return response
    
    @public
    def DELETE(self, request):
        """Handle HTTP DELETE requests for the Swift Object Server."""
        start_time = time.time()
        try:
            device, partition, account, container, obj = \
                split_path(unquote(request.path), 5, 5, True)
            validate_device_partition(device, partition)
        except ValueError, e:
            return jresponse('-1', 'bad request', request,400)
        
        if self.mount_check and not check_mount(self.devices, device):
            return jresponse('-1', 'insufficient storage', request,507)
        
        response_class = HTTPNoContent
        file = DiskFile(self.devices, device, partition, account, container,
                        obj, self.logger, disk_chunk_size=self.disk_chunk_size)
        
        if file.is_deleted():
            response_class = HTTPNotFound
        
        content_length = file.metadata['Content-Length']
        file.unlinkold()
        file.meta_del()
        self.account_update(request, account, content_length, add_flag=False)
        
        resp = response_class(request=request)
        return resp

    @public
    def DELETE_RECYCLE(self, req):
        try:
            device, partition, account, src_container, src_obj = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(device, partition)
        except ValueError, err:
            return jresponse('-1', 'bad request', req,400)
        
        # user_path = src_obj
        
        recycle_uuid = get_uuid()
        recycle_container = 'recycle'
        
        user_obj = 'user' + '/' + recycle_uuid
        
        if self.mount_check and not check_mount(self.devices, device):
            return jresponse('-1', 'insufficient storage', req,507) 

        src_file = DiskFile(self.devices, device, partition, account, src_container,
                        src_obj, self.logger, disk_chunk_size=self.disk_chunk_size)
        
        user_file = DiskMeta(self.devices, device, partition, account, recycle_container,
                        user_obj, self.logger, disk_chunk_size=self.disk_chunk_size,recycle_uuid=recycle_uuid)
    
        if src_file.is_deleted():
            return jresponse('-1', 'not found', req,404)
        
        if not user_file.is_deleted():
            user_file.unlinkold()
        
        if user_file.fhr_dir_is_deleted():
            user_file.create_dir_object(user_file.fhr_path)
            
        user_file.move(src_file.data_file)
        
        
        if user_file.is_deleted():
            return jresponse('-1', 'conflict', req,409)
            
        user_file.metadata = src_file.metadata
        user_file.metadata['user_path'] = '/' + src_container+ '/' + src_obj
        user_file.metadata['recycle_uuid'] = recycle_uuid
        user_file.metadata['ftype'] = 'f'
        user_file.metadata['X-Timestamp'] = req.headers['x-timestamp']
        user_file.metadata['X-File-Type'] = 'f'
        
        with user_file.mkstemp() as (fd, tmppath):
            user_file.put(fd, tmppath,user_file.metadata, extension='.meta')
            src_file.meta_del()
            
        resp = jresponse('0', '', req,204)
        return resp
    
    def copy_action(self,src_file,dst_file,req,account,dbpath,tx_id):
        
        try:
            upload_expiration = time.time() + self.max_upload_time
            upload_size = 0
            last_sync = 0
            with dst_file.mkstemp() as (fd, tmppath):
                
                for chunk in src_file:
                    
                    upload_size += len(chunk)
                    if time.time() > upload_expiration:
                        task_db_update(dbpath,'request timeout',tx_id)
                        return jresponse('-1','request timeout',req,408)
                   
                    while chunk:
                        written = os.write(fd, chunk)
                        chunk = chunk[written:]
                    # For large files sync every 512MB (by default) written
                    if upload_size - last_sync >= self.bytes_per_sync:
                        tpool.execute(os.fdatasync, fd)
                        drop_buffer_cache(fd, last_sync, upload_size - last_sync)
                        last_sync = upload_size
                    sleep()
                
                dst_file.copy_put(fd, tmppath)
            if dst_file.is_deleted():
                task_db_update(dbpath,'failed','conflict',tx_id)
                return jresponse('-1', 'conflict', req,409)
            
            dst_file.metadata = src_file.metadata
            dst_file.metadata['X-Timestamp'] = req.headers['x-timestamp']
            with dst_file.mkstemp() as (fd, tmppath):
                dst_file.put(fd, tmppath,dst_file.metadata, extension='.meta')
            self.account_update(req, account, src_file.metadata['Content-Length'], add_flag=True)
            task_db_update(dbpath,'success','',tx_id)
            
        except:
            task_db_update(dbpath,'failed','server exception',tx_id)
            syslog.syslog(syslog.LOG_ERR,'object copy: '+str(traceback.format_exc()))
            

    @public
    def COPY(self, req):
        
        device, partition, accountname = split_path(unquote(req.path), 3, 3, True)
        accountname = accountname.split('/')[0]
        dbpath = '%s/%s.db' % (self.devices,accountname)
        tx_id = req.environ.get('HTTP_X_TRANS_ID')
        swifttime = str(time.time())
        task_db_insert(dbpath, tx_id, swifttime, 'running', '')
        
        try:
            device, partition, account, src_container, src_obj = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(device, partition)
        except ValueError, err:
            task_db_update(dbpath,'failed','bad request',tx_id)
            return jresponse('-1', 'bad request', req,400)
    
        try:
            dst_path = req.headers.get('x-copy-dst')
            dst_container, dst_obj = split_path(
                unquote(dst_path), 1, 2, True)
        except ValueError, err:
            task_db_update(dbpath,'failed','bad request',tx_id)
            return jresponse('-1', 'bad request', req,400)
                        
        if self.mount_check and not check_mount(self.devices, device):
            task_db_update(dbpath,'failed','insufficient storage',tx_id)
            return jresponse('-1', 'insufficient storage', req,507)

        if 'x-timestamp' not in req.headers or \
                    not check_float(req.headers['x-timestamp']):
            self.logger.increment('PUT.errors')
            task_db_update(dbpath,'failed','bad request',tx_id)
            return jresponse('-1', 'bad request', req,400)
            
        src_file = DiskFile(self.devices, device, partition, account, src_container,
                        src_obj, self.logger, keep_data_fp=True,disk_chunk_size=self.disk_chunk_size)
        
        dst_file = DiskFile(self.devices, device, partition, account, dst_container,
                        dst_obj, self.logger, disk_chunk_size=self.disk_chunk_size)
        
        if not dst_file.cnt_flag:
            task_db_update(dbpath,'failed','container not found',tx_id)
            return jresponse('-1', 'container not found', req,404) 
        
        if src_file.is_deleted():
            task_db_update(dbpath,'failed','not found',tx_id)
            return jresponse('-1', 'not found', req,404)
        
        if not dst_file.is_deleted():

            overwrite = req.headers.get('X-Overwrite','false').lower()
            if 'true' == overwrite:
                content_length = dst_file.metadata['Content-Length']
                dst_file.unlink_data()
                self.account_update(req, account, content_length, add_flag=False) 
            else:    
                task_db_update(dbpath,'failed','conflict',tx_id)
                return jresponse('-1', 'conflict', req,409)
                                      
        ## dst_file.copy(src_file.data_file) ##
        tx_id = req.environ.get('HTTP_X_TRANS_ID') 
        self.copy_action(src_file, dst_file, req,account,dbpath,tx_id)

        return jresponse('0', '', req,201)
    
    
    @public
    def MOVE(self, req):
           
        try:
            device, partition, account, src_container, src_obj = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(device, partition)
        except ValueError, err:
            return jresponse('-1', 'bad request', req,400)
        
        if 'recycle' == src_container:
            return self.MOVE_RECYCLE(req)
        
        try:
            dst_path = req.headers.get('x-move-dst')
            dst_container, dst_obj = split_path(
                unquote(dst_path), 1, 2, True)
        except ValueError, err:
            return jresponse('-1', 'bad request', req,400)
                        
        if self.mount_check and not check_mount(self.devices, device):
            return jresponse('-1', 'insufficient storage', req,507)

        src_file = DiskFile(self.devices, device, partition, account, src_container,
                        src_obj, self.logger, disk_chunk_size=self.disk_chunk_size)
        
        dst_file = DiskFile(self.devices, device, partition, account, dst_container,
                        dst_obj, self.logger, disk_chunk_size=self.disk_chunk_size)
        
        if not dst_file.cnt_flag:
            return jresponse('-1', 'container not found', req,404) 
        
        if src_file.is_deleted():
            return jresponse('-1', 'not found', req,404)
 
        if not dst_file.is_deleted():

            overwrite = req.headers.get('X-Overwrite','false').lower()
            if 'true' == overwrite:
                content_length = dst_file.metadata['Content-Length']
                dst_file.unlink_data()
                self.account_update(req, account, content_length, add_flag=False) 
            else:    
                return jresponse('-1', 'conflict', req,409)
 
        if dst_file.fhr_dir_is_deleted():
            if req.headers.get('x-fhr-dir') == 'True':
                dst_file.create_dir_object(dst_file.fhr_path)
            else:
                return jresponse('-1', 'not found', req,404)
        
        dst_file.move(src_file.data_file)
        
         
        if dst_file.is_deleted():
            return jresponse('-1', 'conflict', req,409)
            
        dst_file.metadata = src_file.metadata
        dst_file.metadata['X-Timestamp'] = req.headers['x-timestamp']
        with dst_file.mkstemp() as (fd, tmppath):
            dst_file.put(fd, tmppath,dst_file.metadata, extension='.meta')
            src_file.meta_del()
            
        return jresponse('0', '', req,201)
    

    @public
    def MOVE_RECYCLE(self, req):
           
        try:
            device, partition, account, src_container, src_obj = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(device, partition)
        except ValueError, err:
            return jresponse('-1', 'bad request', req,400)
        
        if 'recycle' != src_container:
            return jresponse('-1', 'bad request', req,400)
            
        try:
            dst_path = req.headers.get('x-move-dst')
            dst_container, dst_obj = split_path(
                unquote(dst_path), 1, 2, True)
        except ValueError, err:
            return jresponse('-1', 'bad request', req,400)
                        
        recycle_uuid = src_obj[5:]
        
        if self.mount_check and not check_mount(self.devices, device):
            return jresponse('-1', 'insufficient storage', req,507)

        src_file = DiskMeta(self.devices, device, partition, account, src_container,
                        src_obj, self.logger, disk_chunk_size=self.disk_chunk_size,recycle_uuid=recycle_uuid)
        
        dst_file = DiskFile(self.devices, device, partition, account, dst_container,
                        dst_obj, self.logger, disk_chunk_size=self.disk_chunk_size)
        
        if src_file.is_deleted():
            return jresponse('-1', 'not found', req,404)
        
        if not dst_file.is_deleted():

            overwrite = req.headers.get('X-Overwrite','false').lower()
            if 'true' == overwrite:
                content_length = dst_file.metadata['Content-Length']
                dst_file.unlink_data()
                self.account_update(req, account, content_length, add_flag=False) 
            else:    
                return jresponse('-1', 'conflict', req,409)
        
        if dst_file.fhr_dir_is_deleted():
            dst_file.create_dir_object(dst_file.fhr_path)
        
        dst_file.move(src_file.data_file)
        
        if dst_file.is_deleted():
            return jresponse('-1', 'conflict', req,409)
            
        dst_file.metadata = src_file.metadata
        dst_file.metadata['X-Timestamp'] = req.headers['x-timestamp']
        with dst_file.mkstemp() as (fd, tmppath):
            dst_file.put(fd, tmppath,dst_file.metadata, extension='.meta')
            src_file.meta_del()
            
        return jresponse('0', '', req,201)
    
    @public
    def POST(self, request):
        
        """Handle HTTP POST requests for the Swift Object Server."""
        start_time = time.time()
        try:
            device, partition, account, container, obj = \
                split_path(unquote(request.path), 5, 5, True)
            validate_device_partition(device, partition)
        except ValueError, err:
            self.logger.increment('POST.errors')
            return jresponse('-1', 'bad request', request,400) 
        
        if 'x-timestamp' not in request.headers or \
                    not check_float(request.headers['x-timestamp']):
            self.logger.increment('POST.errors')
            return jresponse('-1', 'Missing timestamp', request,400) 
            
        
        if self.mount_check and not check_mount(self.devices, device):
            self.logger.increment('POST.errors')
            return jresponse('-1', 'insufficient storage', request,507)
        
        file = DiskFile(self.devices, device, partition, account, container,
                        obj, self.logger, disk_chunk_size=self.disk_chunk_size)

        if file.is_deleted():
            return jresponse('-1', 'not found', request,404)
        
        try:
            file_size = file.get_data_file_size()
            
        except (DiskFileError, DiskFileNotExist):
            file.quarantine()
            return jresponse('-1', 'not found', request,404)
        
        metadata = {'X-Timestamp': request.headers['x-timestamp']}
        
        # allow_headers or x-object-meta-*
        
        metadata.update(file.metadata)
        
        for key,val in request.headers.iteritems():
            if key.lower().startswith('x-object-'):
                metadata[key] = str(val)
                
        with file.mkstemp() as (fd, tmppath):
            file.put(fd, tmppath, metadata, extension='.meta')
        self.logger.timing_since('POST.timing', start_time)
        
        return jresponse('0', '', request,202)
    
    def __call__(self, env, start_response):
        """WSGI Application entry point for the Swift Object Server."""
        start_time = time.time()
        req = Request(env)
        self.logger.txn_id = req.headers.get('x-trans-id', None)
        
        if not check_utf8(req.path_info):
            res = jresponse('-1', 'invalid utf8', req,412)
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
                    if req.method == 'DELETE_RECYCLE':
                        print 'path:   '+req.path +  '      status:  '+str(res.status_int) + '  msg: '+res.body
            except (Exception, Timeout):
                self.logger.exception(_('ERROR __call__ error with %(method)s'
                    ' %(path)s '), {'method': req.method, 'path': req.path})
                res = jresponse('-1', 'InternalServerError', req,500)
                 
        trans_time = time.time() - start_time
        
        if req.method in ('PUT', 'DELETE'):
            slow = self.slow - trans_time
            if slow > 0:
                sleep(slow)
        return res(env, start_response)


def app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating WSGI object server apps"""
    conf = global_conf.copy()
    conf.update(local_conf)
    return ObjectController(conf)
