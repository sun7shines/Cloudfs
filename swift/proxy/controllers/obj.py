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

try:
    import simplejson as json
except ImportError:
    import json
import mimetypes
import re
import time
from datetime import datetime
from urllib import unquote, quote
from hashlib import md5
from random import shuffle
import syslog

from eventlet import sleep, GreenPile, Timeout
from eventlet.queue import Queue
from eventlet.timeout import Timeout
from webob.exc import HTTPAccepted, HTTPBadRequest, HTTPNotFound, \
    HTTPPreconditionFailed, HTTPRequestEntityTooLarge, HTTPRequestTimeout, \
    HTTPServerError, HTTPServiceUnavailable
from webob import Request, Response

from swift.common.utils import ContextPool, normalize_timestamp, TRUE_VALUES, \
    public,config_true_value
    
from swift.common.bufferedhttp import http_connect,jresponse
from swift.common.constraints import  check_object_creation, \
    CONTAINER_LISTING_LIMIT, MAX_FILE_SIZE,check_metadata
from swift.common.exceptions import ChunkReadTimeout, \
    ChunkWriteTimeout, ConnectionTimeout, ListingIterNotFound, \
    ListingIterNotAuthorized, ListingIterError,SloSegmentError
from swift.common.http import is_success, is_client_error, HTTP_CONTINUE, \
    HTTP_CREATED, HTTP_MULTIPLE_CHOICES, HTTP_NOT_FOUND,HTTP_CONFLICT, \
    HTTP_INTERNAL_SERVER_ERROR, HTTP_SERVICE_UNAVAILABLE,HTTP_OK, \
    HTTP_INSUFFICIENT_STORAGE, HTTPClientDisconnect
from swift.proxy.controllers.base import Controller, delay_denial
from swift.common.env_utils import *

from swift.common.common.swob import Response as HResponse
from swift.common.common.swob import Range

def segment_listing_iter(listing):
    listing = iter(listing)
    while True:
        seg_dict = listing.next()
        if isinstance(seg_dict['name'], unicode):
            seg_dict['name'] = seg_dict['name'].encode('utf-8')
        yield seg_dict


class SegmentedIterable(object):
    
    """
    :param controller: The ObjectController instance to work with.
    :param container: The container the object segments are within. If
                      container is None will derive container from elements
                      in listing using split('/', 1).
    :param listing: The listing of object segments to iterate over; this may
                    be an iterator or list that returns dicts with 'name' and
                    'bytes' keys.
    :param response: The swob.Response this iterable is associated with, if
                     any (default: None)
    """

    def __init__(self, controller, container, listing, response=None,
                 is_slo=False):
        self.controller = controller
        self.container = container
        self.listing = segment_listing_iter(listing)
        self.is_slo = is_slo
        self.segment = 0
        self.segment_dict = None
        self.segment_peek = None
        self.seek = 0
        self.segment_iter = None
        # See NOTE: swift_conn at top of file about this.
        self.segment_iter_swift_conn = None
        self.position = 0
        self.response = response
        if not self.response:
            self.response = Response()
        self.next_get_time = 0

    def _load_next_segment(self):
        """
        Loads the self.segment_iter with the next object segment's contents.

        :raises: StopIteration when there are no more object segments or
                 segment no longer matches SLO manifest specifications.
        """
        try:
            self.segment += 1
            self.segment_dict = self.segment_peek or self.listing.next()
            self.segment_peek = None
            if self.container is None:
                container, obj = \
                    self.segment_dict['name'].lstrip('/').split('/', 1)
            else:
                container, obj = self.container, self.segment_dict['name']
            partition, nodes = self.controller.app.object_ring.get_nodes(
                self.controller.account_name, container, obj)
            path = '/%s/%s/%s' % (self.controller.account_name, container, obj)
            req = Request.blank(path)
            if self.seek:
                
                req.headers['range'] = 'bytes=%s-' % self.seek
                self.seek = 0
                
            if not self.is_slo and self.segment > \
                    self.controller.app.rate_limit_after_segment:
                sleep(max(self.next_get_time - time.time(), 0))
            self.next_get_time = time.time() + \
                1.0 / self.controller.app.rate_limit_segments_per_sec
            
            resp = self.controller.GETorHEAD_base(
                req, _('Object'), partition,
                self.controller.iter_nodes(partition, nodes,
                                           self.controller.app.object_ring),
                path, len(nodes))
            if self.is_slo and resp.status_int == HTTP_NOT_FOUND:
                raise SloSegmentError(_(
                    'Could not load object segment %(path)s:'
                    ' %(status)s') % {'path': path, 'status': resp.status_int})
            if not is_success(resp.status_int):
                raise Exception(_(
                    'Could not load object segment %(path)s:'
                    ' %(status)s') % {'path': path, 'status': resp.status_int})
            if self.is_slo:
                if resp.etag != self.segment_dict['hash']:
                    raise SloSegmentError(_(
                        'Object segment no longer valid: '
                        '%(path)s etag: %(r_etag)s != %(s_etag)s.' %
                        {'path': path, 'r_etag': resp.etag,
                         's_etag': self.segment_dict['hash']}))
            self.segment_iter = resp.app_iter
            # See NOTE: swift_conn at top of file about this.
            self.segment_iter_swift_conn = getattr(resp, 'swift_conn', None)
        except StopIteration:
            raise
        except SloSegmentError, err:
            if not getattr(err, 'swift_logged', False):
                self.controller.app.logger.error(_(
                    'ERROR: While processing manifest '
                    '/%(acc)s/%(cont)s/%(obj)s, %(err)s'),
                    {'acc': self.controller.account_name,
                     'cont': self.controller.container_name,
                     'obj': self.controller.object_name, 'err': err})
                err.swift_logged = True
                self.response.status_int = HTTP_CONFLICT
            raise StopIteration('Invalid manifiest segment')
        except (Exception, Timeout), err:
            if not getattr(err, 'swift_logged', False):
                self.controller.app.logger.exception(_(
                    'ERROR: While processing manifest '
                    '/%(acc)s/%(cont)s/%(obj)s'),
                    {'acc': self.controller.account_name,
                     'cont': self.controller.container_name,
                     'obj': self.controller.object_name})
                err.swift_logged = True
                self.response.status_int = HTTP_SERVICE_UNAVAILABLE
            raise

    def next(self):
        return iter(self).next()

    def __iter__(self):
        """ Standard iterator function that returns the object's contents. """
        try:
            while True:
                if not self.segment_iter:
                    self._load_next_segment()
                while True:
                    with ChunkReadTimeout(self.controller.app.node_timeout):
                        try:
                            chunk = self.segment_iter.next()
                            break
                        except StopIteration:
                            self._load_next_segment()
                self.position += len(chunk)
                yield chunk
        except StopIteration:
            raise
        except (Exception, Timeout), err:
            if not getattr(err, 'swift_logged', False):
                self.controller.app.logger.exception(_(
                    'ERROR: While processing manifest '
                    '/%(acc)s/%(cont)s/%(obj)s'),
                    {'acc': self.controller.account_name,
                     'cont': self.controller.container_name,
                     'obj': self.controller.object_name})
                err.swift_logged = True
                self.response.status_int = HTTP_SERVICE_UNAVAILABLE
            raise


    def app_iter_range(self, start, stop):
        """
        Non-standard iterator function for use with Swob in serving Range
        requests more quickly. This will skip over segments and do a range
        request on the first segment to return data from, if needed.

        :param start: The first byte (zero-based) to return. None for 0.
        :param stop: The last byte (zero-based) to return. None for end.
        """
        try:
            if start:
                self.segment_peek = self.listing.next()
                while start >= self.position + self.segment_peek['bytes']:
                    self.segment += 1
                    self.position += self.segment_peek['bytes']
                    self.segment_peek = self.listing.next()
                self.seek = start - self.position
            else:
                start = 0
            if stop is not None:
                length = stop - start
            else:
                length = None
            for chunk in self:
                if length is not None:
                    length -= len(chunk)
                    if length < 0:
                        # Chop off the extra:
                        yield chunk[:length]
                        break
                yield chunk
            # See NOTE: swift_conn at top of file about this.
            if self.segment_iter_swift_conn:
                try:
                    self.segment_iter_swift_conn.close()
                except Exception:
                    pass
                self.segment_iter_swift_conn = None
            if self.segment_iter:
                try:
                    while self.segment_iter.next():
                        pass
                except Exception:
                    pass
                self.segment_iter = None
        except StopIteration:
            raise
        except (Exception, Timeout), err:
            if not getattr(err, 'swift_logged', False):
                self.controller.app.logger.exception(_(
                    'ERROR: While processing manifest '
                    '/%(acc)s/%(cont)s/%(obj)s'),
                    {'acc': self.controller.account_name,
                     'cont': self.controller.container_name,
                     'obj': self.controller.object_name})
                err.swift_logged = True
                self.response.status_int = HTTP_SERVICE_UNAVAILABLE
            raise


class ObjectController(Controller):
    """WSGI controller for object requests."""
    server_type = 'Object'

    def __init__(self, app, account_name, container_name, object_name,
                 **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)
        self.object_name = unquote(object_name)

    def _listing_iter(self, lcontainer, lprefix, env):
        
        if isinstance(lcontainer, unicode):
            lcontainer = lcontainer.encode('utf-8')
                
        if isinstance(lprefix, unicode):
            lprefix = lprefix.encode('utf-8')
                
        lpartition, lnodes = self.app.container_ring.get_nodes(self.account_name, lcontainer)
        marker = ''
        while True:
            
            if isinstance(marker, unicode):
                marker = marker.encode('utf-8')
            
            lreq = Request.blank('i will be overridden by env', environ=env)
            # Don't quote PATH_INFO, by WSGI spec
            lreq.environ['PATH_INFO'] = \
                '/%s/%s' % (self.account_name, lcontainer)
            lreq.environ['REQUEST_METHOD'] = 'GET'
            lreq.environ['QUERY_STRING'] = \
                'format=json&prefix=%s&marker=%s' % (quote(lprefix),
                                                     quote(marker))
            shuffle(lnodes)
            lresp = self.GETorHEAD_base(lreq, _('Container'),
                lpartition, lnodes, lreq.path_info,
                len(lnodes))
            
            if lresp.status_int == HTTP_NOT_FOUND:
                raise ListingIterNotFound()
            elif not is_success(lresp.status_int):
                raise ListingIterError()
            if not lresp.body:
                break
            sublisting = json.loads(lresp.body)
            if not sublisting:
                break
            marker = sublisting[-1]['name']
            for obj in sublisting:
                yield obj
                
    def GETorHEAD(self, req):
        
        """Handle HTTP GET or HEAD requests."""
        
        partition, nodes = self.app.object_ring.get_nodes(self.account_name, self.container_name, self.object_name)
        shuffle(nodes)
        resp = self.GETorHEAD_base(req, _('Object'), partition,
                self.iter_nodes(partition, nodes, self.app.object_ring),
                req.path_info, len(nodes))
        
        large_object = None
        range_flag = False
        
        if config_true_value(resp.headers.get('x-static-large-object')) and \
                req.GET.get('multipart-manifest') != 'get' and \
                self.app.allow_static_large_object:
            range_flag = True
            large_object = 'SLO'
            listing_page1 = ()
            listing = []
            lcontainer = None  # container name is included in listing
            if resp.status_int == HTTP_OK and \
                    req.method == 'GET' and not req.range:
                try:
                    listing = json.loads(resp.body)
                except ValueError:
                    listing = []
            else:
                # need to make a second request to get whole manifest
                new_req = req.copy_get()
                new_req.method = 'GET'
                new_req.range = None
                
                new_resp = self.GETorHEAD_base(
                    new_req, _('Object'), partition,
                    self.iter_nodes(partition, nodes, self.app.object_ring),
                    req.path_info, len(nodes))
                if new_resp.status_int // 100 == 2:
                    try:
                        listing = json.loads(new_resp.body)
                    except ValueError:
                        listing = []
                else:
                    return jresponse('-1',"Unable to load SLO manifest", req,503)

        if large_object:
            if len(listing_page1) >= CONTAINER_LISTING_LIMIT:
                hrange = None
                if req.headers.get('range') and range_flag:
                    hrange = Range(req.headers.get('range'))
                    
                resp = HResponse(headers=resp.headers, request=req,
                                conditional_response=True,range=hrange)
                if req.method == 'HEAD':
                    
                    def head_response(environ, start_response):
                        resp(environ, start_response)
                        return iter([])

                    head_response.status_int = resp.status_int
                    return head_response
                else:
                    resp.app_iter = SegmentedIterable(
                        self, lcontainer, listing, resp,
                        is_slo=(large_object == 'SLO'))

            else:
                
                if listing:
                    listing = list(listing)
                    try:
                        content_length = sum(o['bytes'] for o in listing)
                        
                        etag = md5(
                            ''.join(o['hash'] for o in listing)).hexdigest()
                    except KeyError:
                        return jresponse('-1', 'Invalid Manifest File', req,500)

                else:
                    content_length = 0
                    
                    etag = md5().hexdigest()
                
                hrange = None
                if req.headers.get('range') and range_flag:
                    hrange = Range(req.headers.get('range'))
                resp = HResponse(headers=resp.headers, request=req,
                                conditional_response=True,range=hrange)
                
                resp.app_iter = SegmentedIterable(
                    self, lcontainer, listing, resp,
                    is_slo=(large_object == 'SLO'))
                resp.content_length = content_length
                
                resp.etag = etag
            resp.headers['accept-ranges'] = 'bytes'
            # In case of a manifest file of nonzero length, the
            # backend may have sent back a Content-Range header for
            # the manifest. It's wrong for the client, though.
            resp.content_range = None
                     
        return resp

    @public
    @delay_denial
    def HEAD(self, req):
        """Handler for HTTP HEAD requests."""
        
        return self.GETorHEAD(req)


    @public
    @delay_denial
    def GET(self, req):
        """Handler for HTTP GET requests."""
        
        return self.GETorHEAD(req)

    @public
    @delay_denial
    def META(self, req):
        
        part, nodes = self.app.object_ring.get_nodes(self.account_name, self.container_name,self.object_name)
        
        shuffle(nodes)
        resp = self.META_base(req, _('Object'), part, nodes,
                req.path_info, len(nodes))

        return resp
    

    def _send_file(self, conn, path):
        """Method for a file PUT coro"""
        while True:
            chunk = conn.queue.get()
            if not conn.failed:
                try:
                    with ChunkWriteTimeout(self.app.node_timeout):
                        conn.send(chunk)
                except (Exception, ChunkWriteTimeout):
                    conn.failed = True
                    self.exception_occurred(conn.node, _('Object'),
                        _('Trying to write to %s') % path)
            conn.queue.task_done()

    def _connect_put_node(self, account,nodes, part, path, headers,
                          logger_thread_locals,query_string = ''):
        """Method for a file PUT connect"""
        self.app.logger.thread_locals = logger_thread_locals
        for node in nodes:
            try:
                with ConnectionTimeout(self.app.conn_timeout):
                    conn = http_connect(node['ip'], node['port'],
                            account, part, 'PUT', path, headers,query_string)
                with Timeout(self.app.node_timeout):
                    resp = conn.getexpect()
                if resp.status == HTTP_CONTINUE:
                    conn.node = node
                    return conn
                elif resp.status == HTTP_INSUFFICIENT_STORAGE:
                    self.error_limit(node)
            except:
                self.exception_occurred(node, _('Object'),
                    _('Expect: 100-continue on %s') % path)

    @public
    @delay_denial
    def PUT(self, req):
        
        account_partition, accounts = self.account_info(self.account_name,autocreate=False)
        account = accounts[0]
        (container_partition, containers,object_versions ) = self.container_info(self.account_name, self.container_name,
                account_autocreate=self.app.account_autocreate)
        
        if not containers:
            return jresponse('-1', 'not found', req,404)
        
        
        delete_at_part = delete_at_nodes = None
        
        partition, nodes = self.app.object_ring.get_nodes(self.account_name, self.container_name, self.object_name)
        req.headers['X-Timestamp'] = normalize_timestamp(time.time())
        
        error_response = check_object_creation(req, self.object_name)
        if error_response:
            return error_response
        
        overwrite = req.GET.get('overwrite')
        
        if 'true'==overwrite and object_versions :
            
            hreq = Request.blank(req.path_info, environ={'REQUEST_METHOD': 'HEAD'})
            hresp = self.GETorHEAD_base(hreq, _('Object'), partition, nodes,
                hreq.path_info, len(nodes))
            
            is_manifest = 'x-static-large-object' in req.headers or \
                          'x-static-large-object' in hresp.headers
                          
            if hresp.status_int != HTTP_NOT_FOUND and not is_manifest:
                
                lcontainer = object_versions.split('/')[0]
                lprefix = self.object_name + '/'
                
                new_ts = normalize_timestamp(float(time.time()))
                vers_obj_name = lprefix + new_ts
                
                move_headers = {
                    'Destination': '/%s/%s' % (lcontainer, vers_obj_name)}
                move_req = Request.blank(req.path_info, headers=move_headers)
                move_resp = self.MOVE_VERSION(move_req)
                if is_client_error(move_resp.status_int):
                    # missing container or bad permissions
                    return jresponse('-1', 'bad permissions', req,412)
                elif not is_success(move_resp.status_int):
                    # could not copy the data, bail
                    return jresponse('-1', 'ServiceUnavailable', req,503)
                
        reader = req.environ['wsgi.input'].read
        data_source = iter(lambda: reader(self.app.client_chunk_size), '')
        
            
        node_iter = self.iter_nodes(partition, nodes, self.app.object_ring)
        pile = GreenPile(len(nodes))
        for container in containers:
            nheaders = dict(req.headers.iteritems())
            nheaders['Connection'] = 'close'
            nheaders['X-Container-Host'] = '%(ip)s:%(port)s' % container
            nheaders['X-Container-Partition'] = container_partition
            nheaders['X-Container-Device'] = container['device']
            
            nheaders['X-Account-Host'] = '%(ip)s:%(port)s' % account
            nheaders['X-Account-Partition'] = account_partition
            nheaders['X-Account-Device'] = self.account_name
                        
            nheaders['Expect'] = '100-continue'
            if delete_at_nodes:
                node = delete_at_nodes.pop(0)
                nheaders['X-Delete-At-Host'] = '%(ip)s:%(port)s' % node
                nheaders['X-Delete-At-Partition'] = delete_at_part
                nheaders['X-Delete-At-Device'] = node['device']
                
            if overwrite:
                nheaders['x-overwrite'] = overwrite
                
            pile.spawn(self._connect_put_node,self.account_name, node_iter, partition,
                       req.path_info, nheaders, self.app.logger.thread_locals,req.query_string)
        conns = [conn for conn in pile if conn]
        if len(conns) <= len(nodes) / 2:
            self.app.logger.error(
                _('Object PUT returning 503, %(conns)s/%(nodes)s '
                'required connections'),
                {'conns': len(conns), 'nodes': len(nodes) // 2 + 1})
            return jresponse('-1', 'ServiceUnavailable', req,503)
        
        bytes_transferred = 0
        start_time=time.time()

        try:
            with ContextPool(len(nodes)) as pool:
                for conn in conns:
                    conn.failed = False
                    conn.queue = Queue(self.app.put_queue_depth)
                    pool.spawn(self._send_file, conn, req.path)
                while True:
                    with ChunkReadTimeout(self.app.client_timeout):
                        try:
                            chunk = next(data_source)
                        except StopIteration:
                            
                            break
                    bytes_transferred += len(chunk)

                    dural_time=float(time.time()) - float(start_time)
                    if(dural_time>0):
                        speed = float(bytes_transferred)/float(dural_time)/(1000*1000)
                        while(speed >1):
                            sleep(0.1)
                            dural_time=float(time.time()) - float(start_time)
                            speed = float(bytes_transferred)/float(dural_time)/(1000*1000)

                    if bytes_transferred > MAX_FILE_SIZE:
                        return jresponse('-1', 'RequestEntityTooLarge', req,413)
                    for conn in list(conns):
                        if not conn.failed:
                            conn.queue.put(chunk)
                        else:
                            conns.remove(conn)
                    if len(conns) <= len(nodes) / 2:
                        self.app.logger.error(_('Object PUT exceptions during'
                            ' send, %(conns)s/%(nodes)s required connections'),
                            {'conns': len(conns), 'nodes': len(nodes) / 2 + 1})
                        return jresponse('-1', 'ServiceUnavailable', req,503)
                for conn in conns:
                    if conn.queue.unfinished_tasks:
                        conn.queue.join()
            conns = [conn for conn in conns if not conn.failed]
        except ChunkReadTimeout, err:
            self.app.logger.warn(
                _('ERROR Client read timeout (%ss)'), err.seconds)
            return jresponse('-1', 'RequestTimeout', req,408)
        except (Exception, Timeout):
            self.app.logger.exception(
                _('ERROR Exception causing client disconnect'))
            return jresponse('-1', 'ClientDisconnect', req,499)
        if req.content_length and bytes_transferred < req.content_length:
            req.client_disconnect = True
            self.app.logger.warn(
                _('Client disconnected without sending enough data'))
            return jresponse('-1', 'ClientDisconnect', req,499)
        
        statuses = []
        reasons = []
        bodies = []
        etags = set()
        
        for conn in conns:
            try:
                with Timeout(self.app.node_timeout):
                    response = conn.getresponse()
                    statuses.append(response.status)
                    reasons.append(response.reason)
                    body = response.read()
                    bodies.append(body)
                    if response.status >= HTTP_INTERNAL_SERVER_ERROR:
                        self.error_occurred(conn.node,
                            _('ERROR %(status)d %(body)s From Object Server ' \
                            're: %(path)s') % {'status': response.status,
                            'body': bodies[-1][:1024], 'path': req.path})
                        
                    elif is_success(response.status):
                        # etags.add(response.getheader('etag').strip('"'))
                        etags.add(json.loads(body)['md5'])
                        
            except (Exception, Timeout):
                self.exception_occurred(conn.node, _('Object'),
                    _('Trying to get final status of PUT to %s') % req.path)
        
        if len(etags) > 1:
            self.app.logger.error(
                _('Object servers returned %s mismatched etags'), len(etags))
            return jresponse('-1', 'ServerError', req,500)
        etag = len(etags) and etags.pop() or None
        
        while len(statuses) < len(nodes):
            statuses.append(HTTP_SERVICE_UNAVAILABLE)
            reasons.append('')
            bodies.append('')
        
        resp = self.best_response(req, statuses, reasons, bodies,
                    _('Object PUT'),etag=etag)
        
        return resp

    @public
    @delay_denial
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        
        account_partition, accounts = self.account_info(self.account_name,autocreate=False)
        account = accounts[0]
        
        (container_partition, containers,object_versions) = self.container_info(self.account_name, self.container_name)
               
        if not containers:
            return jresponse('-1', 'not found', req,404)
        partition, nodes = self.app.object_ring.get_nodes(self.account_name, self.container_name, self.object_name)
        
        
        headers = []
        for container in containers:
            nheaders = dict(req.headers.iteritems())
            nheaders['X-Timestamp']= normalize_timestamp(time.time())
            nheaders['Connection'] = 'close'
            nheaders['X-Container-Host'] = '%(ip)s:%(port)s' % container
            nheaders['X-Container-Partition'] = container_partition
            nheaders['X-Container-Device'] = container['device']
            
            nheaders['X-Account-Host'] = '%(ip)s:%(port)s' % account
            nheaders['X-Account-Partition'] = account_partition
            nheaders['X-Account-Device'] = self.account_name
                                    
            headers.append(nheaders)
        resp = self.make_requests(self.account_name,req, self.app.object_ring,
                partition, 'DELETE_RECYCLE', req.path_info, headers)
        
        if object_versions and req.GET.get('cover') == 'true':
            # this is a version manifest and needs to be handled differently
            
                
            lcontainer = object_versions.split('/')[0]
            # prefix_len = '%03x' % len(self.object_name)
            lprefix = self.object_name + '/'
            last_item = None
            try:
                for last_item in self._listing_iter(lcontainer, lprefix,
                                                    req.environ):
                    pass
            except ListingIterNotFound:
                # no worries, last_item is None
                pass
            except ListingIterNotAuthorized, err:
                return err.aresp
            except ListingIterError:
                return jresponse('-1','ServerERROR',req,500)
            if last_item:
                
                move_path = '/' + self.account_name + '/' + \
                            lcontainer + '/' + last_item['name']
                move_headers = {'Destination': '/' + self.container_name + '/' + self.object_name }
                
                creq = Request.blank(move_path, headers=move_headers)
                move_resp = self.MOVE_VERSION(creq)
                
                if is_client_error(move_resp.status_int):
                    return jresponse('-1', 'client error', req,412)
                elif not is_success(move_resp.status_int):
                    return jresponse('-1', 'ServiceUnavailable', req,503)
                
        return resp


    @public
    def COPY(self,req):    
        
        account_partition, accounts = self.account_info(self.account_name,autocreate=False)
        account = accounts[0]
        
        (container_partition, containers,_) = self.container_info(self.account_name, self.container_name,
                account_autocreate=self.app.account_autocreate)
        
        if not containers:
            return jresponse('-1', 'not found', req,404)
        
        object_partition, object_nodes = self.app.object_ring.get_nodes(self.account_name, self.container_name, self.object_name)
        
        headers = []
        req.GET['ftype'] = 'f'
        for container in containers:
            
            nheaders = {'X-Timestamp': normalize_timestamp(time.time()),
                        'x-trans-id': self.trans_id,
                        'X-Container-Host': '%(ip)s:%(port)s' % container,
                        'X-Container-Partition': container_partition,
                        'X-Container-Device': container['device'],
                        'x-copy-dst':req.headers['Destination'],
                        'x-async':req.GET.get('async','false'),
                        'x-ftype':req.GET['ftype'],
                        'x-overwrite':req.GET.get('overwrite','false'),
                        'X-Account-Host': '%(ip)s:%(port)s' % account,
                        'X-Account-Partition': account_partition,
                        'X-Account-Device': self.account_name,
                        
                        'Connection': 'close'}
                 
            self.transfer_headers(req.headers, nheaders)
            headers.append(nheaders)
            
        resp = self.copy_make_requests(self.account_name,req, self.app.object_ring,
                object_partition, 'COPY', req.path_info, headers)
        
        
        return resp
    
    @public
    def MOVE(self,req):    
    
        (container_partition, containers,object_versions) = self.container_info(self.account_name, self.container_name,
                account_autocreate=self.app.account_autocreate)
        
        if not containers:
            return jresponse('-1', 'not found', req,404)
        
        object_partition, object_nodes = self.app.object_ring.get_nodes(self.account_name, self.container_name, self.object_name)
        
        headers = []
        req.GET['ftype'] = 'f'
        for container in containers:
            
            nheaders = {'X-Timestamp': normalize_timestamp(time.time()),
                        'x-trans-id': self.trans_id,
                        'X-Container-Host': '%(ip)s:%(port)s' % container,
                        'X-Container-Partition': container_partition,
                        'X-Container-Device': container['device'],
                        'x-move-dst':req.headers['Destination'],
                        'x-ftype':req.GET['ftype'],
                        'x-overwrite':req.GET.get('overwrite','false'),
                        'Connection': 'close'}
                 
            self.transfer_headers(req.headers, nheaders)
            headers.append(nheaders)
            
        resp = self.make_requests(self.account_name,req, self.app.object_ring,
                object_partition, 'MOVE', req.path_info, headers)
        
        if False and object_versions:
            # this is a version manifest and needs to be handled differently
            
            lcontainer = object_versions.split('/')[0]
            # prefix_len = '%03x' % len(self.object_name)
            lprefix = self.object_name + '/'
            last_item = None
            try:
                for last_item in self._listing_iter(lcontainer, lprefix,
                                                    req.environ):
                    pass
            except ListingIterNotFound:
                # no worries, last_item is None
                pass
            except ListingIterNotAuthorized, err:
                return err.aresp
            except ListingIterError:
                return jresponse('-1','ServerERROR',req,500)
               
            if last_item:
                
                move_path = '/' + self.account_name + '/' + \
                            lcontainer + '/' + last_item['name']
                move_headers = {'Destination': '/' + self.container_name + '/' + self.object_name }
                
                creq = Request.blank(move_path, headers=move_headers)
                move_resp = self.MOVE_VERSION(creq)
                
                if is_client_error(move_resp.status_int):
                    return jresponse('-1', 'client error', req,412)
                elif not is_success(move_resp.status_int):
                    return jresponse('-1', 'ServiceUnavailable', req,503) 
                
        return resp
    
    
    @public
    def MOVE_VERSION(self,req):    
        
        (container_partition, containers,_) = self.container_info(self.account_name, self.container_name,
                account_autocreate=self.app.account_autocreate)
        
        if not containers:
            return jresponse('-1', 'not found', req,404)
        
        object_partition, object_nodes = self.app.object_ring.get_nodes(self.account_name, self.container_name, self.object_name)
        
        headers = []
        req.GET['ftype'] = 'f'
        for container in containers:
            
            nheaders = {'X-Timestamp': normalize_timestamp(time.time()),
                        'x-trans-id': self.trans_id,
                        'X-Container-Host': '%(ip)s:%(port)s' % container,
                        'X-Container-Partition': container_partition,
                        'X-Container-Device': container['device'],
                        'x-move-dst':req.headers['Destination'],
                        'x-ftype':req.GET['ftype'],
                        'x-fhr-dir':'True',
                        'Connection': 'close'}
                 
            self.transfer_headers(req.headers, nheaders)
            headers.append(nheaders)
            
        resp = self.make_requests(self.account_name,req, self.app.object_ring,
                object_partition, 'MOVE', req.path_info, headers)
               
        return resp
    
    @public
    @delay_denial
    def POST(self, req):
        
        error_response = check_metadata(req, 'object')
        if error_response:
            return error_response
        
        container_partition, containers,_ = self.container_info(self.account_name, self.container_name,
                account_autocreate=self.app.account_autocreate)
            
        if not containers:
            return jresponse('-1', 'not found', req,404)
        
        partition, nodes = self.app.object_ring.get_nodes(self.account_name, self.container_name, self.object_name)
        
        req.headers['X-Timestamp'] = normalize_timestamp(time.time())
        
        headers = []
        for container in containers:
            nheaders = dict(req.headers.iteritems())
            nheaders['Connection'] = 'close'
            nheaders['X-Container-Host'] = '%(ip)s:%(port)s' % container
            nheaders['X-Container-Partition'] = container_partition
            nheaders['X-Container-Device'] = container['device']
            
            headers.append(nheaders)
        resp = self.make_requests(self.account_name,req, self.app.object_ring, partition,
                                  'POST', req.path_info, headers)
        return resp
        
