# -*- coding: utf-8 -*-

from urllib import quote
from cStringIO import StringIO
from datetime import datetime
import mimetypes
from webob import Request
from urllib import unquote

from webob.exc import HTTPBadRequest, HTTPServerError, \
    HTTPMethodNotAllowed, HTTPRequestEntityTooLarge, HTTPLengthRequired
    
from swift.common.mx_swob import wsgify
    
from swift.common.utils import json, get_logger, config_true_value
from swift.common.middleware.bulk import get_response_body, \
    ACCEPTABLE_FORMATS, Bulk

from swift.common.utils import split_path
from swift.common.env_utils import *
from swift.common.bufferedhttp import jresponse

def parse_input(raw_data):
    
    try:
        parsed_data = json.loads(raw_data)
    except ValueError:
        raise HTTPBadRequest("Manifest must be valid json.")

    req_keys = set(['path', 'etag', 'size_bytes'])
    try:
        for seg_dict in parsed_data:
            if (set(seg_dict.keys()) != req_keys or
                    '/' not in seg_dict['path'].lstrip('/')):
                raise HTTPBadRequest('Invalid SLO Manifest File')
    except (AttributeError, TypeError):
        raise HTTPBadRequest('Invalid SLO Manifest File')

    return parsed_data


class StaticLargeObject(object):
    

    def __init__(self, app, conf):
        self.conf = conf
        self.app = app
        self.logger = get_logger(conf, log_route='slo')
        
        self.max_manifest_segments = int(self.conf.get('max_manifest_segments',
                                         1000))
        
        self.max_manifest_size = int(self.conf.get('max_manifest_size',
                                     1024 * 1024 * 2))
        self.min_segment_size = int(self.conf.get('min_segment_size',
                                    1024 * 1024))
        self.bulk_deleter = Bulk(
            app, {'max_deletes_per_request': self.max_manifest_segments})

    def handle_multipart_put(self, req):
                
        try:
            vrs, account, container, obj = split_path(req.path,1, 4, True)
        except ValueError:
            return self.app
        if req.content_length > self.max_manifest_size:
            raise HTTPRequestEntityTooLarge(
                "Manifest File > %d bytes" % self.max_manifest_size)
            
        if req.headers.get('X-Copy-From') or req.headers.get('Destination'):
            raise HTTPMethodNotAllowed(
                'Multipart Manifest PUTs cannot be Copy requests')
        if req.content_length is None and \
                req.headers.get('transfer-encoding', '').lower() != 'chunked':
            raise HTTPLengthRequired(request=req)
        parsed_data = parse_input(req.environ['wsgi.input'].read(self.max_manifest_size))
        problem_segments = []

        if len(parsed_data) > self.max_manifest_segments:
            raise HTTPRequestEntityTooLarge(
                'Number segments must be <= %d' % self.max_manifest_segments)
            
        total_size = 0
        out_content_type = 'application/json'
        if not out_content_type:
            out_content_type = 'text/plain'
        data_for_storage = []
        for index, seg_dict in enumerate(parsed_data):
            obj_path = '/'.join(
                ['', vrs, account, seg_dict['path'].lstrip('/')])
            try:
                seg_size = int(seg_dict['size_bytes'])
            except (ValueError, TypeError):
                raise HTTPBadRequest('Invalid Manifest File')
            
            new_env = req.environ.copy()
            if isinstance(obj_path, unicode):
                obj_path = obj_path.encode('utf-8')
            new_env['PATH_INFO'] = obj_path
            new_env['REQUEST_METHOD'] = 'HEAD'
            new_env['swift.source'] = 'SLO'
            del(new_env['wsgi.input'])
            del(new_env['QUERY_STRING'])
            new_env['CONTENT_LENGTH'] = 0
            new_env['HTTP_USER_AGENT'] = \
                '%s MultipartPUT' % req.environ.get('HTTP_USER_AGENT')
            head_seg_resp = \
                Request.blank(obj_path, new_env).get_response(self.app)
                
            if head_seg_resp.status_int // 100 == 2:
                total_size += seg_size
                if seg_size != head_seg_resp.content_length:
                    problem_segments.append([quote(obj_path), 'Size Mismatch'])
                if seg_dict['etag'] != head_seg_resp.etag:
                    problem_segments.append([quote(obj_path), 'Etag Mismatch'])
                                
                data_for_storage.append(
                    {'name': '/' + seg_dict['path'].lstrip('/'),
                     'bytes': seg_size,
                     'hash': seg_dict['etag']})

            else:
                problem_segments.append([quote(obj_path),
                                         head_seg_resp.status])
        if problem_segments:
            resp_body = get_response_body(
                out_content_type, {}, problem_segments)
            raise jresponse('-1','badrequest',req,400,param=resp_body)
        env = req.environ

        
        env['swift.content_type_overriden'] = True
        
        env['HTTP_X_STATIC_LARGE_OBJECT'] = 'True'
        json_data = json.dumps(data_for_storage)
        env['CONTENT_LENGTH'] = str(len(json_data))
        env['wsgi.input'] = StringIO(json_data)
        return self.app

    def handle_multipart_delete(self, req):
        
        new_env = req.environ.copy()
        new_env['REQUEST_METHOD'] = 'GET'
        del(new_env['wsgi.input'])
        new_env['QUERY_STRING'] = 'multipart-manifest=get'
        new_env['CONTENT_LENGTH'] = 0
        new_env['HTTP_USER_AGENT'] = \
            '%s MultipartDELETE' % req.environ.get('HTTP_USER_AGENT')
        new_env['swift.source'] = 'SLO'
        get_man_resp = \
            Request.blank('', new_env).get_response(self.app)
            
        if get_man_resp.status_int // 100 == 2:
            if not config_true_value(
                    get_man_resp.headers.get('X-Static-Large-Object')):
                raise HTTPBadRequest('Not an SLO manifest')
            try:
                manifest = json.loads(get_man_resp.body)
            except ValueError:
                raise HTTPServerError('Invalid manifest file')
            delete_resp = self.bulk_deleter.handle_delete(
                req,
                objs_to_delete=[o['name'].encode('utf-8') for o in manifest],
                user_agent='MultipartDELETE', swift_source='SLO')
            if delete_resp.status_int // 100 == 2:
                # delete the manifest file itself
                return self.app
            else:
                return delete_resp
        return get_man_resp

    @wsgify
    def __call__(self, req):
        """
        WSGI entry point
        """
        try:
            vrs, account, container, obj = split_path(req.path,1, 4, True)
        except ValueError:
            return self.app
        if obj:
            if req.method == 'PUT' and \
                    req.GET.get('multipart-manifest') == 'put':
                return self.handle_multipart_put(req)
            if req.method == 'DELETE' and \
                    req.GET.get('multipart-manifest') == 'delete':
                return self.handle_multipart_delete(req)
            if 'X-Static-Large-Object' in req.headers:
                raise HTTPBadRequest(
                    request=req,
                    body='X-Static-Large-Object is a reserved header. '
                    'To create a static large object add query param '
                    'multipart-manifest=put.')

        return self.app


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def slo_filter(app):
        return StaticLargeObject(app, conf)
    return slo_filter

