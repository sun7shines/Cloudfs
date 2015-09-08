# Copyright (c) 2010-2012 OpenStack, LLC.


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

from eventlet import sleep, GreenPile, Timeout
from eventlet.queue import Queue
from eventlet.timeout import Timeout
from webob.exc import HTTPAccepted, HTTPBadRequest, HTTPNotFound, \
    HTTPPreconditionFailed, HTTPRequestEntityTooLarge, HTTPRequestTimeout, \
    HTTPServerError, HTTPServiceUnavailable
from webob import Request, Response

from swift.common.utils import ContextPool, normalize_timestamp, TRUE_VALUES, \
    public
from swift.common.bufferedhttp import http_connect,jresponse

from swift.common.constraints import  check_object_creation, \
    CONTAINER_LISTING_LIMIT, MAX_FILE_SIZE
from swift.common.exceptions import ChunkReadTimeout, \
    ChunkWriteTimeout, ConnectionTimeout, ListingIterNotFound, \
    ListingIterNotAuthorized, ListingIterError
from swift.common.http import is_success, is_client_error, HTTP_CONTINUE, \
    HTTP_CREATED, HTTP_MULTIPLE_CHOICES, HTTP_NOT_FOUND, \
    HTTP_INTERNAL_SERVER_ERROR, HTTP_SERVICE_UNAVAILABLE, \
    HTTP_INSUFFICIENT_STORAGE, HTTPClientDisconnect
from swift.proxy.controllers.base import Controller, delay_denial

from swift.common.env_utils import *

class LinkController(Controller):
    """WSGI controller for object requests."""
    server_type = 'Object'

    def __init__(self, app, account_name, container_name, link_name,
                 **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)
        self.link_name = unquote(link_name)

    @public
    @delay_denial
    def CREATESYMLINK(self, req):
        
        (container_partition, containers,_) = self.container_info(self.account_name, self.container_name,
                account_autocreate=self.app.account_autocreate)
        
        if not containers:
            return jresponse('-1', 'not found', req,404)
        
        link_partition, link_nodes = self.app.link_ring.get_nodes(self.account_name, self.container_name, self.link_name)
        
        headers = []
        for container in containers:
            
            nheaders = {'X-Timestamp': normalize_timestamp(time.time()),
                        'x-trans-id': self.trans_id,
                        'X-Container-Host': '%(ip)s:%(port)s' % container,
                        'X-Container-Partition': container_partition,
                        'X-Container-Device': container['device'],
                        'x-link-dst':req.headers['Destination'],
                        'x-ftype':req.GET['ftype'],
                        'Connection': 'close'}
                 
            self.transfer_headers(req.headers, nheaders)
            headers.append(nheaders)
            
        resp = self.make_requests(self.account_name,req, self.app.link_ring,
                link_partition, 'PUT', req.path_info, headers)
        
        return resp


