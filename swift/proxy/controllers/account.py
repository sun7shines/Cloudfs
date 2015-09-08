# Copyright (c) 2010-2012 OpenStack, LLC.


import time
from urllib import unquote
from random import shuffle

from webob.exc import HTTPBadRequest, HTTPMethodNotAllowed
from webob import Request

from swift.common.utils import normalize_timestamp, public
from swift.common.constraints import MAX_ACCOUNT_NAME_LENGTH
from swift.common.http import is_success, HTTP_NOT_FOUND
from swift.proxy.controllers.base import Controller
from swift.common.bufferedhttp import jresponse
from swift.common.env_utils import *

class AccountController(Controller):
    """WSGI controller for account requests"""
    server_type = 'Account'

    def __init__(self, app, account_name, **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)

    def GETorHEAD(self, req):
        """Handler for HTTP GET/HEAD requests."""
        partition, nodes = self.app.account_ring.get_nodes(self.account_name)
        shuffle(nodes)
        resp = self.GETorHEAD_base(req, _('Account'), partition, nodes,
                req.path_info.rstrip('/'), len(nodes))
        if resp.status_int == HTTP_NOT_FOUND and self.app.account_autocreate:
            if len(self.account_name) > MAX_ACCOUNT_NAME_LENGTH:
                respbody = 'Account name length of %d longer than %d' % (len(self.account_name), MAX_ACCOUNT_NAME_LENGTH)
                return jresponse('-1', respbody, req,400)
                
            headers = {'X-Timestamp': normalize_timestamp(time.time()),
                       'X-Trans-Id': self.trans_id,
                       'Connection': 'close'}
            resp = self.make_requests(self.account_name,
                Request.blank('/v1/' + self.account_name),
                self.app.account_ring, partition, 'PUT',
                '/' + self.account_name, [headers] * len(nodes))
            if not is_success(resp.status_int):
                self.app.logger.warning('Could not autocreate account %r' %
                                        self.account_name)
                return resp
            resp = self.GETorHEAD_base(req, _('Account'), partition, nodes,
                req.path_info.rstrip('/'), len(nodes))
        return resp
    
    @public
    def META(self, req):
        """Handler for HTTP GET/HEAD requests."""
        
        partition, nodes = self.app.account_ring.get_nodes(self.account_name)
        shuffle(nodes)
        resp = self.META_base(req, _('Account'), partition, nodes,
                req.path_info.rstrip('/'), len(nodes))
        
        if resp.status_int == HTTP_NOT_FOUND and self.app.account_autocreate:
            if len(self.account_name) > MAX_ACCOUNT_NAME_LENGTH:
                
                respbody = 'Account name length of %d longer than %d' % \
                            (len(self.account_name), MAX_ACCOUNT_NAME_LENGTH)
                return jresponse('-1', respbody, req,400)
            
            headers = {'X-Timestamp': normalize_timestamp(time.time()),
                       'X-Trans-Id': self.trans_id,
                       'Connection': 'close'}
            resp = self.make_requests(self.account_name,
                Request.blank('/v1/' + self.account_name),
                self.app.account_ring, partition, 'PUT',
                '/' + self.account_name, [headers] * len(nodes))
            if not is_success(resp.status_int):
                self.app.logger.warning('Could not autocreate account %r' %
                                        self.account_name)
                return resp
            resp = self.META_base(req, _('Account'), partition, nodes,
                req.path_info.rstrip('/'), len(nodes))
            
        return resp

    
    @public
    def PUT(self, req):
        """HTTP PUT request handler."""
        if not self.app.allow_account_management:
            return jresponse('-1','method not allowed',req,405)
        
        if len(self.account_name) > MAX_ACCOUNT_NAME_LENGTH:
            
            respbody = 'Account name length of %d longer than %d' % \
                        (len(self.account_name), MAX_ACCOUNT_NAME_LENGTH)
            return jresponse('-1', respbody, req,400)
        
        account_partition, accounts = self.app.account_ring.get_nodes(self.account_name)
        headers = {'X-Timestamp': normalize_timestamp(time.time()),
                   'x-trans-id': self.trans_id,
                   'Connection': 'close'}
        self.transfer_headers(req.headers, headers)
        
        resp = self.make_requests(self.account_name,req, self.app.account_ring,
            account_partition, 'PUT', req.path_info, [headers] * len(accounts))
        return resp

    @public
    def POST(self, req):
        """HTTP POST request handler."""
        
        account_partition, accounts = self.app.account_ring.get_nodes(self.account_name)
        headers = {'X-Timestamp': normalize_timestamp(time.time()),
                   'X-Trans-Id': self.trans_id,
                   'Connection': 'close'}
        self.transfer_headers(req.headers, headers)
        
        resp = self.make_requests(self.account_name,req, self.app.account_ring,
            account_partition, 'POST', req.path_info,
            [headers] * len(accounts))
        if resp.status_int == HTTP_NOT_FOUND and self.app.account_autocreate:
            if len(self.account_name) > MAX_ACCOUNT_NAME_LENGTH:
                
                respbody = 'Account name length of %d longer than %d' % \
                            (len(self.account_name), MAX_ACCOUNT_NAME_LENGTH)
                return jresponse('-1', respbody, req,400)
            
            resp = self.make_requests(self.account_name,
                Request.blank('/v1/' + self.account_name),
                self.app.account_ring, account_partition, 'PUT',
                '/' + self.account_name, [headers] * len(accounts))
            if not is_success(resp.status_int):
                self.app.logger.warning('Could not autocreate account %r' %
                                        self.account_name)
                return resp
        return resp

    @public
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        if not self.app.allow_account_management:
            return jresponse('-1', 'method not allowed', req,405)
        account_partition, accounts = self.app.account_ring.get_nodes(self.account_name)
        headers = {'X-Timestamp': normalize_timestamp(time.time()),
                   'X-Trans-Id': self.trans_id,
                   'Connection': 'close'}
        
        resp = self.make_requests(self.account_name,req, self.app.account_ring,
            account_partition, 'DELETE', req.path_info,
            [headers] * len(accounts))
        return resp

