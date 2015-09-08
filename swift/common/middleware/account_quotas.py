# -*- coding: utf-8 -*-
# Copyright (c) 2013 OpenStack Foundation.
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

""" Account quota middleware for Openstack Swift Proxy """

from webob.exc import HTTPForbidden, HTTPRequestEntityTooLarge, HTTPBadRequest
from webob import Request
from swift.common.mx_swob import wsgify

from swift.proxy.controllers.base import get_account_info
from swift.common.utils import split_path
from swift.common.bufferedhttp import jresponse

class AccountQuotaMiddleware(object):


    def __init__(self, app, *args, **kwargs):
        self.app = app

    @wsgify
    def __call__(self, request):
       
        if request.method not in ("PUT","COPY"):
            return self.app

        try:
            split_path(request.path,2, 4, rest_with_last=True)
        except ValueError:
            return self.app

        new_quota = request.headers.get('X-Account-Meta-Quota-Bytes')
        if new_quota:
            if not new_quota.isdigit():
                return jresponse('-1', 'bad request', request, 400)
            return self.app

        account_info = get_account_info(request.environ, self.app)
        new_size = int(account_info['bytes']) + (request.content_length or 0)
        quota = int(account_info['meta'].get('quota-bytes', -1))

        if 0 <= quota < new_size:
            respbody='Your request is too large.'
            return jresponse('-1', respbody, request,413)

        return self.app


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    def account_quota_filter(app):
        return AccountQuotaMiddleware(app)
    return account_quota_filter
