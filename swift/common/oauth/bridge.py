#!/user/bin/python
import os
import sys
import commands
import random
import json
from swift.common.oauth.httptool import *

class bridgeUtil(object):
    def __init__(self):
        self.client = NetUtil()

    '''
    def get_client_access_token(self,url='', input = {}):
        recv = self.client.http_post(url,443,input,30,True)
        return json.loads(recv)

    def register_user(self,url='', input = {}):
        recv = self.client.http_post(url,443,input,30,True)
        return json.loads(recv)

    '''
        
    def get_user_access_token(self, url='', port = 443, input = {}):
        recv = self.client.http_post(url,port,input,30,True)
        if not recv:
            return None
        return json.loads(recv)

        
    def verify_user(self, url='', port = 443, input = {}):
        recv = self.client.http_post(url,port,input,30,True)
        if not recv:
            return None
        return json.loads(recv)
