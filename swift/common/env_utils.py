# -*- coding: utf-8 -*-

def env_comment(env,comment=''):
    
    if env.get('fwuser_info') and not env['fwuser_info'].get('lock'):
        env['fwuser_info']['comment'] = comment
        env['fwuser_info']['lock'] = True