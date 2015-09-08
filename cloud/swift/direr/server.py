

import cloud.swift.common.constraints

from swift.direr import server
from cloud.swift.common.DiskDirer import DiskDirer

from cloud.swift.common.DirMeta import DirMeta

class DirerController(server.DirerController):
    def _get_direr_broker(self, drive, part, account, container,direr):
        
        return DiskDirer(self.root, drive, account, container, direr,self.logger)


    def _get_meta_broker(self, drive, part, account, container,direr,recycle_uuid):
        
        return DirMeta(self.root, drive, account, container, direr,self.logger,recycle_uuid=recycle_uuid)


# def app_factory(global_conf, **local_conf):
    
#    conf = global_conf.copy()
#    conf.update(local_conf)
#    return DirerController(conf)

def filter_factory(global_conf, **local_conf):
    
    conf = global_conf.copy()
    conf.update(local_conf)

    def direr_filter(app):
        return DirerController(app,conf)
    return direr_filter
