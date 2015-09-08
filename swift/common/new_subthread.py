# -*- coding: utf-8 -*-

import time
import threading
import thread
import syslog
import traceback
import sys
import multiprocessing

class Vmdworker(threading.Thread):


    def __init__(self, threadname, func, args):

        self.func = func
        self.param = args
        self.threadname = threadname
        threading.Thread.__init__(self)

    def run(self):
        strs = ""
        num = len(self.param)

        for i in range(0,num):
            strs += "self.param[%d]" % i
            if i == num -1:
                pass # do nothing
            else:
                strs += ","
        try:
            eval("self.func(%s)" % strs)
        except:
            syslog.syslog(syslog.LOG_ERR, "thread_erro:"+str(sys.exc_info()))
            syslog.syslog(syslog.LOG_ERR, "thread_erro:"+traceback.format_exc())

def addtosubthread(threadname, func, *args):  #support compound

    worker = Vmdworker(threadname, func, args)
    if worker == None:
        return False
    worker.setDaemon(True)
    try:
        worker.start()
    except thread.error:
        syslog.syslog(syslog.LOG_ERR, str(sys.exc_info()))
        syslog.syslog(syslog.LOG_ERR, traceback.format_exc())
    time.sleep(0.1)

    
