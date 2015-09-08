# -*- coding: utf-8 -*-
#python sqlite

import sqlite3
import os
from urllib import unquote
import traceback

def get_conn(path):
    
    conn = sqlite3.connect(path)
    conn.text_factory = lambda x: unicode(x, 'utf-8', 'ignore')
    return conn
    
def get_cursor(conn):
    
    if conn is not None:
        return conn.cursor()
    

def drop_table(conn, table):
    
    if table is not None and table != '':
        sql = 'DROP TABLE IF EXISTS ' + table
        
        cu = get_cursor(conn)
        cu.execute(sql)
        conn.commit()
        close_all(conn, cu)
    

def create_table(conn, sql):
    
    if sql is not None and sql != '':
        cu = get_cursor(conn)
        cu.execute(sql)
        conn.commit()
        
        close_all(conn, cu)
    
def close_all(conn, cu):
    
    try:
        if cu is not None:
            cu.close()
    finally:
        if cu is not None:
            cu.close()

def db_save(conn, sql, data):
    
    if sql is not None and sql != '':
        if data is not None:
            cu = get_cursor(conn)
            for d in data:
                cu.execute(sql, d)
                conn.commit()
            close_all(conn, cu)
    
def fetchall(conn, sql):
    
    '''查询所有数据'''
    data = []
    if sql is not None and sql != '':
        cu = get_cursor(conn)
        cu.execute(sql)
        data = cu.fetchall()
        return data 
        
def update(conn, sql, data):
    '''更新数据'''
    if sql is not None and sql != '':
        if data is not None:
            cu = get_cursor(conn)
            for d in data:
                cu.execute(sql, d)
                conn.commit()
            close_all(conn, cu)
    else:
        print 'the %s is empty or equal None!' % (sql)

def delete(conn, sql):
    '''删除数据'''
    if sql is not None and sql != '':
        cu = get_cursor(conn)
        cu.execute(sql)
        conn.commit()

        close_all(conn, cu)

def delete_data(conn, sql, data):
    '''删除数据'''
    if sql is not None and sql != '':
        if data is not None:
            cu = get_cursor(conn)
            for d in data:
                
                cu.execute(sql, d)
                conn.commit()
            close_all(conn, cu)
    
def fetchone(conn, sql, data):
    '''查询一条数据'''
    if sql is not None and sql != '':
        if data is not None:
            
            
            cu = get_cursor(conn)
            cu.execute(sql, data)
            r = cu.fetchall()
            return r


def task_db_init(dbpath):

    table = 'tasks'

    conn = get_conn(dbpath)
    drop_table(conn, table)
        
    # id tx_id path type method tenant url time status comment
    create_table_sql = '''CREATE TABLE `tasks` (
                          `id` integer PRIMARY KEY autoincrement,
                          `tx_id` varchar(64) DEFAULT NULL,
                          `time` varchar(32) DEFAULT NULL,
                          `status` varchar(256) DEFAULT NULL,
                          `comment` varchar(256) DEFAULT NULL
                        )'''
    conn = get_conn(dbpath)
    create_table(conn, create_table_sql)
    
def task_db_values(dbpath,tx_id):
    '''查询所有数据...'''
    
    fetchall_sql = '''SELECT time,status,comment FROM tasks WHERE tx_id = ?'''
    data = (tx_id,)
    conn = get_conn(dbpath)
    return fetchone(conn, fetchall_sql,data)

def task_db_update(dbpath,status='status3',comment='comments3',tx_id ='tx1'):
        
    update_sql = 'UPDATE tasks SET status = ?,comment = ? WHERE tx_id = ? '
    data = [(status, comment,tx_id)]
    
    conn = get_conn(dbpath)
    update(conn, update_sql, data)

def task_db_delete(dbpath,tx_id):
    
    delete_sql = 'DELETE FROM tasks WHERE tx_id = ? '
    data = [(tx_id,)]
    conn = get_conn(dbpath)
    delete_data(conn, delete_sql,data)

def task_db_insert(dbpath,tx_id, swifttime, status, comment):
    
    save_sql = '''INSERT INTO tasks values (?, ?, ?, ?, ?)'''
    data = [(None, tx_id, swifttime, status, comment)]
    conn = get_conn(dbpath)
    db_save(conn, save_sql, data)
    
def db_init(dbpath):
    
    table = 'operations'
    
    conn = get_conn(dbpath)
    drop_table(conn, table)
    
    # id tx_id path type method tenant url time status comment
    create_table_sql = '''CREATE TABLE `operations` (
                          `id` integer PRIMARY KEY autoincrement,
                          `tx_id` varchar(64) DEFAULT NULL,
                          `path` varchar(256) NOT NULL,
                          `type` varchar(8) DEFAULT NULL,
                          `method` varchar(8) DEFAULT NULL,
                          `tenant` varchar(256) DEFAULT NULL,
                          `url` varchar(512) DEFAULT NULL,
                          `time` varchar(32) DEFAULT NULL,
                          `status` varchar(256) DEFAULT NULL,
                          `comment` varchar(256) DEFAULT NULL
                        )'''
    conn = get_conn(dbpath)
    create_table(conn, create_table_sql)

def db_values(dbpath,desc=False,limit=None):
    '''查询所有数据...'''
    
    if desc and limit:
        fetchall_sql = '''SELECT path,type,method,tenant,time,status,comment FROM operations order by id desc limit %s''' % (str(limit))
    else:
        fetchall_sql = '''SELECT path,type,method,tenant,time,status,comment FROM operations'''
        
    conn = get_conn(dbpath)
    return fetchall(conn, fetchall_sql)

def db_update(dbpath,status='status3',comment='comments3',tx_id ='tx1'):
        
    update_sql = 'UPDATE operations SET status = ?,comment = ? WHERE tx_id = ? '
    data = [(status, comment,tx_id)]
    
    conn = get_conn(dbpath)
    update(conn, update_sql, data)

def db_delete(dbpath,desc=False,limit=None):
    
    if desc and limit:
        delete_sql = 'DELETE FROM operations WHERE id IN (SELECT id FROM operations order by id desc limit %s)' % (str(limit))
    else:
        delete_sql = 'DELETE FROM operations'
    data = []
    conn = get_conn(dbpath)
    delete(conn, delete_sql)

def db_insert(dbpath,tx_id, path, type, method, tenant, url, swifttime, status, comment):
    
    save_sql = '''INSERT INTO operations values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'''
    data = [(None, tx_id, unquote(path), type, method, tenant, unquote(url), swifttime, status, comment)]
    conn = get_conn(dbpath)
    # conn.text_factory = lambda x: unicode(x, 'utf-8', 'ignore')
    try:
        db_save(conn, save_sql, data)
    except:
        print dbpath+'  '+str(traceback.format_exc())
    
def operations_main():
    account = 'zhu__feng006'
    dbpath = '/mnt/cloudfs-object/%s.db' % (account)
    db_init(dbpath)
    db_insert(dbpath,'tx1','path2','type3','method4','tenant5','url6','time7','','')
    db_insert(dbpath,'tx2','path5','type7','method4','tenant5','url6','time7','','')
    print 'insert'
    print db_values(dbpath)
    
    db_update(dbpath,'status3','comment3','tx1')
    print 'update'
    print db_values(dbpath)
    
    db_delete(dbpath)
    print 'delete'
    print db_values(dbpath)

def tasks_main():
    account = 'zhu__feng006'
    dbpath = '/mnt/cloudfs-object/%s.db' % (account)
    task_db_init(dbpath)
    task_db_insert(dbpath,'tx1','time7','','')
    task_db_insert(dbpath,'tx2','time7','','')
    print 'insert'
    print task_db_values(dbpath,'tx1')
    
    task_db_update(dbpath,'status3','comment3','tx1')
    print 'update'
    print task_db_values(dbpath,'tx1')
    
    task_db_delete(dbpath,'tx1')
    print 'delete'
    print task_db_values(dbpath,'tx1')

if __name__ == '__main__':
    ## operations_main() ##
    tasks_main()
