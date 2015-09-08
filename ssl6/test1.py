

import os
import sys

if __name__ == '__main__':
    cmd = 'rm -f /etc/pki/CA/index.txt; touch /etc/pki/CA/index.txt '
    os.system(cmd)
    cmd = 'openssl req -new -x509 -days 3650 -keyout ca.key -out ca.crt -extensions v3_req -subj "/C=CN/ST=BJ/L=hd/O=FW/OU=ff" -config /root/task/api/ssl6/openssl.cnf ' # % (sys.argv[1])
    os.system(cmd)
    cmd = 'openssl genrsa -out server.key 2048'
    os.system(cmd)
    cmd = 'openssl req -new -key server.key -out server.csr -subj "/C=CN/ST=BJ/L=hd/O=FW/OU=ff/CN=localhost" -config /root/task/api/ssl6/openssl.cnf'  # % (sys.argv[1])
    os.system(cmd)
    cmd = 'openssl ca -in server.csr -out server.crt -cert ca.crt -keyfile ca.key -config /root/task/api/ssl6/openssl.cnf'
    os.system(cmd)

