
from swift.common.utils import split_path

def check_path_parts(path_parts):
    
    ftype = path_parts.get('ftype')
    op = path_parts.get('op')
    if 'd' == ftype:
        if path_parts.get('op') not in ['MKDIRS','DELETE','MOVE','COPY','LIST','RENAME','RESET','LISTDIR']:
            return False
    
    if 'l' == ftype:
        if path_parts.get('op') not in ['CREATESYMLINK']:
            return False
        
    return True


def path_std(path):
    # //a/bc/ /a//bc// /a/bc -> /a/b/c
    # parent_path /a/b/c -> /a/b
    # base_path /a/b/c -> c
    
    ll = path.split('/')
    newll = []
    for x in ll:
        if x:
            newll.append(x)
    path = '/' + '/'.join(newll)
    return path

def parent_path(path):

    path = path_std(path)

    return path_std('/'+'/'.join(path.split('/')[:-1]))

def base_path(path):

    path=path_std(path)
    return path.split('/')[-1]

