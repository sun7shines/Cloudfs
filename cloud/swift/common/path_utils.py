
import os

def path_std(path):
    # //a/bc/ /a//bc// /a/bc -> /a/b/c
    # parent_path /a/b/c -> /a/b
    # base_path /a/b/c -> c
    
    ll = path.strip().split('/')
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

def GetPathSize(strPath):  
    
    if not os.path.exists(strPath):  
        return 0;  
  
    if os.path.isfile(strPath):  
        return os.path.getsize(strPath);  
  
    nTotalSize = 0;  
    for strRoot, lsDir, lsFiles in os.walk(strPath):  
        if 'ff89f933b2ca8df40' in strRoot:
            continue
        for strDir in lsDir:  
            nTotalSize = nTotalSize + GetPathSize(os.path.join(strRoot, strDir));  
  
        for strFile in lsFiles:  
            nTotalSize = nTotalSize + os.path.getsize(os.path.join(strRoot, strFile));  
  
    return nTotalSize;  

if __name__ == '__main__':

    for x in ['///a','//a/bc/',' /a//bc//',' /a/bc', '///a']:
        print path_std(x)+'  '+ parent_path(x) + ' '+parent_path(x)

