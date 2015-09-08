
import pickle

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

def write_meta(metapath, metadata):
    
    assert isinstance(metadata, dict)
    
    with open(metapath,'wb' ) as f:  
        pickle.dump (metadata , f )

def read_meta(metapath):

    metadata = {}
    with open(metapath,'rb') as f:
        metadata = pickle.load(f)

    return metadata

if __name__ == '__main1__':

    for x in ['///a','//a/bc/',' /a//bc//',' /a/bc', '///a']:
        print path_std(x)+'  '+ parent_path(x) + ' '+parent_path(x)

if __name__ == '__main__':

    write_meta('./meta',{'a':1,'b':'c'})
    print read_meta('./meta')
