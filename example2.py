

secure_reqs = ['login', 'register', 'pay']
ods.pub('secure_reqs', secure_reqs)

untrusted_nodes = ['s3']
path_secure = False

@sub('req', 'secure_reqs', 'topo')
def NF(req, secure_reqs, topo):
  if req in secure_reqs:
    path = bypassFWPath(topo)
  else:
    path = shortestPath(topo)
  ods.pub('path', path)
  return path
  
s = socker(nf=NF)
s.connect((SERVER, 80))

@sub('path')
def AF(path, data):
  if untrusted_nodes.intersect(path) == []:
    path_secure = True
  else:
    path_secure = False

def login(path, password):
  ods.pub('req', 'login')
  
  if path_secure == False:
    password = encrypt(password)
  s.send(password)
