from libsocky import ods, socky
import gzip

QOS_THRESHOLD = 8

compressLevel = 0
ods.set('mimeList', ['text/plain'])

def shortestPath(topo):
  return [2, 3]

def maxBWPath(topo):
  return [3, 2, 3]

def computeCL(fs, bw):
  return 5

@ods.reactor('mimeType', 'mimeList', 'topo')
def NF(mimeType, mimeList, topo):
  if mimeType in mimeList:
    path = maxBWPath(topo)
  else:
    path = shortestPath(topo)
  ods.pub('path', path)
  return path
  
@ods.reactor('path', 'filesize')
def updateCL(path, filesize):
  bw = path.getBW()
  if (filesize / bw) > QOS_THRESHOLD:
    compressLevel = computeCL(filesize, bw)
  else:
    compressLevel = 0

def file_upload(file):
  ods.set('filesize', getSize(file))
  ods.set('mimeType', getMime(file))
  s = socky.socky(nf=NF)
  s.connect((SERVER, PORT))
  if compressLevel > 0:
    file = gzip.compress(file, compressLevel)
  s.send(file)
  s.close()