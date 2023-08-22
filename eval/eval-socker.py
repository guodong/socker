import socket
import time
import gzip
import libsocky as socker

def NF():
  return [3, 2, 3]

s = socker.socky(route=NF)
s.connect(('10.0.0.2', 8080))

with open('./enwik8', 'rb') as f:
  content = f.read()
  start = time.time()
  content = bytearray(content)
  print(len(content))
  for i in range(100000):
    s.send(content[i * 1000: (i+1) * 1000])
    time.sleep(1)
  end = time.time()
  print(start, end)

  for i in range(1, 10):
    start = time.time()
    data = gzip.compress(content, i)
    mid = time.time()
    s.send(data)
    end = time.time()
    print(start, mid, end)
    time.sleep(2)
