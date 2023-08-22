import socket
import time
import gzip

s = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
s.connect(('10.0.0.2', 8080))

with open('./enwik8', 'rb') as f:
  content = f.read()
  # start = time.time()
  # s.send(content)
  # end = time.time()
  # print(start, end)

  for i in range(0,2):
    start = time.time()
    data = gzip.compress(content, i)
    mid = time.time()
    s.send(data)
    end = time.time()
    print(start, mid, end)
    # time.sleep(2)
