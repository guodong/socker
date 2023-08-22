import gzip
import random
import string
import os

def get_str(N):
  return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))


def comp(buf):
  for i in range(1, 10):
    c = gzip.compress(buf, i)
    print(len(c))

with open('/Users/gd/Downloads/enwik8', 'rb') as f:
  d = f.read()
  print(len(d))
  comp(d)

buf = bytearray((1024*1024*10))

print(len(buf))

comp(buf)