import gzip, time

with open('./enwik8', 'rb') as f:
  content = f.read()

  for i in range(1,10):
    s = time.time()
    data = gzip.compress(content, i)
    e = time.time() - s
    print(len(data), e)