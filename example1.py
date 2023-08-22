import libsocky as socky
import threading
import socket

user = 'guest'
user = 'admin'

def route_compute():
  if user == 'admin':
    return [3, 2]
  else:
    return [3, 2, 3]

def request_as_user():
  s = socky.socky(family=socket.AF_INET, type=socket.SOCK_STREAM, route=route_compute)
  s.connect(('10.0.0.2', 80))
  s.sendall(b'Hello')
  data = s.recv(1024)
  print(repr(data))

if __name__ == '__main__':
  request_as_user()
  # request_as_user('admin')