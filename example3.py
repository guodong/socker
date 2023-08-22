import libsocky as socky
import threading
import socket

user = 'guest'

def fn():
  if user == 'admin':
    return [3, 2]
  else:
    return [3, 2, 3]

def fa(): # can use fn state
  user = 'admin'
  s = socky.socky(family=socket.AF_INET, type=socket.SOCK_STREAM, route=route_compute)
  if result_of(fn) pass fw:
    s.connect((srv, 443))
  else:
    s.connect((srv, 80))

if __name__ == '__main__':
  request_as_user()
  # request_as_user('admin')