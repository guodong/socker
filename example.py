import libsocky as socky
import threading

def sp():
  return [3, 2]

def bp():
  return [3, 2, 3]

def route_by_user(user):
  if user == 'admin':
    s = socky.socky(route=sp)
  else:
    s = socky.socky(route=bp)
  s.connect(('10.0.0.2', 80))

if __name__ == '__main__':
  t1 = threading.Thread(target=route_by_user, args=('guest',))
  t1.start()
  t2 = threading.Thread(target=route_by_user, args=('admin',))
  t2.start()