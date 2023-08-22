from bcc import BPF
import ctypes
import time
import os
import socket

code="""
struct path {
  u32 hops[16];
  u32 size;
};
BPF_TABLE_PINNED("hash", u32, u32, pids, 10240, "/sys/fs/bpf/pids11");
BPF_TABLE_PINNED("hash", unsigned long, struct path, ino2upath, 10240, "/sys/fs/bpf/ino2upath");
"""
bpf = BPF(text=code)
pids = bpf["pids"]
ino2upath = bpf["ino2upath"]


pid = os.getpid()

# set pid to pids map to enable bpf
def write_pid():
  print(os.getpid())
  keys = [pid]
  vals = [0]
  pids.items_update_batch((ctypes.c_uint32 * len(keys))(*keys), (ctypes.c_uint32 * len(vals))(*vals))

class Path(ctypes.Structure):
  _fields_ = [("hops", ctypes.c_uint32 * 16), ("size", ctypes.c_uint32)]


def write_route(ino, route=None):
  ori_len = len(route)
  route.extend(range(16 - len(route)))
  v = Path((ctypes.c_uint32 * 16)(*route), ori_len)
  keys = [ino]
  vals = [v]
  ino2upath.items_update_batch((ctypes.c_uint64 * len(keys))(*keys), (Path * len(vals))(*vals))

def get_ino_from_sock(sock):
  str = os.readlink("/proc/%d/fd/%d" % (pid, sock.fileno()))
  ino = int(str.split('[')[1].split(']')[0])
  print(ino)
  return ino

def set_route(sock, route):
  ino = get_ino_from_sock(sock)
  write_route(ino, route())

def socky(family=socket.AF_INET, type=socket.SOCK_STREAM, route=None):
  write_pid()
  sock = socket.socket(family, type)
  ino = get_ino_from_sock(sock)
  assert(callable(route))
  r = route()
  write_route(ino, r)
  return sock
