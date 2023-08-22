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
BPF_TABLE_PINNED("hash", u32, struct path, ino2upath, 10240, "/sys/fs/bpf/ino2upath");
"""
bpf = BPF(text=code)
pids = bpf["pids"]
i2p = bpf["i2p"]

pid = os.getpid()
print(pid)

keys = [pid]
vals = [0]
pids.items_update_batch((ctypes.c_uint32 * len(keys))(*keys), (ctypes.c_uint32 * len(vals))(*vals))

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print(client.fileno())
try:
  client.connect(('172.16.189.1', 80))
except:
  pass

while True:
  time.sleep(1)

# class path(ctypes.Structure):
#   _fields_ = [("hops", ctypes.c_uint32 * 16), ("size", ctypes.c_uint32)]

# keys = [0]
# t = range(100, 116)
# v = path((ctypes.c_uint32 * 16)(*t), 4)
# keys = [0]
# vals = [v]
# i2p.items_update_batch((ctypes.c_uint32 * len(keys))(*keys), (path * len(vals))(*vals))
# i = 0
# while True:
#   for k, v in i2p.items():
#     for i in range(16):
#       print("%d" % v.hops[i])
#   print("ok")
#   time.sleep(3)
# while True:
#   try:
#     keys = [i]
#     vals = [i]
#     pids.items_update_batch((ctypes.c_uint64 * len(keys))(*keys), (ctypes.c_uint32 * len(vals))(*vals))
#     time.sleep(1)
#   except KeyboardInterrupt:
#     break
#   i = i + 1