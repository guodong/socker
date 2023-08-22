from bcc import BPF, libbcc
import ctypes
import time
from pyroute2 import IPRoute

ipr = IPRoute()

bpf = BPF(src_file="socky.c")

# bpf.attach_kprobe(event="__sys_socket", fn_name="test")
# bpf.attach_kprobe(event="tcp_v4_connect", fn_name="test2")
bpf.attach_kretprobe(event="sock_alloc_file", fn_name="kprobe__sock_alloc_file")
bpf.attach_kprobe(event="tcp_connect", fn_name="kprobe__tcp_connect")
pids = bpf["pids"]
# ret = libbcc.lib.bpf_obj_pin(pids.map_fd, ctypes.c_char_p("/sys/fs/bpf/pids"))
# if ret != 0:
#   raise Exception("Failed to pinning object")

socky = bpf.load_func("main_route", BPF.SCHED_CLS)
# ifindex = ipr.link_lookup(ifname="ens33")[0]
ifindex = ipr.link_lookup(ifname="h1-eth0")[0]
print(ifindex)
ipr.tc("add", "sfq", ifindex, "ffff:")
ipr.tc("add-filter", "bpf", ifindex, ":1", fd=socky.fd, name=socky.name, parent="ffff:", action="ok", classid=1)

while True:
  for k, v in bpf["testmap"].items():
    print("%10d %d" % (k.value, v.value))
  print("o")
  for k, v in bpf["ino2upath"].items():
    print(v.hops[0], v.hops[1], v.hops[2], v.hops[3], v.size)
    # print("%10d %d" % (k.value, v.value))
  print("ok")
  time.sleep(3)