from bcc import BPF
import socket

def socketx():
  bpf = BPF(src_file="myprog.c", debug=0)
  eBPFprog = bpf.load_func("http_filter", BPF.SOCKET_FILTER)
  BPF.attach_raw_socket(eBPFprog, "ens33")
  socket_fd = eBPFprog.sock
  sock = socket.fromfd(socket_fd, socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
  sock.setblocking(True)
  return sock

def control():
  pass

def test():
  s = socket.socket()
  socky.bind(s, control)

