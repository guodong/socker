#!/usr/bin/python
#
# tcpv4connect	Trace TCP IPv4 connect()s.
#		For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpv4connect [-h] [-t] [-p PID]
#
# This is provided as a basic example of TCP connection & socket tracing.
#
# All IPv4 connection attempts are traced, even if they ultimately fail.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Oct-2015	Brendan Gregg	Created this.

from __future__ import print_function
from bcc import BPF
from pyroute2 import IPRoute

ipr = IPRoute()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/ptrace.h>


BPF_HASH(currsock, u32, struct sock *);
BPF_HASH(pid2sk, u32, struct sock *);
BPF_HASH(pid2fd, u32, u32);
BPF_HASH(stof, struct sock *, u32);


//int kprobe__tcp_connect(struct pt_regs *ctx, struct sock *sk)
/*int kprobe__sys_socket(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();
	// stash the sock ptr for lookup on return
	currsock.update(&pid, &sk);
	u32 saddr = 0, daddr = 0;
	u16 dport = 0, sport = 0;
  struct sock *skp = sk;
	bpf_probe_read(&saddr, sizeof(saddr), &skp->__sk_common.skc_rcv_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
	bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);
	bpf_probe_read(&sport, sizeof(sport), &skp->__sk_common.skc_num);
	// output
	bpf_trace_printk("trace_tcp4connect %s %x %x\\n", skp->sk_socket->file->f_path.dentry->d_name.name, daddr, (skp->sk_socket->file->f_inode->i_ino));
	return 0;
};*/


int kprobe__sock_alloc_file(struct pt_regs *ctx, struct socket *sk) {
  u32 pid = bpf_get_current_pid_tgid();
  struct sock *s = sk->sk;
  pid2sk.update(&pid, &s);
  return 0;
}

int kretprobe__sys_socket(struct pt_regs *ctx) {
  int fd = PT_REGS_RC(ctx);
  u32 pid = bpf_get_current_pid_tgid();
  struct sock **s = pid2sk.lookup(&pid);
  if (s == 0) {
    return 0;
  }
  //currsock.update(&fd, s);
  stof.update(s, &fd);
  if (fd < 10)
    bpf_trace_printk("trace_tcp4connect %d %d %d\\n", fd, fd, fd);

  return 0;
}

int kprobe__tcp_connect(struct pt_regs *ctx, struct sock *sk) {
  int *fd = stof.lookup((&sk));
  if (fd == 0) {
    bpf_trace_printk("trace_tcp4connect %d %d %d\\n", 222, 222, 222);
    return 0;
  }
  bpf_trace_printk("trace_tcp4connect %d %d %d\\n", 22, 22, 22);
  return 0;
}

// get sock fd, the fd is associated with user space sock fd
/*int kretprobe__sys_socket(struct pt_regs *ctx) {
  int ret = PT_REGS_RC(ctx);
  int err, fput_needed;
  //struct socket *sk = sockfd_lookup_light(ret, &err, &fput_needed);
  bpf_trace_printk("trace_tcp4connect %d %d %d\\n", ret, ret, ret);
  u32 pid = bpf_get_current_pid_tgid();
	// stash the sock ptr for lookup on return
	//currsock.update(&pid, &sk);
  return 0;
}

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	skpp = currsock.lookup(&pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}
	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		currsock.delete(&pid);
		return 0;
	}
	// pull in details
	struct sock *skp = *skpp;
	u32 saddr = 0, daddr = 0;
	u16 dport = 0, sport = 0;
	bpf_probe_read(&saddr, sizeof(saddr), &skp->__sk_common.skc_rcv_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
	bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);
	bpf_probe_read(&sport, sizeof(sport), &skp->__sk_common.skc_num);
	// output
	bpf_trace_printk("trace_tcp4connect %x %x %d\\n", saddr, daddr, (199));
	currsock.delete(&pid);
	return 0;
}*/
"""

# initialize BPF
b = BPF(src_file="m.c")
b.attach_kprobe(event="sock_alloc_file", fn_name="kprobe__sock_alloc_file")
b.attach_kretprobe(event="__sys_socket", fn_name="kretprobe__sys_socket")
b.attach_kprobe(event="tcp_connect", fn_name="kprobe__tcp_connect")

socky = b.load_func("push_vlan", BPF.SCHED_CLS)
ifindex = ipr.link_lookup(ifname="ens33")[0]
print(ifindex)
ipr.tc("add", "sfq", ifindex, "ffff:")
ipr.tc("add-filter", "bpf", ifindex, ":1", fd=socky.fd, name=socky.name, parent="ffff:", action="ok", classid=1)

# header
print("%-6s %-12s %-16s %-16s %-4s" % ("PID", "COMM", "SADDR", "DADDR",
    "DPORT"))

def inet_ntoa(addr):
	dq = ''
	for i in range(0, 4):
		dq = dq + str(addr & 0xff)
		if (i != 3):
			dq = dq + '.'
		addr = addr >> 8
	return dq

# filter and format output
while 1:
        # Read messages from kernel pipe
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            # (_tag, saddr_hs, daddr_hs, dport_s) = msg.split(" ")
        except ValueError:
            # Ignore messages from other tracers
            continue

        # Ignore messages from other tracers
        # if _tag != "trace_tcp4connect":
            # continue

	# print("%-6d %-12.12s %-16s %-16s %-4s %s" % (pid, task,
	#     saddr_hs,
	#     inet_ntoa(int(daddr_hs, 16)),
	#     dport_s, saddr_hs))