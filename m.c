#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/ptrace.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>

struct _path {

};

BPF_HASH(pid2sk, u32, struct sock *);
BPF_HASH(sk2fd, struct sock *, u32);
BPF_HASH(fd2path, u32, struct _path *);
BPF_HASH(hash2f, u32, u32);


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
  sk2fd.update(s, &fd);
  if (fd < 10)
    bpf_trace_printk("trace_tcp4connect %d %d %d\\n", fd, fd, fd);

  return 0;
}

int kprobe__tcp_connect(struct pt_regs *ctx, struct sock *sk) {

  int *fd = sk2fd.lookup((&sk));
  if (fd == 0) {
    bpf_trace_printk("trace_tcp4connect %d %d %d\\n", 222, 222, 222);
    return 0;
  }
  u32 hash = bpf_ntohs(sk->__sk_common.skc_num) + bpf_ntohs(sk->__sk_common.skc_dport);
  hash = sk->__sk_common.skc_num;
  hash2f.update(&hash, fd);
  bpf_trace_printk("trace_tcp4connect %d %d %d\\n", 22, 22, 22);
  return 0;
}

int push_vlan(struct __sk_buff *skb) {
  __u8 proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
  if (proto != IPPROTO_TCP) {
    return 1;
  }
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

  u32 hash = tcp->src_port;
  
  int *fd = hash2f.lookup(&hash);
  if (fd == 0) {
    bpf_trace_printk("trace_tcp4connect %d %d %d\\n", 222, 222, 222);
    return 1;
  }
  if (tcp->dst_port == 80) {
    bpf_skb_vlan_push(skb, bpf_htons(ETH_P_8021Q), 100);
    bpf_skb_vlan_push(skb, bpf_htons(ETH_P_8021Q), 100);
    u64 cookie = bpf_get_socket_cookie(skb);
    bpf_trace_printk("trace_tcp4connect %x\\n", skb);
  }

  return 1;

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