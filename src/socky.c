#include <bcc/proto.h>
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include "mpls.h"

#define MAXHOPS 16
#define TCP_PROTO 6
#define DEBUG

/*
 * The Internet Protocol (IP) is defined in RFC 791.
 * The RFC specifies the format of the IP header.
 * In the header there is the IHL (Internet Header Length) field which is 4bit
 * long
 * and specifies the header length in 32bit words.
 * The IHL field can hold values from 0 (Binary 0000) to 15 (Binary 1111).
 * 15 * 32bits = 480bits = 60 bytes
 */
#define MAX_IP_HDR_LEN 60

/**
 * Adjust room at the network layer
 * (room space is added or removed below the layer 3 header).
 * https://elixir.bootlin.com/linux/v5.3.6/source/include/uapi/linux/bpf.h#L1536
 */
#define BPF_ADJ_ROOM_NET 0

/* the set of pids of user processes, key: pid_tgid, value: enable socky or not */
// BPF_HASH(pids, u64, u32);
BPF_TABLE_PINNED("hash", u32, u32, pids, 10240, "/sys/fs/bpf/pids11");

/* internal port switching/SR structure, the realize of routing depends on adapter */
struct upath {
  u32 hops[MAXHOPS];
  u32 size;
};

/* user programs set the mapping from kernel socket inode to user defined path */
BPF_TABLE_PINNED("hash", unsigned long, struct upath, ino2upath, 10240, "/sys/fs/bpf/ino2upath");

/* the mapping from hash of 5 tuples to pfd */
BPF_HASH(hash2ino, u32, unsigned long);

/* kernel sock to socket inode */
BPF_HASH(sk2inode, struct sock *, unsigned long);

BPF_HASH(testmap, u32, u32);

/* Returns the process ID in the lower 32 bits (kernel's view of the PID,
 which in user space is usually presented as the thread ID), and the thread
group ID in the upper 32 bits (what user space often thinks of as the PID). */
inline static int check_pid() {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

#ifdef DEBUG
  u32 i = 1;
  testmap.update(&pid, &i);
#endif

  if (pids.lookup(&pid) == 0) {
    return 0;
  }
  return 1;
}

struct tuple {
  u8 protocal;
  u32 src_ip;
  u32 dst_ip;
  u16 src_port;
  u16 dst_port;
};

/* simple hash need to consider conflict */
inline static u32 simple_hash(struct tuple *tuple) {
  return tuple->protocal ^ tuple->src_ip ^ tuple->dst_ip ^ tuple->src_port ^ tuple->dst_port;
}

/* get socket inode and map to kernel sock */
int kprobe__sock_alloc_file(struct pt_regs *ctx, struct socket *sock) {
  if (check_pid() == 0) {
    return 0;
  }
  struct inode *inode = SOCK_INODE(sock);
  struct sock *sk = sock->sk;
  unsigned long ino = inode->i_ino;
  sk2inode.update(&sk, &ino);
  return 0;
}

/* kernel tcp_connect assigns local port on socket */
int kprobe__tcp_connect(struct pt_regs *ctx, struct sock *sk) {
  if (check_pid() == 0) {
    return 0;
  }
  
  unsigned long *ino = sk2inode.lookup(&sk);
  if (ino == 0) {
    return 0;
  }

#ifdef DEBUG
  u32 i = 0;
  u32 v = sk->__sk_common.skc_num;
  testmap.update(&i, &v);
#endif
  
  u32 hash = TCP_PROTO << 16 | sk->__sk_common.skc_num;

  hash2ino.update(&hash, ino);
  
  return 0;
}

#ifdef MPLS
inline static int push_mpls(struct __sk_buff *skb, int label, bool bos) {
  /*
   * the redundant casts are needed according to the documentation.
   * possibly for the BPF verifier.
   * https://www.spinics.net/lists/xdp-newbies/msg00181.html
   */
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  // The packet starts with the ethernet header, so let's get that going:
  struct ethhdr *eth = (struct ethhdr *)(data);

  /*
   * Now, we can't just go "eth->h_proto", that's illegal.  We have to
   * explicitly test that such an access is in range and doesn't go
   * beyond "data_end" -- again for the verifier.
   * The eBPF verifier will see that "eth" holds a packet pointer,
   * and also that you have made sure that from "eth" to "eth + 1"
   * is inside the valid access range for the packet.
   */
  if ((void *)(eth + 1) > data_end) {
    return 1;
  }

  /*
   * We only care about IP packet frames. Don't do anything to other ethernet
   * packets like ARP.
   * hton -> host to network order. Network order is always big-endian.
   * pedantic: the protocol is also directly accessible from __sk_buf
   */
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return 1;
  }

  struct iphdr *iph = (struct iphdr *)(void *)(eth + 1);

  if ((void *)(iph + 1) > data_end) {
    return 1;
  }

  // multiply ip header by 4 (bytes) to get the number of bytes of the header.
  int iph_len = iph->ihl << 2;
  if (iph_len > MAX_IP_HDR_LEN) {
    return 1;
  }

  

  /*
   * This is the amount of padding we need to remove to be just left
   * with eth * iphdr.
   */
  int padlen = sizeof(struct mpls_hdr);

  /*
   * Grow or shrink the room for data in the packet associated to
   * skb by length and according to the selected mode.
   * BPF_ADJ_ROOM_NET: Adjust room at the network layer
   *  (room space is added or removed below the layer 3 header).
   */
  int ret = bpf_skb_adjust_room(skb, padlen, BPF_ADJ_ROOM_NET, 0);
  if (ret) {
    return 1;
  }

  // construct our deterministic mpls header
  struct mpls_hdr mpls = mpls_encode(label, 123, 0, bos);

  unsigned long offset = sizeof(struct ethhdr) + (unsigned long)iph_len;
  ret = bpf_skb_store_bytes(skb, (int)offset, &mpls, sizeof(struct mpls_hdr),
                            BPF_F_RECOMPUTE_CSUM);
  return 1;
}
#endif

int main_route(struct __sk_buff *skb) {
  /* tc cls ebpf doesn't support query pid
  if (check_pid() == 0) {
    return 1;
  }*/
  __u8 proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
  if (proto != IPPROTO_TCP) {
    return 1;
  }
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

  u32 hash = TCP_PROTO << 16 | tcp->src_port;
  
  unsigned long *ino = hash2ino.lookup(&hash);
  if (ino == 0) {
    return 1;
  }

  struct upath *p = ino2upath.lookup(ino);
  if (p == 0) {
    return 1;
  }

  /* here we push vlan as port switching, ebpf verifier will reject loop code if unrolling leads to #inst > 4k */
  for (size_t i = 0; i < MAXHOPS && i < p->size; i++) {
    bpf_skb_vlan_push(skb, bpf_htons(ETH_P_8021Q), p->hops[i]);
    // push_mpls(skb, p->hops[i], i == (p->size - 1));
  }

  return 1;
}


// int test() {
//   struct upath p;
//   p.size = 15;
//   for (size_t i = 0; i < 16; i++) {
//     p.hops[i] = i;
//   }
//   u32 id = 0;
//   i2p.update(&id, &p);
//   return 0;
// }
// int test2(struct pt_regs *ctx) {
//   u64 ptid = bpf_get_current_pid_tgid();
//   u32 pid = ptid;
//   u32 *r = pids.lookup(&pid);
//   if (r == 0) {
//     return 0;
//   }
//   struct socket *sock = PT_REGS_RC(ctx);
//   struct inode *inode = SOCK_INODE(sock);
//   u32 i = 0;
//   u64 v = inode->i_ino;
//   testmap.update(&i, &v);

//   return 0;
// }
// int test1() {
//   u32 id = 0;
//   struct upath *p = i2p.lookup(&id);
//   if (p == 0) {
//     return 0;
//   }
//   for (size_t i = 0; i < 16 && i < p->size; i++) {
//     u64 ii = i;
//     u32 v = p->hops[i] + 2;
//     pids.update(&ii, &v);
//     // if (i == p->size) {
//     //   break;
//     // }
//   }
//   return 0;
// }