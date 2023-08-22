#include <bcc/proto.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>

#define IP_TCP 	6
#define ETH_HLEN 14
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define TCP_SPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))
#define TCP_DPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))

static struct bpf_sock_tuple *get_tuple(void *data, __u64 nh_off,
					void *data_end, __u16 eth_proto,
					bool *ipv4)
{
	struct bpf_sock_tuple *result;
	__u8 proto = 0;
	__u64 ihl_len;

	if (eth_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = (struct iphdr *)(data + nh_off);

		if (iph + 1 > data_end)
			return NULL;
		ihl_len = iph->ihl * 4;
		proto = iph->protocol;
		*ipv4 = true;
		result = (struct bpf_sock_tuple *)&iph->saddr;
	} 

	if (data + nh_off + ihl_len > data_end || proto != IPPROTO_TCP)
		return NULL;

	return result;
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

  // void *data = (void *)(long)skb->data;
  // void *data_end = (void *)(long)skb->data_end;
  // struct ethhdr *eth = (struct ethhdr *)(data);
  // bool ipv4;
  // struct bpf_sock_tuple *tuple = get_tuple(data, sizeof(*eth), data_end, eth->h_proto, &ipv4);
  // size_t tuple_len = sizeof(*tuple);
  // struct bpf_sock_tuple tuple1 = {};
  // struct bpf_sock *sk = bpf_sk_lookup_tcp(skb, &tuple1, sizeof(tuple1), BPF_F_CURRENT_NETNS, 0);

  // struct sock *sk = __inet_lookup_skb(&tcp_hashinfo, skb, tcp->src_port, tcp->dst_port);
  if (tcp->dst_port == 80) {
    bpf_skb_vlan_push(skb, bpf_htons(ETH_P_8021Q), 100);
    u64 cookie = bpf_get_socket_cookie(skb);
    bpf_trace_printk("trace_tcp4connect %x\\n", skb);
    // bpf_skb_vlan_pop(skb);
    // __u16 dp = bpf_htons(8080);
    // __u16 old_port = (load_half(skb, TCP_DPORT_OFF));
    // // bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_port, dp, sizeof(dp));
    // bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_port, dp, sizeof(dp));
    // bpf_skb_store_bytes(skb, TCP_DPORT_OFF, &dp, sizeof(dp), 0);
  }
  // if (tcp->src_port == 8080) {
  //   __u16 dp = (80);
  //   __u16 old_port = htons(load_half(skb, TCP_SPORT_OFF));
  //   bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_port, dp, sizeof(dp));
  //   bpf_skb_store_bytes(skb, TCP_SPORT_OFF, &dp, sizeof(dp), 0);
  // }

  return 1;

  // u64 src_mac = ethernet->src;
	// struct sock *skp = *skpp;
	// u32 saddr = 0, daddr = 0;
	// u16 dport = 0, sport = 0;
	// bpf_probe_read(&saddr, sizeof(saddr), &skp->__sk_common.skc_rcv_saddr);
	// bpf_probe_read(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
	// bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);
	// bpf_probe_read(&sport, sizeof(sport), &skp->__sk_common.skc_num);
	// // output
	// bpf_trace_printk("trace_tcp4connect %x %x %d\\n", saddr, daddr, (sport));

}