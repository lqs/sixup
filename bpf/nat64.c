// SPDX-License-Identifier: (MIT OR GPL-2.0)
//
// NAT64 on the tc egress of sixup-nat64. Each IPv6 source is given an IPv4 address of its own from
// a private pool, so no ports are touched: the stateful part of NAT64, the sharing of the line's
// IPv4 address, is left to conntrack and the source NAT on the way out, as for any other IPv4
// host behind the router. A translated packet is handed back to the same device's ingress and
// enters the stack as a new packet of the other family. Fragments reach the program as they were
// sent, or as conntrack's reassembly is cut again on the way out of the device, no larger than
// the pool route's MTU leaves room for.

#include "xlat.h"

#define PROBES 8 // pool slots tried for a new source before giving up

volatile const __u32 pool_base; // the first address of the pool, host order
volatile const __u32 pool_mask; // the pool's size less one, a power of two less one

// The two directions of the address mapping, kept in step; sixup removes the pairs conntrack has
// no flow for
struct map_def v4_of SEC("maps") = {BPF_MAP_TYPE_HASH, sizeof(struct in6_addr), sizeof(__be32), 65536};
struct map_def v6_of SEC("maps") = {BPF_MAP_TYPE_HASH, sizeof(__be32), sizeof(struct in6_addr), 65536};

static __always_inline __u32 hash6(const struct in6_addr *a)
{
	__u32 h = a->s6_addr32[0] * 0x9e3779b1;
	h = (h ^ a->s6_addr32[1]) * 0x85ebca6b;
	h = (h ^ a->s6_addr32[2]) * 0xc2b2ae35;
	h = (h ^ a->s6_addr32[3]) * 0x27d4eb2f;
	return h ^ (h >> 15);
}

static __always_inline int in_pool(__be32 a)
{
	return (bpf_ntohl(a) & ~pool_mask) == pool_base;
}

// map6to4 extracts what the NAT64 prefix carries, and numbers an IPv6 source from the pool,
// giving it a free address the first time it is seen.
static __always_inline int map6to4(const struct in6_addr *a, __be32 *out, int alloc)
{
	if (in_pref64(a)) {
		*out = extract4(a);
		return 0;
	}
	__be32 *v = bpf_map_lookup_elem(&v4_of, a);
	if (v) {
		*out = *v;
		return 0;
	}
	if (!alloc)
		return STAT_DROP_NOMAP;
	__u32 h = hash6(a);
#pragma unroll
	for (int i = 0; i < PROBES; i++) {
		__be32 p = bpf_htonl(pool_base + ((h + i) & pool_mask));
		if (bpf_map_update_elem(&v6_of, &p, a, BPF_NOEXIST))
			continue;
		if (!bpf_map_update_elem(&v4_of, a, &p, BPF_NOEXIST)) {
			*out = p;
			return 0;
		}
		// Another CPU mapped the same source meanwhile
		bpf_map_delete_elem(&v6_of, &p);
		v = bpf_map_lookup_elem(&v4_of, a);
		if (!v)
			return STAT_DROP_POOL;
		*out = *v;
		return 0;
	}
	return STAT_DROP_POOL;
}

// map4to6 finds the source a pool address stands for, and embeds any other address in the prefix.
static __always_inline int map4to6(__be32 a, struct in6_addr *out)
{
	if (!in_pool(a)) {
		embed4(out, a);
		return 0;
	}
	struct in6_addr *v = bpf_map_lookup_elem(&v6_of, &a);
	if (!v)
		return STAT_DROP_NOMAP;
	*out = *v;
	return 0;
}

// The device's own MLD and router solicitations are no one's loss, and nothing but the pool's
// should come its way
static __always_inline int skip6(struct __sk_buff *skb, const struct ipv6hdr *ip6)
{
	return in_pref64(&ip6->daddr) ? XLAT : TC_ACT_SHOT;
}

static __always_inline int skip4(struct __sk_buff *skb, const struct iphdr *ip)
{
	return in_pool(ip->daddr) ? XLAT : TC_ACT_SHOT;
}

static __always_inline int deliver(struct __sk_buff *skb, int to6)
{
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

SEC("tc")
int nat64(struct __sk_buff *skb)
{
	// What sixup's slow path translated comes in like what the program translates
	if (skb->mark == slow_mark) {
		skb->mark = 0;
		return deliver(skb, skb->protocol == bpf_htons(ETH_P_IPV6));
	}
	if (skb->protocol == bpf_htons(ETH_P_IPV6))
		return six_to_four(skb);
	if (skb->protocol == bpf_htons(ETH_P_IP))
		return four_to_six(skb);
	return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
