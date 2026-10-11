// SPDX-License-Identifier: (MIT OR GPL-2.0)
//
// A CLAT (RFC 6877) for this host's own IPv4, through the NAT64 of the line's PREF64. IPv4 leaves
// by the low-priority default route on the device sixup-clat, from 192.0.0.4, and the program on
// that device's egress translates it to IPv6 from the host's CLAT address and sends it out of the
// WAN, the kernel filling in the link layer. On the WAN's ingress the same program takes the IPv6
// from the NAT64 prefix to the CLAT address, translates it back and hands it to sixup-clat's
// ingress, where the host receives it, with the errors routers on the IPv6 path send the address.
// Everything else on the WAN passes untouched. The WAN is an Ethernet link.

#include "xlat.h"

volatile const __u8 clat6[16];      // the host's CLAT address
volatile const __be32 clat4;        // 192.0.0.4
volatile const __u32 clat_ifindex;  // sixup-clat
volatile const __u8 clat_mac[6];    // and its address, which what it receives has to be for
volatile const __u32 wan_ifindex;   // the WAN

static __always_inline int is_clat6(const struct in6_addr *a)
{
#pragma unroll
	for (int i = 0; i < 16; i++)
		if (a->s6_addr[i] != clat6[i])
			return 0;
	return 1;
}

// map6to4 extracts what the NAT64 prefix carries. Any other source is a router on the IPv6 path
// reporting an error, which becomes the IPv4 dummy address (RFC 7600).
static __always_inline int map6to4(const struct in6_addr *a, __be32 *out, int alloc)
{
	if (in_pref64(a))
		*out = extract4(a);
	else if (is_clat6(a))
		*out = clat4;
	else
		*out = bpf_htonl(0xc0000008); // 192.0.0.8
	return 0;
}

static __always_inline int map4to6(__be32 a, struct in6_addr *out)
{
	if (a != clat4) {
		embed4(out, a);
		return 0;
	}
#pragma unroll
	for (int i = 0; i < 16; i++)
		out->s6_addr[i] = clat6[i];
	return 0;
}

// On the WAN, the program's is what the NAT64 sends the CLAT address, and the errors any router on
// the way sends it; neighbour discovery and the rest of ICMPv6 for the address are the kernel's
static __always_inline int skip6(struct __sk_buff *skb, const struct ipv6hdr *ip6)
{
	if (!is_clat6(&ip6->daddr))
		return TC_ACT_OK;
	if (in_pref64(&ip6->saddr))
		return XLAT;
	__u8 type;
	if (ip6->nexthdr == IPPROTO_ICMPV6 && !bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(*ip6), &type, 1) && type < 128)
		return XLAT;
	return TC_ACT_OK;
}

// On sixup-clat, only what the host sends from 192.0.0.4; anything else has no way back
static __always_inline int skip4(struct __sk_buff *skb, const struct iphdr *ip)
{
	return ip->saddr == clat4 ? XLAT : TC_ACT_SHOT;
}

static __always_inline int deliver(struct __sk_buff *skb, int to6)
{
	if (to6)
		return bpf_redirect_neigh(wan_ifindex, NULL, 0, 0);
	// Received on the WAN, the frame is addressed to it, which sixup-clat would not take for its own
	if (bpf_skb_store_bytes(skb, 0, (const void *)clat_mac, sizeof(clat_mac), 0))
		return count(STAT_DROP_ERR, TC_ACT_SHOT);
	return bpf_redirect(clat_ifindex, BPF_F_INGRESS);
}

SEC("tc")
int clat(struct __sk_buff *skb)
{
	int v6 = skb->protocol == bpf_htons(ETH_P_IPV6);
	if (skb->ifindex == wan_ifindex)
		return v6 ? six_to_four(skb) : TC_ACT_OK;
	// sixup-clat's egress. What sixup's slow path translated goes on like what the program does
	if (skb->mark == slow_mark) {
		skb->mark = 0;
		return deliver(skb, v6);
	}
	if (skb->protocol == bpf_htons(ETH_P_IP))
		return four_to_six(skb);
	return TC_ACT_SHOT; // the device's own MLD and router solicitations
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
