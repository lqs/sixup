// SPDX-License-Identifier: (MIT OR GPL-2.0)
//
// A stateless IPv6/IPv4 translator (RFC 7915) on the tc egress of sixup-nat64. Each IPv6 source is
// given an IPv4 address of its own from a private pool, so no ports are touched: the stateful part
// of NAT64, the sharing of the line's IPv4 address, is left to conntrack and the source NAT on the
// way out, as for any other IPv4 host behind the router. A translated packet is handed back to
// the same device's ingress and enters the stack as a new packet of the other family.
//
// TCP, UDP and ICMP are translated, ICMP errors with the packet they quote, and fragments one by
// one. Fragments reach the program as they were sent, or as conntrack's reassembly is cut again
// on the way out of the device, no larger than the pool route's MTU leaves room for. Two kinds
// need the whole datagram for their new checksum and go to sixup instead, through the perf buffer
// slow: fragmented ICMP, whose IPv6 checksum covers a length no single fragment shows, and IPv4
// UDP without a checksum, which IPv6 requires. sixup sends them back translated through the same
// device, marked, and the program hands them to its ingress like the rest. Dropped and counted: IPv4 options, IPv6 extension
// headers other than a fragment header, and ICMP messages RFC 7915 does not translate.
//
// No packet reaches the program with CHECKSUM_COMPLETE: forwarding turns it into CHECKSUM_NONE
// (skb_forward_csum), and the router's own packets are never received ones. So only the checksum
// fields themselves are kept right, and with BPF_F_PSEUDO_HDR for CHECKSUM_PARTIAL.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define IP_MF 0x2000
#define IP_DF 0x4000
#define IP_OFFSET 0x1fff

#define IPV6_MIN_MTU 1280
#define IPV4_MIN_MTU 68

#define PROBES 8 // pool slots tried for a new source before giving up

// Set by the loader
volatile const __u32 pool_base; // the first address of the pool, host order
volatile const __u32 pool_mask; // the pool's size less one, a power of two less one
volatile const __u8 pref6[16]; // the NAT64 prefix, its host bits zero
volatile const __u8 mask6[16]; // ones over the prefix's length
volatile const __u8 v4pos[4];  // where RFC 6052 puts the bytes of an IPv4 address after it
volatile const __u32 slow_mark; // marks the packets sixup sends back translated

enum {
	STAT_OUT,        // IPv6 translated to IPv4
	STAT_IN,         // IPv4 translated to IPv6
	STAT_DROP_PROTO, // not TCP, UDP or ICMP, or with IPv4 options or IPv6 extension headers
	STAT_SLOW,       // handed to sixup whole
	STAT_DROP_ICMP,  // an ICMP message RFC 7915 does not translate, or one too short to
	STAT_DROP_POOL,  // no free pool address for a new source
	STAT_DROP_NOMAP, // for a pool address no source has, or quoting one
	STAT_DROP_ERR,   // a helper failed
	STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

// The two directions of the address mapping, kept in step; sixup removes the pairs conntrack has
// no flow for
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct in6_addr);
	__type(value, __be32);
} v4_of SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __be32);
	__type(value, struct in6_addr);
} v6_of SEC(".maps");

// The packets handed to sixup, each after its length
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} slow SEC(".maps");

// The IPv4 UDP datagrams without a checksum whose first fragment went to sixup, so that the rest
// follows it there: the kernel cuts a reassembled datagram again first fragment first
struct frag4 {
	__be32 saddr;
	__be32 daddr;
	__be16 id;
	__u16 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct frag4);
	__type(value, __u8);
} slow_frags SEC(".maps");

// The IPv6 pseudo-header, which the ICMPv6 checksum covers and the ICMP one does not
struct pseudo6 {
	struct in6_addr saddr;
	struct in6_addr daddr;
	__be32 len;
	__be32 nexthdr;
};

struct frag6 {
	__u8 nexthdr;
	__u8 reserved;
	__be16 frag_off; // offset in 8-byte units << 3, then two reserved bits and M
	__be32 id;
};

// The fixed eight bytes of an ICMP or ICMPv6 header
union icmp8 {
	__u8 b[8];
	__be16 h[4];
	__be32 w[2];
};

// What an ICMP error quotes, header and all, as the checksum difference sees it
struct quote4 {
	union icmp8 icmp;
	struct iphdr ip;
	__u8 l4[8];
};

// A quoted IPv6 packet may carry a fragment header; without one, the eight bytes after the IPv6
// header sit where it would, and the quote is 56 bytes long instead of 64
struct quote6 {
	union icmp8 icmp;
	struct ipv6hdr ip;
	struct frag6 fh;
	__u8 l4[8];
};

static __always_inline int count(__u32 stat, int verdict)
{
	__u64 *n = bpf_map_lookup_elem(&stats, &stat);
	if (n)
		*n += 1;
	return verdict;
}

// to_slow hands the packet to sixup, Ethernet header and all, and takes it from the stack. It is
// stolen rather than shot: a drop would fail the transmission, and the kernel cutting a datagram
// into fragments gives up on the rest at the first failure.
static __always_inline int to_slow(struct __sk_buff *skb)
{
	__u32 len = skb->len;
	if (bpf_perf_event_output(skb, &slow, BPF_F_CURRENT_CPU | (__u64)len << 32, &len, sizeof(len)))
		return count(STAT_DROP_ERR, TC_ACT_SHOT);
	return count(STAT_SLOW, TC_ACT_STOLEN);
}

static __always_inline __u16 ip_checksum(const struct iphdr *ip)
{
	const __u16 *w = (const __u16 *)ip;
	__u32 sum = 0;
#pragma unroll
	for (int i = 0; i < (int)sizeof(*ip) / 2; i++)
		sum += w[i];
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

static __always_inline __u32 hash6(const struct in6_addr *a)
{
	__u32 h = a->s6_addr32[0] * 0x9e3779b1;
	h = (h ^ a->s6_addr32[1]) * 0x85ebca6b;
	h = (h ^ a->s6_addr32[2]) * 0xc2b2ae35;
	h = (h ^ a->s6_addr32[3]) * 0x27d4eb2f;
	return h ^ (h >> 15);
}

static __always_inline int in_pref64(const struct in6_addr *a)
{
#pragma unroll
	for (int i = 0; i < 16; i++)
		if ((a->s6_addr[i] & mask6[i]) != pref6[i])
			return 0;
	return 1;
}

// embed4 is the IPv6 address of an IPv4 one behind the NAT64 prefix (RFC 6052 section 2.2).
static __always_inline void embed4(struct in6_addr *a, __be32 v4)
{
	const __u8 *b = (const __u8 *)&v4;
#pragma unroll
	for (int i = 0; i < 16; i++)
		a->s6_addr[i] = pref6[i];
#pragma unroll
	for (int i = 0; i < 4; i++)
		a->s6_addr[v4pos[i] & 15] = b[i];
}

// extract4 is the IPv4 address an address in the NAT64 prefix carries.
static __always_inline __be32 extract4(const struct in6_addr *a)
{
	__be32 v4;
	__u8 *b = (__u8 *)&v4;
#pragma unroll
	for (int i = 0; i < 4; i++)
		b[i] = a->s6_addr[v4pos[i] & 15];
	return v4;
}

// map4 finds the pool address of an IPv6 source, giving it a free one the first time it is seen.
static __always_inline int map4(const struct in6_addr *src, __be32 *out)
{
	__be32 *v = bpf_map_lookup_elem(&v4_of, src);
	if (v) {
		*out = *v;
		return 0;
	}
	__u32 h = hash6(src);
#pragma unroll
	for (int i = 0; i < PROBES; i++) {
		__be32 a = bpf_htonl(pool_base + ((h + i) & pool_mask));
		if (bpf_map_update_elem(&v6_of, &a, src, BPF_NOEXIST))
			continue;
		if (!bpf_map_update_elem(&v4_of, src, &a, BPF_NOEXIST)) {
			*out = a;
			return 0;
		}
		// Another CPU mapped the same source meanwhile
		bpf_map_delete_elem(&v6_of, &a);
		v = bpf_map_lookup_elem(&v4_of, src);
		if (!v)
			return -1;
		*out = *v;
		return 0;
	}
	return -1;
}

// l4_csum_offset is where the checksum sits in a TCP or UDP header.
static __always_inline int l4_csum_offset(__u8 proto)
{
	return proto == IPPROTO_TCP ? 16 : 6;
}

// The pointer of a Parameter Problem, from one header layout to the other (RFC 7915 figures 3 and 6)
static __always_inline int pointer_4to6(__u8 p)
{
	if (p <= 1)
		return p;
	if (p <= 3)
		return 4; // Total Length: Payload Length
	if (p == 8)
		return 7; // TTL: Hop Limit
	if (p == 9)
		return 6; // Protocol: Next Header
	if (p >= 12 && p <= 15)
		return 8;
	if (p >= 16 && p <= 19)
		return 24;
	return -1;
}

static __always_inline int pointer_6to4(__u32 p)
{
	if (p <= 1)
		return p;
	if (p == 4 || p == 5)
		return 2;
	if (p == 6)
		return 9;
	if (p == 7)
		return 8;
	if (p >= 8 && p <= 23)
		return 12;
	if (p >= 24 && p <= 39)
		return 16;
	return -1;
}

// icmp_6to4 turns an ICMPv6 header into its ICMP counterpart (RFC 7915 section 5.2). It returns 0
// for an echo, 1 for an error quoting a packet, and -1 for a message that is not translated.
static __always_inline int icmp_6to4(union icmp8 *h)
{
	__u8 code = h->b[1];
	__u32 v = bpf_ntohl(h->w[1]);
	int p;
	switch (h->b[0]) {
	case 128: // Echo Request
		h->b[0] = 8;
		return 0;
	case 129: // Echo Reply
		h->b[0] = 0;
		return 0;
	case 1: // Destination Unreachable
		h->b[0] = 3;
		switch (code) {
		case 0: // no route
		case 2: // beyond the scope of the source
		case 3: // address unreachable
			h->b[1] = 1;
			break;
		case 1: // administratively prohibited
			h->b[1] = 10;
			break;
		case 4: // port unreachable
			h->b[1] = 3;
			break;
		default:
			return -1;
		}
		h->w[1] = 0;
		return 1;
	case 2: // Packet Too Big: Fragmentation Needed, for the 20 bytes the IPv4 header saves
		if (v < IPV4_MIN_MTU + 20)
			v = IPV4_MIN_MTU + 20;
		v -= 20;
		if (v > 0xffff)
			v = 0xffff;
		h->b[0] = 3;
		h->b[1] = 4;
		h->w[1] = bpf_htonl(v);
		return 1;
	case 3: // Time Exceeded, the codes the same
		h->b[0] = 11;
		h->w[1] = 0;
		return 1;
	case 4: // Parameter Problem
		if (code == 1) { // unrecognised Next Header: Protocol Unreachable
			h->b[0] = 3;
			h->b[1] = 2;
			h->w[1] = 0;
			return 1;
		}
		if (code != 0)
			return -1;
		p = pointer_6to4(v);
		if (p < 0)
			return -1;
		h->b[0] = 12;
		h->w[1] = bpf_htonl((__u32)p << 24);
		return 1;
	}
	return -1;
}

// icmp_4to6 is the other way (RFC 7915 section 4.2).
static __always_inline int icmp_4to6(union icmp8 *h)
{
	__u8 code = h->b[1];
	__u32 v;
	int p;
	switch (h->b[0]) {
	case 8: // Echo Request
		h->b[0] = 128;
		return 0;
	case 0: // Echo Reply
		h->b[0] = 129;
		return 0;
	case 3: // Destination Unreachable
		switch (code) {
		case 0:  // net unreachable
		case 1:  // host unreachable
		case 5:  // source route failed
		case 6:  // destination network unknown
		case 7:  // destination host unknown
		case 8:  // source host isolated
		case 11: // network unreachable for the TOS
		case 12: // host unreachable for the TOS
			h->b[0] = 1;
			h->b[1] = 0;
			h->w[1] = 0;
			return 1;
		case 9:  // network administratively prohibited
		case 10: // host administratively prohibited
		case 13: // communication administratively prohibited
		case 15: // precedence cutoff in effect
			h->b[0] = 1;
			h->b[1] = 1;
			h->w[1] = 0;
			return 1;
		case 3: // port unreachable
			h->b[0] = 1;
			h->b[1] = 4;
			h->w[1] = 0;
			return 1;
		case 2: // protocol unreachable: Parameter Problem at the Next Header
			h->b[0] = 4;
			h->b[1] = 1;
			h->w[1] = bpf_htonl(6);
			return 1;
		case 4: // Fragmentation Needed: Packet Too Big, for the 20 bytes the IPv6 header adds
			v = bpf_ntohs(h->h[3]);
			v = v ? v + 20 : IPV6_MIN_MTU;
			if (v < IPV6_MIN_MTU)
				v = IPV6_MIN_MTU;
			h->b[0] = 2;
			h->b[1] = 0;
			h->w[1] = bpf_htonl(v);
			return 1;
		}
		return -1;
	case 11: // Time Exceeded, the codes the same
		h->b[0] = 3;
		h->w[1] = 0;
		return 1;
	case 12: // Parameter Problem
		if (code != 0 && code != 2)
			return -1;
		p = pointer_4to6(h->b[4]);
		if (p < 0)
			return -1;
		h->b[0] = 4;
		h->b[1] = 0;
		h->w[1] = bpf_htonl(p);
		return 1;
	}
	return -1;
}

// icmp6_to_4 translates an ICMPv6 message whose IPv4 header ip is ready but for its length and
// checksum. An error's quote is translated too, back the way the packet it quotes came: from the
// NAT64 prefix to an IPv6 source the pool has an address for. The quote grows or shrinks by the
// difference of the headers, and the checksum is moved by what changed.
static __always_inline int icmp6_to_4(struct __sk_buff *skb, const struct ipv6hdr *ip6, struct iphdr *ip, __u16 len)
{
	const __u32 at = ETH_HLEN + sizeof(*ip6);
	union icmp8 old, new;
	if (len < sizeof(old) || bpf_skb_load_bytes(skb, at, &old, sizeof(old)))
		return count(STAT_DROP_ICMP, TC_ACT_SHOT);
	__be16 csum = old.h[1];
	old.h[1] = 0;
	new = old;
	int r = icmp_6to4(&new);
	if (r < 0)
		return count(STAT_DROP_ICMP, TC_ACT_SHOT);
	struct pseudo6 ph = {
		.saddr = ip6->saddr,
		.daddr = ip6->daddr,
		.len = bpf_htonl(len),
		.nexthdr = bpf_htonl(IPPROTO_ICMPV6),
	};
	__s64 seed = bpf_csum_diff((__be32 *)&ph, sizeof(ph), NULL, 0, 0);
	ip->protocol = IPPROTO_ICMP;

	if (r == 0) {
		ip->check = ip_checksum(ip);
		__s64 diff = bpf_csum_diff(old.w, sizeof(old), new.w, sizeof(new), seed);
		new.h[1] = csum;
		if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0))
			return count(STAT_DROP_ERR, TC_ACT_SHOT);
		__be16 ethertype = bpf_htons(ETH_P_IP);
		if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto), &ethertype, sizeof(ethertype), 0) ||
		    bpf_skb_store_bytes(skb, ETH_HLEN, ip, sizeof(*ip), 0) ||
		    bpf_skb_store_bytes(skb, ETH_HLEN + sizeof(*ip), &new, sizeof(new), 0) ||
		    bpf_l4_csum_replace(skb, ETH_HLEN + sizeof(*ip) + 2, 0, diff, 0))
			return count(STAT_DROP_ERR, TC_ACT_SHOT);
		count(STAT_OUT, 0);
		return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
	}

	struct quote6 o;
	struct quote4 n = {};
	if (len < sizeof(o) - sizeof(o.l4) || bpf_skb_load_bytes(skb, at + sizeof(o.icmp), &o.ip, sizeof(o.ip) + sizeof(o.fh)))
		return count(STAT_DROP_ICMP, TC_ACT_SHOT);
	o.icmp = old;
	__u8 proto = o.ip.nexthdr;
	__u16 ipl = bpf_ntohs(o.ip.payload_len);
	int ifrag = proto == IPPROTO_FRAGMENT, first = 1;
	n.ip.frag_off = bpf_htons(IP_DF);
	if (ifrag) {
		if (len < sizeof(o) || ipl < sizeof(o.fh) || bpf_skb_load_bytes(skb, at + sizeof(o) - sizeof(o.l4), o.l4, sizeof(o.l4)))
			return count(STAT_DROP_ICMP, TC_ACT_SHOT);
		proto = o.fh.nexthdr;
		ipl -= sizeof(o.fh);
		__u16 fo = bpf_ntohs(o.fh.frag_off);
		first = fo >> 3 == 0;
		n.ip.frag_off = bpf_htons(fo >> 3 | (fo & 1) << 13);
		n.ip.id = bpf_htons(bpf_ntohl(o.fh.id));
		__builtin_memcpy(n.l4, o.l4, sizeof(n.l4));
	} else {
		__builtin_memcpy(n.l4, &o.fh, sizeof(n.l4));
	}
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_ICMPV6)
		return count(STAT_DROP_PROTO, TC_ACT_SHOT);
	if (!in_pref64(&o.ip.saddr))
		return count(STAT_DROP_ICMP, TC_ACT_SHOT);
	__be32 *dst = bpf_map_lookup_elem(&v4_of, &o.ip.daddr);
	if (!dst)
		return count(STAT_DROP_NOMAP, TC_ACT_SHOT);
	n.icmp = new;
	n.ip.version = 4;
	n.ip.ihl = 5;
	n.ip.tos = o.ip.priority << 4 | o.ip.flow_lbl[0] >> 4;
	n.ip.tot_len = bpf_htons(ipl + sizeof(struct iphdr));
	n.ip.ttl = o.ip.hop_limit;
	n.ip.protocol = proto == IPPROTO_ICMPV6 ? IPPROTO_ICMP : proto;
	n.ip.saddr = extract4(&o.ip.saddr);
	n.ip.daddr = *dst;
	n.ip.check = ip_checksum(&n.ip);
	// A quoted echo gets its own type; its checksum, like a quoted TCP or UDP one, is left alone
	if (first && proto == IPPROTO_ICMPV6 && (n.l4[0] == 128 || n.l4[0] == 129))
		n.l4[0] = n.l4[0] == 128 ? 8 : 0;
	__s64 diff = ifrag ? bpf_csum_diff((__be32 *)&o, sizeof(o), (__be32 *)&n, sizeof(n), seed)
			   : bpf_csum_diff((__be32 *)&o, sizeof(o) - sizeof(o.l4), (__be32 *)&n, sizeof(n), seed);
	n.icmp.h[1] = csum;

	// The message shrinks by what the header does, and by the fragment header if the quote has one
	int shrink = sizeof(struct ipv6hdr) - sizeof(struct iphdr) + (ifrag ? sizeof(struct frag6) : 0);
	ip->tot_len = bpf_htons(len + sizeof(struct iphdr) - shrink);
	ip->check = ip_checksum(ip);
	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0) || bpf_skb_adjust_room(skb, -shrink, BPF_ADJ_ROOM_NET, 0))
		return count(STAT_DROP_ERR, TC_ACT_SHOT);
	__be16 ethertype = bpf_htons(ETH_P_IP);
	if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto), &ethertype, sizeof(ethertype), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, ip, sizeof(*ip), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + sizeof(*ip), &n, sizeof(n), 0) ||
	    bpf_l4_csum_replace(skb, ETH_HLEN + sizeof(*ip) + 2, 0, diff, 0))
		return count(STAT_DROP_ERR, TC_ACT_SHOT);
	count(STAT_OUT, 0);
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

static __always_inline int six_to_four(struct __sk_buff *skb)
{
	struct ipv6hdr ip6;
	if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip6, sizeof(ip6)))
		return count(STAT_DROP_ERR, TC_ACT_SHOT);
	// The device's own MLD and router solicitations are no one's loss
	if (!in_pref64(&ip6.daddr))
		return TC_ACT_SHOT;
	__u8 proto = ip6.nexthdr;
	__u16 len = bpf_ntohs(ip6.payload_len);
	__be16 frag_off = bpf_htons(IP_DF), id = 0;
	int frag = 0, first = 1;
	if (proto == IPPROTO_FRAGMENT) {
		struct frag6 fh;
		if (len < sizeof(fh) || bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(ip6), &fh, sizeof(fh)))
			return count(STAT_DROP_ERR, TC_ACT_SHOT);
		proto = fh.nexthdr;
		if (proto == IPPROTO_ICMPV6)
			return to_slow(skb);
		len -= sizeof(fh);
		__u16 fo = bpf_ntohs(fh.frag_off);
		frag = 1;
		first = fo >> 3 == 0;
		frag_off = bpf_htons(fo >> 3 | (fo & 1) << 13); // DF clear: the pieces may be cut again
		id = bpf_htons(bpf_ntohl(fh.id));
	}
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_ICMPV6)
		return count(STAT_DROP_PROTO, TC_ACT_SHOT);
	if (len > 0xffff - sizeof(struct iphdr))
		return count(STAT_DROP_PROTO, TC_ACT_SHOT);

	__be32 saddr;
	if (map4(&ip6.saddr, &saddr))
		return count(STAT_DROP_POOL, TC_ACT_SHOT);
	struct iphdr ip = {
		.version = 4,
		.ihl = 5,
		.tos = ip6.priority << 4 | ip6.flow_lbl[0] >> 4,
		.tot_len = bpf_htons(len + sizeof(struct iphdr)),
		.id = id,
		.frag_off = frag_off,
		.ttl = ip6.hop_limit,
		.protocol = proto,
		.saddr = saddr,
		.daddr = extract4(&ip6.daddr),
	};
	if (proto == IPPROTO_ICMPV6)
		return icmp6_to_4(skb, &ip6, &ip, len);
	ip.check = ip_checksum(&ip);

	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0))
		return count(STAT_DROP_ERR, TC_ACT_SHOT);
	if (frag && bpf_skb_adjust_room(skb, -(int)sizeof(struct frag6), BPF_ADJ_ROOM_NET, 0))
		return count(STAT_DROP_ERR, TC_ACT_SHOT);
	__be16 ethertype = bpf_htons(ETH_P_IP);
	if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto), &ethertype, sizeof(ethertype), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, &ip, sizeof(ip), 0))
		return count(STAT_DROP_ERR, TC_ACT_SHOT);
	if (first) {
		// The pseudo-header keeps its length and protocol; only the addresses change
		__s64 diff = bpf_csum_diff((__be32 *)&ip6.saddr, 32, (__be32 *)&ip.saddr, 8, 0);
		__u64 flags = BPF_F_PSEUDO_HDR | (proto == IPPROTO_UDP ? BPF_F_MARK_MANGLED_0 : 0);
		if (bpf_l4_csum_replace(skb, ETH_HLEN + sizeof(ip) + l4_csum_offset(proto), 0, diff, flags))
			return count(STAT_DROP_ERR, TC_ACT_SHOT);
	}
	count(STAT_OUT, 0);
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

// icmp4_to_6 is icmp6_to_4 the other way: an error quotes a packet from a pool address to the
// NAT64 prefix.
static __always_inline int icmp4_to_6(struct __sk_buff *skb, const struct iphdr *ip, struct ipv6hdr *ip6, __u16 len)
{
	const __u32 at = ETH_HLEN + sizeof(*ip);
	union icmp8 old, new;
	if (len < sizeof(old) || bpf_skb_load_bytes(skb, at, &old, sizeof(old)))
		return count(STAT_DROP_ICMP, TC_ACT_SHOT);
	__be16 csum = old.h[1];
	old.h[1] = 0;
	new = old;
	int r = icmp_4to6(&new);
	if (r < 0)
		return count(STAT_DROP_ICMP, TC_ACT_SHOT);
	ip6->nexthdr = IPPROTO_ICMPV6;

	if (r == 0) {
		struct pseudo6 ph = {
			.saddr = ip6->saddr,
			.daddr = ip6->daddr,
			.len = bpf_htonl(len),
			.nexthdr = bpf_htonl(IPPROTO_ICMPV6),
		};
		__s64 seed = bpf_csum_diff(NULL, 0, (__be32 *)&ph, sizeof(ph), 0);
		__s64 diff = bpf_csum_diff(old.w, sizeof(old), new.w, sizeof(new), seed);
		new.h[1] = csum;
		if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IPV6), 0))
			return count(STAT_DROP_ERR, TC_ACT_SHOT);
		__be16 ethertype = bpf_htons(ETH_P_IPV6);
		if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto), &ethertype, sizeof(ethertype), 0) ||
		    bpf_skb_store_bytes(skb, ETH_HLEN, ip6, sizeof(*ip6), 0) ||
		    bpf_skb_store_bytes(skb, ETH_HLEN + sizeof(*ip6), &new, sizeof(new), 0) ||
		    bpf_l4_csum_replace(skb, ETH_HLEN + sizeof(*ip6) + 2, 0, diff, 0))
			return count(STAT_DROP_ERR, TC_ACT_SHOT);
		count(STAT_IN, 0);
		return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
	}

	struct quote4 o;
	struct quote6 n = {};
	if (len < sizeof(o) || bpf_skb_load_bytes(skb, at + sizeof(o.icmp), &o.ip, sizeof(o.ip) + sizeof(o.l4)))
		return count(STAT_DROP_ICMP, TC_ACT_SHOT);
	o.icmp = old;
	__u8 proto = o.ip.protocol;
	if (o.ip.ihl != 5 || (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_ICMP))
		return count(STAT_DROP_PROTO, TC_ACT_SHOT);
	struct in6_addr *src = bpf_map_lookup_elem(&v6_of, &o.ip.saddr);
	if (!src)
		return count(STAT_DROP_NOMAP, TC_ACT_SHOT);
	__u16 fo = bpf_ntohs(o.ip.frag_off);
	int ifrag = (fo & (IP_MF | IP_OFFSET)) != 0;
	__u8 nexthdr = proto == IPPROTO_ICMP ? IPPROTO_ICMPV6 : proto;
	n.icmp = new;
	n.ip.version = 6;
	n.ip.priority = o.ip.tos >> 4;
	n.ip.flow_lbl[0] = (o.ip.tos & 0xf) << 4;
	n.ip.payload_len = bpf_htons(bpf_ntohs(o.ip.tot_len) - sizeof(struct iphdr) + (ifrag ? sizeof(n.fh) : 0));
	n.ip.nexthdr = nexthdr;
	n.ip.hop_limit = o.ip.ttl;
	n.ip.saddr = *src;
	embed4(&n.ip.daddr, o.ip.daddr);
	__u8 *l4 = (__u8 *)&n.fh; // right after the IPv6 header, unless a fragment header comes first
	if (ifrag) {
		n.ip.nexthdr = IPPROTO_FRAGMENT;
		n.fh.nexthdr = nexthdr;
		n.fh.frag_off = bpf_htons((fo & IP_OFFSET) << 3 | !!(fo & IP_MF));
		n.fh.id = bpf_htonl(bpf_ntohs(o.ip.id));
		l4 = n.l4;
	}
	__builtin_memcpy(l4, o.l4, sizeof(o.l4));
	if (!(fo & IP_OFFSET) && proto == IPPROTO_ICMP && (l4[0] == 8 || l4[0] == 0))
		l4[0] = l4[0] == 8 ? 128 : 129;

	int grow = sizeof(struct ipv6hdr) - sizeof(struct iphdr) + (ifrag ? sizeof(struct frag6) : 0);
	len += grow;
	ip6->payload_len = bpf_htons(len);
	struct pseudo6 ph = {
		.saddr = ip6->saddr,
		.daddr = ip6->daddr,
		.len = bpf_htonl(len),
		.nexthdr = bpf_htonl(IPPROTO_ICMPV6),
	};
	__s64 seed = bpf_csum_diff(NULL, 0, (__be32 *)&ph, sizeof(ph), 0);
	__s64 diff = ifrag ? bpf_csum_diff((__be32 *)&o, sizeof(o), (__be32 *)&n, sizeof(n), seed)
			   : bpf_csum_diff((__be32 *)&o, sizeof(o), (__be32 *)&n, sizeof(n) - sizeof(n.l4), seed);
	n.icmp.h[1] = csum;

	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IPV6), 0) || bpf_skb_adjust_room(skb, grow, BPF_ADJ_ROOM_NET, 0))
		return count(STAT_DROP_ERR, TC_ACT_SHOT);
	__be16 ethertype = bpf_htons(ETH_P_IPV6);
	if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto), &ethertype, sizeof(ethertype), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, ip6, sizeof(*ip6), 0) ||
	    (ifrag ? bpf_skb_store_bytes(skb, ETH_HLEN + sizeof(*ip6), &n, sizeof(n), 0)
		   : bpf_skb_store_bytes(skb, ETH_HLEN + sizeof(*ip6), &n, sizeof(n) - sizeof(n.l4), 0)) ||
	    bpf_l4_csum_replace(skb, ETH_HLEN + sizeof(*ip6) + 2, 0, diff, 0))
		return count(STAT_DROP_ERR, TC_ACT_SHOT);
	count(STAT_IN, 0);
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

static __always_inline int four_to_six(struct __sk_buff *skb)
{
	struct iphdr ip;
	if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(ip)))
		return count(STAT_DROP_ERR, TC_ACT_SHOT);
	if ((bpf_ntohl(ip.daddr) & ~pool_mask) != pool_base)
		return TC_ACT_SHOT; // nothing of the pool's
	if (ip.ihl != 5)
		return count(STAT_DROP_PROTO, TC_ACT_SHOT);
	__u8 proto = ip.protocol;
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_ICMP)
		return count(STAT_DROP_PROTO, TC_ACT_SHOT);
	__u16 tot = bpf_ntohs(ip.tot_len);
	if (tot < sizeof(ip))
		return count(STAT_DROP_PROTO, TC_ACT_SHOT);
	__u16 len = tot - sizeof(ip);
	__u16 fo = bpf_ntohs(ip.frag_off);
	int frag = (fo & (IP_MF | IP_OFFSET)) != 0, first = (fo & IP_OFFSET) == 0;
	if (frag && proto == IPPROTO_ICMP)
		return to_slow(skb);
	if (proto == IPPROTO_UDP) {
		struct frag4 k = {.saddr = ip.saddr, .daddr = ip.daddr, .id = ip.id};
		if (first) {
			__be16 check;
			if (bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(ip) + 6, &check, sizeof(check)))
				return count(STAT_DROP_ERR, TC_ACT_SHOT);
			if (!check) {
				__u8 one = 1;
				if (frag)
					bpf_map_update_elem(&slow_frags, &k, &one, BPF_ANY);
				return to_slow(skb);
			}
		} else if (bpf_map_lookup_elem(&slow_frags, &k)) {
			return to_slow(skb);
		}
	}

	struct in6_addr *daddr = bpf_map_lookup_elem(&v6_of, &ip.daddr);
	if (!daddr)
		return count(STAT_DROP_NOMAP, TC_ACT_SHOT);
	struct ipv6hdr ip6 = {
		.version = 6,
		.priority = ip.tos >> 4,
		.flow_lbl = {(ip.tos & 0xf) << 4},
		.payload_len = bpf_htons(len),
		.nexthdr = proto,
		.hop_limit = ip.ttl,
		.daddr = *daddr,
	};
	embed4(&ip6.saddr, ip.saddr);
	if (proto == IPPROTO_ICMP)
		return icmp4_to_6(skb, &ip, &ip6, len);

	struct frag6 fh = {
		.nexthdr = proto,
		.frag_off = bpf_htons((fo & IP_OFFSET) << 3 | !!(fo & IP_MF)),
		.id = bpf_htonl(bpf_ntohs(ip.id)),
	};
	if (frag) {
		ip6.nexthdr = IPPROTO_FRAGMENT;
		ip6.payload_len = bpf_htons(len + sizeof(fh));
	}
	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IPV6), 0))
		return count(STAT_DROP_ERR, TC_ACT_SHOT);
	if (frag && bpf_skb_adjust_room(skb, sizeof(fh), BPF_ADJ_ROOM_NET, 0))
		return count(STAT_DROP_ERR, TC_ACT_SHOT);
	__be16 ethertype = bpf_htons(ETH_P_IPV6);
	if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto), &ethertype, sizeof(ethertype), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, &ip6, sizeof(ip6), 0))
		return count(STAT_DROP_ERR, TC_ACT_SHOT);
	__u32 l4 = ETH_HLEN + sizeof(ip6);
	if (frag) {
		if (bpf_skb_store_bytes(skb, l4, &fh, sizeof(fh), 0))
			return count(STAT_DROP_ERR, TC_ACT_SHOT);
		l4 += sizeof(fh);
	}
	if (first) {
		__s64 diff = bpf_csum_diff((__be32 *)&ip.saddr, 8, (__be32 *)&ip6.saddr, 32, 0);
		__u64 flags = BPF_F_PSEUDO_HDR | (proto == IPPROTO_UDP ? BPF_F_MARK_MANGLED_0 : 0);
		if (bpf_l4_csum_replace(skb, l4 + l4_csum_offset(proto), 0, diff, flags))
			return count(STAT_DROP_ERR, TC_ACT_SHOT);
	}
	count(STAT_IN, 0);
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

SEC("tc")
int nat64(struct __sk_buff *skb)
{
	// What sixup's slow path translated comes in like what the program translates
	if (skb->mark == slow_mark) {
		skb->mark = 0;
		return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
	}
	if (skb->protocol == bpf_htons(ETH_P_IPV6))
		return six_to_four(skb);
	if (skb->protocol == bpf_htons(ETH_P_IP))
		return four_to_six(skb);
	return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
