package main

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/ipv4"
)

// NAT-PMP (RFC 6886), the protocol PCP replaced, still spoken by programs that know no PCP. It is
// IPv4 only. Its mapping requests are PCP's MAP in another form, so they are answered as one and
// share the mappings (RFC 6887 appendix A); the first octet, 0, tells them apart.
const (
	natpmpOpAddress = 0
	natpmpOpUDP     = 1
	natpmpOpTCP     = 2

	natpmpSuccess        = 0
	natpmpRefused        = 2
	natpmpNetworkFailure = 3
	natpmpNoResources    = 4
	natpmpUnsuppOpcode   = 5
)

// natpmp answers a NAT-PMP request from an IPv4 host; the caller holds mu.
func (p *pcpServer) natpmp(req []byte, src netip.Addr, now time.Time) []byte {
	op := req[1]
	reply := func(result uint16, n int) []byte {
		b := make([]byte, n)
		b[1] = 0x80 | op
		binary.BigEndian.PutUint16(b[2:], result)
		binary.BigEndian.PutUint32(b[4:], uint32(now.Sub(p.start)/time.Second))
		return b
	}
	switch op {
	case natpmpOpAddress:
		if !p.ipv4.IsValid() {
			return reply(natpmpNetworkFailure, 12)
		}
		b := reply(natpmpSuccess, 12)
		a := p.ipv4.As4()
		copy(b[8:], a[:])
		return b
	case natpmpOpUDP, natpmpOpTCP:
	default:
		return reply(natpmpUnsuppOpcode, 8)
	}
	if len(req) < 12 {
		return nil
	}
	proto := byte(pcpProtoUDP)
	if op == natpmpOpTCP {
		proto = pcpProtoTCP
	}
	internal, suggested, lifetime := binary.BigEndian.Uint16(req[4:6]), binary.BigEndian.Uint16(req[6:8]), binary.BigEndian.Uint32(req[8:12])
	b := reply(natpmpSuccess, 16)
	binary.BigEndian.PutUint16(b[8:], internal)
	refuse := func(result uint16, why string) []byte {
		debugf("[pcp] refused a NAT-PMP %s mapping of port %d from %s: %s", protoName(proto), internal, src, why)
		binary.BigEndian.PutUint16(b[2:], result)
		return b
	}
	if !p.ipv4.IsValid() {
		return refuse(natpmpNetworkFailure, "no IPv4 of a tunnel whose NAT is sixup's")
	}
	if internal == 0 {
		if lifetime != 0 {
			return refuse(natpmpRefused, "no internal port")
		}
		// Every mapping of the host for the protocol goes, as a host that took over the address
		// asks (RFC 6886 section 3.4)
		n := 0
		for k := range p.maps {
			if k.proto == proto && k.internal.Addr() == src {
				delete(p.maps, k)
				n++
			}
		}
		if n > 0 {
			p.push()
			infof("[pcp] %s released its %d %s mappings", src, n, protoName(proto))
		}
		return b
	}

	// The same request in PCP's words
	r := make([]byte, pcpHeaderLen+pcpMapLen)
	r[0], r[1] = pcpVersion, pcpOpMap
	binary.BigEndian.PutUint32(r[4:], lifetime)
	a := src.As16() // IPv4-mapped, as PCP carries it
	copy(r[8:24], a[:])
	data := r[pcpHeaderLen:]
	data[12] = proto
	binary.BigEndian.PutUint16(data[16:], internal)
	if lifetime != 0 {
		binary.BigEndian.PutUint16(data[18:], suggested)
		lifetime = min(max(lifetime, pcpMinLifetime), pcpMaxLifetime)
	}
	out := p.mapping4(r, data, src, proto, internal, lifetime, false, now)
	switch out[3] {
	case pcpSuccess:
	case pcpNotAuthorized:
		return refuse(natpmpRefused, "mapped already by PCP")
	case pcpNetworkFailure:
		return refuse(natpmpNetworkFailure, "no IPv4")
	default:
		return refuse(natpmpNoResources, pcpResultNames[out[3]])
	}
	if lifetime != 0 {
		copy(b[10:12], out[pcpHeaderLen+18:pcpHeaderLen+20])
		copy(b[12:16], out[4:8])
	}
	return b
}

// announceNATPMP tells the NAT-PMP clients of each LAN the external address, after a start or a
// change of it: ten times, the first gap 250 ms and doubling (RFC 6886 section 3.2.1).
func (p *pcpServer) announceNATPMP(ctx context.Context) {
	if p.c4 == nil {
		return
	}
	gap := 250 * time.Millisecond
	for range 10 {
		p.mu.Lock()
		msg := p.natpmp([]byte{0, natpmpOpAddress}, netip.Addr{}, time.Now())
		ok := p.ipv4.IsValid()
		p.mu.Unlock()
		if !ok {
			return
		}
		for _, name := range p.lans {
			ifi, err := net.InterfaceByName(name)
			if err != nil {
				continue
			}
			dst := &net.UDPAddr{IP: net.IPv4allsys, Port: pcpClientPort}
			if _, err := p.c4.WriteTo(msg, &ipv4.ControlMessage{IfIndex: ifi.Index}, dst); err != nil {
				debugf("[pcp] NAT-PMP announce on %s failed: %v", name, err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(gap):
		}
		gap *= 2
	}
}
