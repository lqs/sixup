package main

import (
	"cmp"
	"context"
	"encoding/binary"
	"fmt"
	"maps"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// PCP (RFC 6887) lets a host ask the router to open an inbound path to one of its ports.
//
// Over IPv6 nothing is filtered here, so the router is what RFC 6887 calls a stateless device, a
// pure firewall that rewrites nothing: a MAP request is answered with the host's own address and
// port, which are already reachable, and no state is kept. Once a filter exists, the mappings will
// be its pinholes.
//
// Over IPv4 the router translates, and a MAP request gets a real mapping: an external port of the
// tunnel's IPv4, inside the line's port set on MAP-E, forwarded to the host. The mappings live in
// memory only; the ANNOUNCE sent at startup, and whenever the tunnel's address or port set
// changes, tells the clients to ask again.
const (
	pcpServerPort = 5351
	pcpClientPort = 5350
	pcpVersion    = 2
	pcpHeaderLen  = 24
	pcpMaxLen     = 1100
	pcpMapLen     = 36

	pcpOpAnnounce = 0
	pcpOpMap      = 1

	pcpOptPreferFailure = 2

	pcpMinLifetime = 120          // RFC 6887 section 15
	pcpMaxLifetime = 24 * 60 * 60 // ditto
	pcpShortError  = 30           // lifetime of an error that may clear soon
	pcpLongError   = 30 * 60      // and of one that will not
	pcpProtoTCP    = 6
	pcpProtoUDP    = 17

	pcpMaxPerHost  = 16   // mappings one host address may hold, IPv6 pinholes included
	pcpMinExternal = 1024 // lowest external IPv4 port handed out
)

// Result codes, section 7.4.
const (
	pcpSuccess               = 0
	pcpUnsuppVersion         = 1
	pcpNotAuthorized         = 2
	pcpMalformedRequest      = 3
	pcpUnsuppOpcode          = 4
	pcpUnsuppOption          = 5
	pcpMalformedOption       = 6
	pcpNetworkFailure        = 7
	pcpNoResources           = 8
	pcpUnsuppProtocol        = 9
	pcpUserExQuota           = 10
	pcpCannotProvideExternal = 11
	pcpAddressMismatch       = 12
)

type pcpServer struct {
	lans []string    // interfaces requests are accepted on
	nat  *natManager // the tunnel's IPv4 NAT; nil when sixup does not do it, and IPv4 is refused
	fw   *firewall   // the IPv6 filter whose pinholes MAP opens; nil while IPv6 inbound is let through

	mu    sync.Mutex
	start time.Time         // Epoch Time counts from here, and restarts whenever state is lost
	ipv4  netip.Addr        // the tunnel's IPv4 that mappings are made on; zero while there is none
	ports []portSpan        // the line's port set on MAP-E; empty when every port is the line's
	maps  map[pcpKey]pcpMap // IPv4 mappings
	// listeners reports the ports this host listens on itself; tests substitute a fixed set
	listeners func(proto byte, addr netip.Addr) map[uint16]bool
	c4        *ipv4.PacketConn
	c6        *ipv6.PacketConn
}

type pcpKey struct {
	proto    byte
	internal netip.AddrPort
}

type pcpMap struct {
	external uint16
	nonce    [12]byte
	expires  time.Time
}

func (p *pcpServer) run(ctx context.Context, ch <-chan Snapshot) {
	p.mu.Lock()
	p.start = time.Now()
	p.mu.Unlock()
	if c, err := net.ListenPacket("udp6", "[::]:5351"); err != nil {
		errorf("[pcp] listen on UDP %d over IPv6 failed: %v", pcpServerPort, err)
	} else {
		defer c.Close()
		p.c6 = ipv6.NewPacketConn(c)
		p.c6.SetControlMessage(ipv6.FlagInterface|ipv6.FlagDst, true)
		go p.serve6()
	}
	if c, err := net.ListenPacket("udp4", "0.0.0.0:5351"); err != nil {
		errorf("[pcp] listen on UDP %d over IPv4 failed: %v", pcpServerPort, err)
	} else {
		defer c.Close()
		p.c4 = ipv4.NewPacketConn(c)
		p.c4.SetControlMessage(ipv4.FlagInterface|ipv4.FlagDst, true)
		go p.serve4()
	}
	if p.c4 == nil && p.c6 == nil {
		return
	}
	infof("[pcp] answering on UDP %d; over IPv6 hosts are told their own address and port, IPv6 inbound not being filtered", pcpServerPort)
	go p.announce(ctx)
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-ch:
			switch lost, gained := p.setTunnel(s); {
			case lost:
				go p.announce(ctx) // NAT-PMP's announcement goes with it
			case gained:
				go p.announceNATPMP(ctx)
			}
		case <-tick.C:
			p.expire(time.Now())
		}
	}
}

func (p *pcpServer) serve6() {
	buf := make([]byte, 2048)
	for {
		n, cm, from, err := p.c6.ReadFrom(buf)
		if err != nil {
			return
		}
		udp, ok := from.(*net.UDPAddr)
		if !ok || cm == nil || !p.onLAN(cm.IfIndex) || cm.Dst.IsMulticast() {
			continue // requests come from a LAN, to the router's own address
		}
		src, _ := netip.AddrFromSlice(udp.IP)
		if resp := p.handle(buf[:n], src.Unmap(), time.Now()); resp != nil {
			// The reply comes from the address the request went to, or the client drops it
			if _, err := p.c6.WriteTo(resp, &ipv6.ControlMessage{Src: cm.Dst, IfIndex: cm.IfIndex}, udp); err != nil {
				debugf("[pcp] reply to %s failed: %v", src, err)
			}
		}
	}
}

func (p *pcpServer) serve4() {
	buf := make([]byte, 2048)
	for {
		n, cm, from, err := p.c4.ReadFrom(buf)
		if err != nil {
			return
		}
		udp, ok := from.(*net.UDPAddr)
		if !ok || cm == nil || !p.onLAN(cm.IfIndex) || cm.Dst.IsMulticast() || cm.Dst.Equal(net.IPv4bcast) {
			continue
		}
		src, _ := netip.AddrFromSlice(udp.IP)
		if resp := p.handle(buf[:n], src.Unmap(), time.Now()); resp != nil {
			if _, err := p.c4.WriteTo(resp, &ipv4.ControlMessage{Src: cm.Dst, IfIndex: cm.IfIndex}, udp); err != nil {
				debugf("[pcp] reply to %s failed: %v", src, err)
			}
		}
	}
}

func (p *pcpServer) onLAN(index int) bool {
	ifi, err := net.InterfaceByIndex(index)
	return err == nil && slices.Contains(p.lans, ifi.Name)
}

// setTunnel follows the tunnel's IPv4 and port set. When they change, mappings made on the old
// ones are gone, and lost reports that the clients have to be told. gained reports an IPv4 that
// is new, the first one included, which NAT-PMP announces (RFC 6886 section 3.2.1).
func (p *pcpServer) setTunnel(s Snapshot) (lost, gained bool) {
	var addr netip.Addr
	var ports []portSpan
	if plan, ok := natPlanFor(s, 0); ok && p.nat != nil {
		addr, ports = plan.ipv4, plan.ports
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if addr == p.ipv4 && slices.Equal(ports, p.ports) {
		return false, false
	}
	lost, gained = p.ipv4.IsValid(), addr.IsValid() && addr != p.ipv4
	p.ipv4, p.ports = addr, ports
	n := len(p.maps)
	maps.DeleteFunc(p.maps, func(k pcpKey, _ pcpMap) bool { return k.internal.Addr().Is4() })
	if n != len(p.maps) {
		infof("[pcp] the tunnel's IPv4 or port set changed, dropping %d mappings", n-len(p.maps))
		p.push()
	}
	if lost {
		p.start = time.Now()
	}
	return lost, gained
}

// expire drops the mappings whose lifetime has run out.
func (p *pcpServer) expire(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.maps)
	maps.DeleteFunc(p.maps, func(k pcpKey, m pcpMap) bool {
		if now.After(m.expires) {
			infof("[pcp] %s port %d to %s expired", protoName(k.proto), m.external, k.internal)
			return true
		}
		return false
	})
	if len(p.maps) != n {
		p.push()
	}
}

// push hands the IPv4 mappings to the NAT and the IPv6 ones to the filter; the caller holds mu.
func (p *pcpServer) push() {
	var v4, v6 []portMapping
	for k, m := range p.maps {
		mp := portMapping{proto: k.proto, internal: k.internal, external: m.external}
		if k.internal.Addr().Is4() {
			v4 = append(v4, mp)
		} else {
			v6 = append(v6, mp)
		}
	}
	order := func(a, b portMapping) int {
		return cmp.Or(cmp.Compare(a.external, b.external), cmp.Compare(a.proto, b.proto), a.internal.Compare(b.internal))
	}
	slices.SortFunc(v4, order)
	slices.SortFunc(v6, order)
	if p.nat != nil {
		p.nat.setMappings(v4)
	}
	if p.fw != nil {
		p.fw.setPinholes(v6)
	}
}

// announce tells the clients on each LAN that any mappings they held are gone, as a server that
// starts without state must (section 14.1.3): three times, the first gap 500 ms and doubling.
func (p *pcpServer) announce(ctx context.Context) {
	go p.announceNATPMP(ctx)
	gap := 500 * time.Millisecond
	for range 3 {
		p.mu.Lock()
		msg := p.header(pcpOpAnnounce, pcpSuccess, 0, time.Now())
		p.mu.Unlock()
		for _, name := range p.lans {
			ifi, err := net.InterfaceByName(name)
			if err != nil {
				continue
			}
			if p.c6 != nil {
				dst := &net.UDPAddr{IP: net.ParseIP("ff02::1"), Port: pcpClientPort, Zone: name}
				if _, err := p.c6.WriteTo(msg, &ipv6.ControlMessage{IfIndex: ifi.Index}, dst); err != nil {
					debugf("[pcp] announce on %s failed: %v", name, err)
				}
			}
			if p.c4 != nil {
				dst := &net.UDPAddr{IP: net.IPv4allsys, Port: pcpClientPort}
				if _, err := p.c4.WriteTo(msg, &ipv4.ControlMessage{IfIndex: ifi.Index}, dst); err != nil {
					debugf("[pcp] announce on %s failed: %v", name, err)
				}
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

// header builds a response header with nothing after it; the caller holds mu.
func (p *pcpServer) header(opcode, result byte, lifetime uint32, now time.Time) []byte {
	b := make([]byte, pcpHeaderLen)
	b[0], b[1], b[3] = pcpVersion, 0x80|opcode, result
	binary.BigEndian.PutUint32(b[4:], lifetime)
	binary.BigEndian.PutUint32(b[8:], uint32(now.Sub(p.start)/time.Second))
	return b
}

// handle answers one request from src, or returns nil for one that is dropped silently. A refusal
// is logged, since the client rarely says why it failed.
func (p *pcpServer) handle(req []byte, src netip.Addr, now time.Time) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	resp := p.respond(req, src, now)
	if len(resp) >= pcpHeaderLen && resp[3] != pcpSuccess {
		op := map[byte]string{pcpOpAnnounce: "ANNOUNCE", pcpOpMap: "MAP"}[req[1]&0x7f]
		switch {
		case req[0] == 0:
			// NAT-PMP (RFC 6886), whose opcodes mean other things; the answer tells the client to
			// speak PCP instead (RFC 6887 appendix A)
			op = "a NAT-PMP request"
		case op == "":
			op = fmt.Sprintf("opcode %d", req[1]&0x7f)
		}
		debugf("[pcp] refused %s from %s (version %d): %s", op, src, req[0], pcpResultNames[resp[3]])
	}
	return resp
}

var pcpResultNames = map[byte]string{
	pcpUnsuppVersion: "UNSUPP_VERSION", pcpNotAuthorized: "NOT_AUTHORIZED", pcpMalformedRequest: "MALFORMED_REQUEST",
	pcpUnsuppOpcode: "UNSUPP_OPCODE", pcpUnsuppOption: "UNSUPP_OPTION", pcpMalformedOption: "MALFORMED_OPTION",
	pcpNetworkFailure: "NETWORK_FAILURE", pcpNoResources: "NO_RESOURCES", pcpUnsuppProtocol: "UNSUPP_PROTOCOL",
	pcpUserExQuota: "USER_EX_QUOTA", pcpCannotProvideExternal: "CANNOT_PROVIDE_EXTERNAL", pcpAddressMismatch: "ADDRESS_MISMATCH",
}

func (p *pcpServer) respond(req []byte, src netip.Addr, now time.Time) []byte {
	if len(req) < 2 || req[1]&0x80 != 0 {
		return nil
	}
	if req[0] == 0 && src.Is4() {
		return p.natpmp(req, src, now)
	}
	if req[0] != pcpVersion {
		return p.fail(req, pcpUnsuppVersion, pcpLongError, now)
	}
	if len(req) < pcpHeaderLen {
		return nil
	}
	if len(req) > pcpMaxLen || len(req)%4 != 0 {
		return p.fail(req, pcpMalformedRequest, pcpLongError, now)
	}
	client, _ := netip.AddrFromSlice(req[8:24])
	if client.Unmap() != src {
		return p.fail(req, pcpAddressMismatch, pcpLongError, now)
	}
	opcode := req[1]
	switch opcode {
	case pcpOpAnnounce:
		opts, code := pcpOptions(req[pcpHeaderLen:])
		if code != pcpSuccess {
			return p.fail(req, code, pcpLongError, now)
		}
		if code := mandatoryUnsupported(opts, nil); code != pcpSuccess {
			return p.fail(req, code, pcpLongError, now)
		}
		return p.header(opcode, pcpSuccess, 0, now)
	case pcpOpMap:
		return p.mapping(req, src, now)
	}
	return p.fail(req, pcpUnsuppOpcode, pcpLongError, now)
}

// mapping answers a MAP request. Nothing between the host and the Internet rewrites or filters
// its IPv6, so the external address and port are its own.
func (p *pcpServer) mapping(req []byte, src netip.Addr, now time.Time) []byte {
	if len(req) < pcpHeaderLen+pcpMapLen {
		return p.fail(req, pcpMalformedRequest, pcpLongError, now)
	}
	data := req[pcpHeaderLen : pcpHeaderLen+pcpMapLen]
	proto, port := data[12], binary.BigEndian.Uint16(data[16:18])
	lifetime := binary.BigEndian.Uint32(req[4:8])
	opts, code := pcpOptions(req[pcpHeaderLen+pcpMapLen:])
	if code != pcpSuccess {
		return p.fail(req, code, pcpLongError, now)
	}
	if code := mandatoryUnsupported(opts, []byte{pcpOptPreferFailure}); code != pcpSuccess {
		return p.fail(req, code, pcpLongError, now)
	}
	var prefer []pcpOption // PREFER_FAILURE carries no data and appears once at most
	for _, o := range opts {
		if o.code == pcpOptPreferFailure {
			prefer = append(prefer, o)
		}
	}
	preferFailure := len(prefer) > 0
	switch {
	case proto == 0 && port != 0:
		return p.fail(req, pcpMalformedRequest, pcpLongError, now)
	case len(prefer) > 1 || preferFailure && len(prefer[0].data) != 0:
		return p.fail(req, pcpMalformedOption, pcpLongError, now)
	case preferFailure && lifetime == 0:
		return p.fail(req, pcpMalformedOption, pcpLongError, now)
	}
	if lifetime != 0 {
		lifetime = min(max(lifetime, pcpMinLifetime), pcpMaxLifetime)
	}
	if src.Is4() {
		return p.mapping4(req, data, src, proto, port, lifetime, preferFailure, now)
	}
	switch {
	case proto == pcpProtoUDP && (port == pcpClientPort || port == pcpServerPort):
		return p.fail(req, pcpNotAuthorized, pcpLongError, now) // section 11.3 keeps PCP's own ports out
	case !src.IsGlobalUnicast() || src.IsPrivate():
		// A link-local or ULA address cannot be reached from outside whatever the router does
		return p.fail(req, pcpNotAuthorized, pcpLongError, now)
	}
	if p.fw != nil {
		return p.pinhole(req, data, src, proto, port, lifetime, preferFailure, now)
	}
	if lifetime != 0 {
		debugf("[pcp] %s asks for protocol %d port %d, reachable as it is for %s", src, proto, port, seconds(lifetime))
	}
	return p.mapResponse(data, lifetime, src, port, preferFailure, now)
}

// mapping4 answers a MAP request from an IPv4 host with a mapping on the tunnel's IPv4.
func (p *pcpServer) mapping4(req, data []byte, src netip.Addr, proto byte, port uint16, lifetime uint32, preferFailure bool, now time.Time) []byte {
	if !p.ipv4.IsValid() {
		return p.fail(req, pcpNetworkFailure, pcpShortError, now) // no tunnel whose NAT is ours, or DS-Lite's
	}
	if proto != pcpProtoTCP && proto != pcpProtoUDP || port == 0 {
		return p.fail(req, pcpUnsuppProtocol, pcpLongError, now)
	}
	pick := func(suggested uint16) (uint16, bool) { return p.pickPort(proto, port, suggested, preferFailure) }
	// A service of the router's own may have started on the port since; the mapping moves off it
	stale := func(external uint16) bool { return p.localPorts(proto)[external] }
	return p.mapStateful(req, data, pcpKey{proto, netip.AddrPortFrom(src, port)}, p.ipv4, lifetime, preferFailure, now, pick, stale)
}

// pinhole answers a MAP request from an IPv6 host while unsolicited inbound is filtered: the
// firewall lets its address and port be reached, which are then its external ones too.
func (p *pcpServer) pinhole(req, data []byte, src netip.Addr, proto byte, port uint16, lifetime uint32, preferFailure bool, now time.Time) []byte {
	if proto != pcpProtoTCP && proto != pcpProtoUDP || port == 0 {
		return p.fail(req, pcpUnsuppProtocol, pcpLongError, now)
	}
	pick := func(suggested uint16) (uint16, bool) { return port, !preferFailure || suggested == port }
	return p.mapStateful(req, data, pcpKey{proto, netip.AddrPortFrom(src, port)}, src, lifetime, preferFailure, now, pick, nil)
}

// mapStateful grants, renews or deletes a mapping kept in p.maps, with ext as its external
// address. pick chooses the external port of a new mapping from the one suggested; stale, when
// set, tells that an existing one can no longer keep its port.
func (p *pcpServer) mapStateful(req, data []byte, key pcpKey, ext netip.Addr, lifetime uint32, preferFailure bool, now time.Time,
	pick func(suggested uint16) (uint16, bool), stale func(uint16) bool) []byte {
	var nonce [12]byte
	copy(nonce[:], data[:12])
	suggested := binary.BigEndian.Uint16(data[18:20])
	suggestedAddr, _ := netip.AddrFromSlice(data[20:36])
	suggestedAddr = suggestedAddr.Unmap()
	// PREFER_FAILURE turns a suggestion into a condition
	unmet := func(external uint16) bool {
		return preferFailure && (suggested != external || !suggestedAddr.IsUnspecified() && suggestedAddr != ext)
	}
	proto := protoName(key.proto)
	cur, have := p.maps[key]
	if have && cur.nonce != nonce {
		debugf("[pcp] %s %s is mapped already under another nonce, until %s", proto, key.internal, cur.expires.Format(time.TimeOnly))
		return p.fail(req, pcpNotAuthorized, uint32(max(cur.expires.Sub(now), 0)/time.Second), now)
	}
	if have && lifetime != 0 && stale != nil && stale(cur.external) {
		infof("[pcp] this router now listens on %s port %d itself, moving %s's mapping", proto, cur.external, key.internal)
		delete(p.maps, key)
		p.push()
		have = false
	}
	if lifetime == 0 {
		if have {
			delete(p.maps, key)
			p.push()
			infof("[pcp] %s released %s port %d", key.internal.Addr(), proto, cur.external)
		}
		return p.mapResponse(data, 0, ext, cur.external, false, now)
	}
	if !have {
		if p.hostMappings(key.internal.Addr()) >= pcpMaxPerHost {
			return p.fail(req, pcpUserExQuota, pcpShortError, now)
		}
		external, ok := pick(suggested)
		switch {
		case !ok && preferFailure || ok && unmet(external):
			return p.fail(req, pcpCannotProvideExternal, pcpShortError, now)
		case !ok:
			return p.fail(req, pcpNoResources, pcpShortError, now)
		}
		cur.external, cur.nonce = external, nonce
	} else if unmet(cur.external) {
		return p.fail(req, pcpCannotProvideExternal, pcpShortError, now)
	}
	cur.expires = now.Add(time.Duration(lifetime) * time.Second)
	if p.maps == nil {
		p.maps = map[pcpKey]pcpMap{}
	}
	p.maps[key] = cur
	switch {
	case have:
		debugf("[pcp] %s renewed %s port %d for %s", key.internal, proto, cur.external, seconds(lifetime))
	case ext.Is6():
		p.push()
		infof("[pcp] inbound %s to %s let through for %s", proto, key.internal, seconds(lifetime))
	default:
		p.push()
		infof("[pcp] %s port %d of %s maps to %s for %s", proto, cur.external, ext, key.internal, seconds(lifetime))
	}
	return p.mapResponse(data, lifetime, ext, cur.external, preferFailure, now)
}

func (p *pcpServer) hostMappings(host netip.Addr) int {
	n := 0
	for k := range p.maps {
		if k.internal.Addr() == host {
			n++
		}
	}
	return n
}

// pickPort chooses an external port: the one suggested, then the internal one, then any other,
// from a random place so that hosts do not all line up on the same ones. With PREFER_FAILURE
// only the suggestion will do.
func (p *pcpServer) pickPort(proto byte, internal, suggested uint16, preferFailure bool) (uint16, bool) {
	local := p.localPorts(proto)
	usable := func(e uint16) bool {
		if e < pcpMinExternal || proto == pcpProtoUDP && (e == pcpClientPort || e == pcpServerPort) {
			return false
		}
		if local[e] {
			return false // a service of the router's own listens there, and would be cut off
		}
		if len(p.ports) > 0 && !slices.ContainsFunc(p.ports, func(s portSpan) bool { return s.Start <= e && e <= s.End }) {
			return false
		}
		for k, m := range p.maps {
			if k.proto == proto && m.external == e {
				return false
			}
		}
		return true
	}
	if suggested != 0 && usable(suggested) {
		return suggested, true
	}
	if preferFailure {
		return 0, false
	}
	if usable(internal) {
		return internal, true
	}
	spans := p.ports
	if len(spans) == 0 {
		spans = []portSpan{{pcpMinExternal, 65535}}
	}
	n := portCount(spans)
	start := rand.IntN(n)
	for i := range n {
		if e := nthPort(spans, (start+i)%n); usable(e) {
			return e, true
		}
	}
	return 0, false
}

// localPorts are the ports this host listens on for proto, at the tunnel's IPv4 or a wildcard.
// Mapping one would hand its new connections to a LAN host.
func (p *pcpServer) localPorts(proto byte) map[uint16]bool {
	if p.listeners != nil {
		return p.listeners(proto, p.ipv4)
	}
	ports, err := localListeners(proto, p.ipv4)
	if err != nil {
		debugf("[pcp] cannot list the ports this router listens on: %v", err)
	}
	return ports
}

// seconds formats a PCP lifetime, such as 1h0m0s for 3600.
func seconds(n uint32) time.Duration { return time.Duration(n) * time.Second }

// nthPort is the i-th port counting through spans.
func nthPort(spans []portSpan, i int) uint16 {
	for _, s := range spans {
		if n := int(s.End) - int(s.Start) + 1; i < n {
			return s.Start + uint16(i)
		} else {
			i -= n
		}
	}
	return 0
}

// mapResponse builds a successful MAP response giving addr and port as the external ones.
func (p *pcpServer) mapResponse(data []byte, lifetime uint32, addr netip.Addr, port uint16, preferFailure bool, now time.Time) []byte {
	resp := p.header(pcpOpMap, pcpSuccess, lifetime, now)
	out := slices.Clone(data)
	clear(out[13:16]) // reserved
	binary.BigEndian.PutUint16(out[18:20], port)
	a := addr.As16() // an IPv4 address in its IPv4-mapped form, as PCP carries it
	copy(out[20:36], a[:])
	resp = append(resp, out...)
	if preferFailure {
		resp = append(resp, pcpOptPreferFailure, 0, 0, 0) // processed options go back in a success
	}
	return resp
}

// fail builds an error response: the request echoed with the result code and the header fields a
// response sets, truncated to the size limit.
func (p *pcpServer) fail(req []byte, code byte, lifetime uint32, now time.Time) []byte {
	resp := slices.Clone(req[:min(len(req), pcpMaxLen)])
	if len(resp) < pcpHeaderLen {
		resp = append(resp, make([]byte, pcpHeaderLen-len(resp))...)
	}
	h := p.header(resp[1]&0x7f, code, lifetime, now)
	h[0] = pcpVersion // the version this server speaks, as version negotiation needs
	copy(resp, h)
	return resp
}

type pcpOption struct {
	code byte
	data []byte
}

// pcpOptions splits the options after the opcode data; a structure that does not parse is
// MALFORMED_OPTION (section 7.3).
func pcpOptions(b []byte) ([]pcpOption, byte) {
	var out []pcpOption
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, pcpMalformedOption
		}
		n := int(binary.BigEndian.Uint16(b[2:4]))
		padded := 4 + (n+3)/4*4
		if padded > len(b) {
			return nil, pcpMalformedOption
		}
		out = append(out, pcpOption{code: b[0], data: b[4 : 4+n]})
		b = b[padded:]
	}
	return out, pcpSuccess
}

// mandatoryUnsupported returns UNSUPP_OPTION for a mandatory option (code below 128) not in
// known, such as THIRD_PARTY; optional ones are ignored.
func mandatoryUnsupported(opts []pcpOption, known []byte) byte {
	for _, o := range opts {
		if o.code < 128 && !slices.Contains(known, o.code) {
			return pcpUnsuppOption
		}
	}
	return pcpSuccess
}
