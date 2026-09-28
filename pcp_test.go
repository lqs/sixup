package main

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var pcpHost = netip.MustParseAddr("2001:db8:1::10")

// pcpReq builds a request from pcpHost: the header, then data, then options.
func pcpReq(opcode byte, lifetime uint32, data []byte, opts ...[]byte) []byte {
	b := make([]byte, pcpHeaderLen)
	b[0], b[1] = pcpVersion, opcode
	binary.BigEndian.PutUint32(b[4:], lifetime)
	a := pcpHost.As16()
	copy(b[8:], a[:])
	b = append(b, data...)
	for _, o := range opts {
		b = append(b, o...)
	}
	return b
}

// mapData is the MAP opcode data asking for proto/port, with a nonce and a suggested address to
// be replaced.
func mapData(proto byte, port uint16) []byte {
	d := make([]byte, pcpMapLen)
	copy(d, "nonce-123456")
	d[12], d[13] = proto, 0xff // reserved set, to be cleared in the reply
	binary.BigEndian.PutUint16(d[16:], port)
	binary.BigEndian.PutUint16(d[18:], 9999)
	return d
}

func TestPCPMapIsAnsweredWithTheHostItself(t *testing.T) {
	p := &pcpServer{start: time.Now().Add(-time.Minute)}
	resp := p.handle(pcpReq(pcpOpMap, 3600, mapData(6, 8080)), pcpHost, time.Now())
	if len(resp) != pcpHeaderLen+pcpMapLen {
		t.Fatalf("response is %d bytes", len(resp))
	}
	if resp[0] != pcpVersion || resp[1] != 0x80|pcpOpMap || resp[3] != pcpSuccess {
		t.Fatalf("header: %x", resp[:4])
	}
	if lt := binary.BigEndian.Uint32(resp[4:]); lt != 3600 {
		t.Fatalf("lifetime %d", lt)
	}
	if epoch := binary.BigEndian.Uint32(resp[8:]); epoch != 60 {
		t.Fatalf("epoch counts seconds since start, got %d", epoch)
	}
	d := resp[pcpHeaderLen:]
	if string(d[:12]) != "nonce-123456" || d[12] != 6 || d[13] != 0 {
		t.Fatalf("the nonce and protocol come back, reserved cleared: %x", d[:16])
	}
	ext, _ := netip.AddrFromSlice(d[20:36])
	if binary.BigEndian.Uint16(d[16:]) != 8080 || binary.BigEndian.Uint16(d[18:]) != 8080 || ext != pcpHost {
		t.Fatalf("the external address and port are the host's own: %s port %d", ext, binary.BigEndian.Uint16(d[18:]))
	}
}

func TestPCPMapLifetimes(t *testing.T) {
	p := &pcpServer{start: time.Now()}
	for req, want := range map[uint32]uint32{0: 0, 10: pcpMinLifetime, 7 * 24 * 3600: pcpMaxLifetime} {
		resp := p.handle(pcpReq(pcpOpMap, req, mapData(17, 5000)), pcpHost, time.Now())
		if resp[3] != pcpSuccess || binary.BigEndian.Uint32(resp[4:]) != want {
			t.Errorf("lifetime %d: result %d, lifetime %d, want %d", req, resp[3], binary.BigEndian.Uint32(resp[4:]), want)
		}
	}
}

func TestPCPErrors(t *testing.T) {
	p := &pcpServer{start: time.Now()}
	thirdParty := []byte{1, 0, 0, 16}
	thirdParty = append(thirdParty, make([]byte, 16)...)
	cases := []struct {
		name string
		req  []byte
		src  netip.Addr
		code byte
	}{
		{"another version", func() []byte { r := pcpReq(pcpOpMap, 60, mapData(6, 80)); r[0] = 3; return r }(), pcpHost, pcpUnsuppVersion},
		{"not a multiple of 4", append(pcpReq(pcpOpMap, 60, mapData(6, 80)), 0), pcpHost, pcpMalformedRequest},
		{"MAP data too short", pcpReq(pcpOpMap, 60, make([]byte, 20)), pcpHost, pcpMalformedRequest},
		{"client address is not the source", pcpReq(pcpOpMap, 60, mapData(6, 80)), netip.MustParseAddr("2001:db8:1::11"), pcpAddressMismatch},
		{"PEER", pcpReq(2, 60, make([]byte, 56)), pcpHost, pcpUnsuppOpcode},
		{"THIRD_PARTY", pcpReq(pcpOpMap, 60, mapData(6, 80), thirdParty), pcpHost, pcpUnsuppOption},
		{"option longer than the packet", pcpReq(pcpOpMap, 60, mapData(6, 80), []byte{130, 0, 0, 40}), pcpHost, pcpMalformedOption},
		{"PREFER_FAILURE twice", pcpReq(pcpOpMap, 60, mapData(6, 80), []byte{2, 0, 0, 0}, []byte{2, 0, 0, 0}), pcpHost, pcpMalformedOption},
		{"PREFER_FAILURE on a delete", pcpReq(pcpOpMap, 0, mapData(6, 80), []byte{2, 0, 0, 0}), pcpHost, pcpMalformedOption},
		{"all protocols but one port", pcpReq(pcpOpMap, 60, mapData(0, 80)), pcpHost, pcpMalformedRequest},
		{"PCP's own port", pcpReq(pcpOpMap, 60, mapData(17, pcpServerPort)), pcpHost, pcpNotAuthorized},
	}
	for _, c := range cases {
		resp := p.handle(c.req, c.src, time.Now())
		if resp == nil || resp[3] != c.code {
			t.Errorf("%s: want result %d, got %v", c.name, c.code, resp)
			continue
		}
		if resp[1] != 0x80|c.req[1] || len(resp) != len(c.req) || binary.BigEndian.Uint32(resp[4:]) != pcpLongError {
			t.Errorf("%s: an error echoes the request with a long error lifetime, got %x", c.name, resp[:8])
		}
	}
}

// Link-local and ULA hosts cannot be reached from outside, so they get no mapping.
func TestPCPMapNeedsAGlobalAddress(t *testing.T) {
	p := &pcpServer{start: time.Now()}
	for _, a := range []string{"fe80::10", "fd00::10"} {
		src := netip.MustParseAddr(a)
		req := pcpReq(pcpOpMap, 60, mapData(6, 80))
		b := src.As16()
		copy(req[8:24], b[:])
		if resp := p.handle(req, src, time.Now()); resp[3] != pcpNotAuthorized {
			t.Errorf("%s: want NOT_AUTHORIZED, got %d", a, resp[3])
		}
	}
}

func TestPCPDropsWhatIsNotARequest(t *testing.T) {
	p := &pcpServer{start: time.Now()}
	resp := pcpReq(pcpOpMap, 60, mapData(6, 80))
	resp[1] |= 0x80
	for name, b := range map[string][]byte{"a response": resp, "one octet": {2}, "shorter than a header": make([]byte, 12)} {
		if name == "shorter than a header" {
			b[0] = pcpVersion
		}
		if p.handle(b, pcpHost, time.Now()) != nil {
			t.Errorf("%s must be dropped", name)
		}
	}
}

func TestPCPAnnounce(t *testing.T) {
	p := &pcpServer{start: time.Now()}
	resp := p.handle(pcpReq(pcpOpAnnounce, 0, nil), pcpHost, time.Now())
	if len(resp) != pcpHeaderLen || resp[1] != 0x80 || resp[3] != pcpSuccess {
		t.Fatalf("ANNOUNCE: %x", resp)
	}
	withOptional := p.handle(pcpReq(pcpOpMap, 60, mapData(6, 80), []byte{200, 0, 0, 0}), pcpHost, time.Now())
	if withOptional[3] != pcpSuccess || len(withOptional) != pcpHeaderLen+pcpMapLen {
		t.Fatal("an optional option is ignored, and left out of the reply")
	}
}

var pcpHost4 = netip.MustParseAddr("192.168.1.10")

// pcpServer4 maps on 203.0.113.9, every port of it unless ports narrows them, and hands its
// mappings to a NAT that only records them.
func pcpServer4(ports []portSpan) *pcpServer {
	return &pcpServer{
		start: time.Now(), nat: &natManager{mapIn: make(chan []portMapping, 1)},
		ipv4: netip.MustParseAddr("203.0.113.9"), ports: ports,
		listeners: func(byte, netip.Addr) map[uint16]bool { return nil },
	}
}

// pcpReq4 is a MAP request from host for proto/port suggesting external port suggested.
func pcpReq4(host netip.Addr, lifetime uint32, proto byte, port, suggested uint16, nonce string, opts ...[]byte) []byte {
	d := mapData(proto, port)
	copy(d, nonce)
	binary.BigEndian.PutUint16(d[18:], suggested)
	r := pcpReq(pcpOpMap, lifetime, d, opts...)
	a := netip.AddrFrom16(host.As16()).As16() // IPv4-mapped
	copy(r[8:24], a[:])
	return r
}

func external(t *testing.T, resp []byte) (netip.Addr, uint16) {
	t.Helper()
	if resp[3] != pcpSuccess {
		t.Fatalf("result %d", resp[3])
	}
	a, _ := netip.AddrFromSlice(resp[pcpHeaderLen+20 : pcpHeaderLen+36])
	return a.Unmap(), binary.BigEndian.Uint16(resp[pcpHeaderLen+18:])
}

func TestPCP4MapsOnTheTunnelAddress(t *testing.T) {
	p := pcpServer4(nil)
	addr, port := external(t, p.handle(pcpReq4(pcpHost4, 3600, pcpProtoTCP, 8080, 9090, "nonce-aaaaaa"), pcpHost4, time.Now()))
	if addr != p.ipv4 || port != 9090 {
		t.Fatalf("the suggested port on the tunnel's IPv4, got %s:%d", addr, port)
	}
	ms := <-p.nat.mapIn
	if len(ms) != 1 || ms[0] != (portMapping{pcpProtoTCP, netip.AddrPortFrom(pcpHost4, 8080), 9090}) {
		t.Fatalf("the NAT was handed %+v", ms)
	}
	// Renewing keeps the port and hands nothing new to the NAT
	if _, port := external(t, p.handle(pcpReq4(pcpHost4, 3600, pcpProtoTCP, 8080, 0, "nonce-aaaaaa"), pcpHost4, time.Now())); port != 9090 {
		t.Fatalf("a renewal keeps port 9090, got %d", port)
	}
	select {
	case ms := <-p.nat.mapIn:
		t.Fatalf("a renewal changes no rules, got %+v", ms)
	default:
	}
	// Another nonce is another client, which may not take the mapping over
	if resp := p.handle(pcpReq4(pcpHost4, 3600, pcpProtoTCP, 8080, 0, "nonce-bbbbbb"), pcpHost4, time.Now()); resp[3] != pcpNotAuthorized {
		t.Fatalf("a foreign nonce: want NOT_AUTHORIZED, got %d", resp[3])
	}
	// Deleting it
	p.handle(pcpReq4(pcpHost4, 0, pcpProtoTCP, 8080, 0, "nonce-aaaaaa"), pcpHost4, time.Now())
	if ms := <-p.nat.mapIn; len(ms) != 0 || len(p.maps) != 0 {
		t.Fatalf("after the delete: %+v", ms)
	}
}

func TestPCP4PortChoice(t *testing.T) {
	p := pcpServer4(nil)
	other := netip.MustParseAddr("192.168.1.11")
	take := func(host netip.Addr, port, suggested uint16, nonce string) uint16 {
		_, e := external(t, p.handle(pcpReq4(host, 3600, pcpProtoUDP, port, suggested, nonce), host, time.Now()))
		return e
	}
	if e := take(pcpHost4, 6000, 80, "n1"); e != 6000 {
		t.Fatalf("a suggestion below 1024 falls back to the internal port, got %d", e)
	}
	if e := take(other, 6000, 6000, "n2"); e == 6000 || e < pcpMinExternal {
		t.Fatalf("a taken port goes to someone else only once, got %d", e)
	}
	if e := take(pcpHost4, 53, 0, "n3"); e < pcpMinExternal {
		t.Fatalf("no external port below 1024, got %d", e)
	}
	if e := take(pcpHost4, 7000, pcpServerPort, "n4"); e == pcpServerPort {
		t.Fatal("UDP 5351 is PCP's own")
	}

	mape := pcpServer4([]portSpan{{5472, 5487}, {9568, 9583}})
	_, e := external(t, mape.handle(pcpReq4(pcpHost4, 3600, pcpProtoTCP, 8080, 8080, "n5"), pcpHost4, time.Now()))
	if inSet := e >= 5472 && e <= 5487 || e >= 9568 && e <= 9583; !inSet {
		t.Fatalf("on MAP-E the port comes from the line's port set, got %d", e)
	}
}

func TestPCP4Refusals(t *testing.T) {
	p := pcpServer4(nil)
	for i := range pcpMaxPerHost {
		if resp := p.handle(pcpReq4(pcpHost4, 3600, pcpProtoTCP, uint16(10000+i), 0, "quota"), pcpHost4, time.Now()); resp[3] != pcpSuccess {
			t.Fatalf("mapping %d: %d", i, resp[3])
		}
	}
	if resp := p.handle(pcpReq4(pcpHost4, 3600, pcpProtoTCP, 20000, 0, "quota"), pcpHost4, time.Now()); resp[3] != pcpUserExQuota {
		t.Fatalf("mapping %d: want USER_EX_QUOTA, got %d", pcpMaxPerHost+1, resp[3])
	}
	other := netip.MustParseAddr("192.168.1.11")
	prefer := []byte{pcpOptPreferFailure, 0, 0, 0}
	if resp := p.handle(pcpReq4(other, 3600, pcpProtoTCP, 10000, 10000, "pf", prefer), other, time.Now()); resp[3] != pcpCannotProvideExternal {
		t.Fatalf("PREFER_FAILURE on a taken port: want CANNOT_PROVIDE_EXTERNAL, got %d", resp[3])
	}
	if resp := p.handle(pcpReq4(other, 3600, 0, 0, 0, "dmz"), other, time.Now()); resp[3] != pcpUnsuppProtocol {
		t.Fatalf("all ports: want UNSUPP_PROTOCOL, got %d", resp[3])
	}
	if resp := p.handle(pcpReq4(other, 3600, 132, 5000, 0, "sctp"), other, time.Now()); resp[3] != pcpUnsuppProtocol {
		t.Fatalf("SCTP: want UNSUPP_PROTOCOL, got %d", resp[3])
	}
	none := pcpServer4(nil)
	none.ipv4 = netip.Addr{}
	if resp := none.handle(pcpReq4(other, 3600, pcpProtoTCP, 5000, 0, "none"), other, time.Now()); resp[3] != pcpNetworkFailure || binary.BigEndian.Uint32(resp[4:]) != pcpShortError {
		t.Fatalf("no tunnel IPv4: want a short NETWORK_FAILURE, got %d", resp[3])
	}
}

func TestPCP4ExpiryAndTunnelChange(t *testing.T) {
	p := pcpServer4(nil)
	now := time.Now()
	p.handle(pcpReq4(pcpHost4, 120, pcpProtoTCP, 8080, 0, "n"), pcpHost4, now)
	<-p.nat.mapIn
	p.expire(now.Add(time.Minute))
	if len(p.maps) != 1 {
		t.Fatal("a mapping lives out its lifetime")
	}
	p.expire(now.Add(3 * time.Minute))
	if ms := <-p.nat.mapIn; len(ms) != 0 || len(p.maps) != 0 {
		t.Fatal("an expired mapping is dropped from the NAT")
	}

	p.handle(pcpReq4(pcpHost4, 3600, pcpProtoTCP, 8080, 0, "n"), pcpHost4, now)
	<-p.nat.mapIn
	moved := Snapshot{Tunnel: &TunnelParams{
		Kind: "4in6", Local: netip.MustParseAddr("2001:db8::1"), Remote: netip.MustParseAddr("2001:db8::2"),
		IPv4: netip.MustParseAddr("198.51.100.7"),
	}}
	if lost, gained := p.setTunnel(moved); !lost || !gained {
		t.Fatal("a new tunnel address loses the state, which the clients have to hear")
	}
	if ms := <-p.nat.mapIn; len(ms) != 0 || p.ipv4 != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("mappings on the old address are dropped: %+v %s", ms, p.ipv4)
	}
	if lost, gained := p.setTunnel(moved); lost || gained {
		t.Fatal("the same tunnel again changes nothing")
	}
	// The first IPv4 loses nothing but is new to NAT-PMP clients
	fresh := &pcpServer{nat: &natManager{mapIn: make(chan []portMapping, 1)}}
	if lost, gained := fresh.setTunnel(moved); lost || !gained {
		t.Fatalf("a first IPv4: lost %v gained %v", lost, gained)
	}
}

// A port the router listens on itself is never handed out, and a mapping moves off one when a
// service of the router's own starts there later.
func TestPCP4AvoidsTheRoutersOwnPorts(t *testing.T) {
	p := pcpServer4(nil)
	own := map[uint16]bool{}
	p.listeners = func(proto byte, addr netip.Addr) map[uint16]bool {
		if proto != pcpProtoUDP || addr != p.ipv4 {
			t.Errorf("asked about protocol %d on %s", proto, addr)
		}
		return own
	}
	own[51820] = true // say, WireGuard
	if _, e := external(t, p.handle(pcpReq4(pcpHost4, 3600, pcpProtoUDP, 51820, 51820, "wg"), pcpHost4, time.Now())); e == 51820 {
		t.Fatal("the router's own port must not be mapped")
	}
	<-p.nat.mapIn
	prefer := []byte{pcpOptPreferFailure, 0, 0, 0}
	if resp := p.handle(pcpReq4(pcpHost4, 3600, pcpProtoUDP, 51821, 51820, "pf", prefer), pcpHost4, time.Now()); resp[3] != pcpCannotProvideExternal {
		t.Fatalf("PREFER_FAILURE on the router's own port: want CANNOT_PROVIDE_EXTERNAL, got %d", resp[3])
	}

	_, e := external(t, p.handle(pcpReq4(pcpHost4, 3600, pcpProtoUDP, 6000, 6000, "later"), pcpHost4, time.Now()))
	<-p.nat.mapIn
	own[e] = true // a service of the router's starts on it
	if _, moved := external(t, p.handle(pcpReq4(pcpHost4, 3600, pcpProtoUDP, 6000, 0, "later"), pcpHost4, time.Now())); moved == e {
		t.Fatalf("the renewal should move the mapping off %d", e)
	}
	for _, m := range <-p.nat.mapIn {
		if m.external == e {
			t.Fatalf("the NAT still maps %d", e)
		}
	}
}

// A refusal is logged with who asked, for what, and why, the client rarely saying.
func TestPCPLogsRefusals(t *testing.T) {
	var logged bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(&plainHandler{w: &logged}))
	defer slog.SetDefault(prev)
	defer logLevel.Set(logLevel.Level())
	setDebug()
	p := &pcpServer{start: time.Now()}
	req := pcpReq(pcpOpMap, 60, mapData(6, 80))
	req[0] = 3 // a later PCP
	p.handle(req, pcpHost, time.Now())
	req[0] = 0 // NAT-PMP, whose opcodes are not PCP's
	p.handle(req, pcpHost, time.Now())
	got := logged.String()
	if !strings.Contains(got, "refused MAP from 2001:db8:1::10 (version 3): UNSUPP_VERSION") ||
		!strings.Contains(got, "refused a NAT-PMP request from 2001:db8:1::10 (version 0): UNSUPP_VERSION") {
		t.Fatalf("log: %q", got)
	}
}

// Under -unsolicited request, a MAP from an IPv6 host opens a pinhole for its own address and port,
// kept like an IPv4 mapping, and handed to the filter.
func TestPCPPinholes(t *testing.T) {
	p := &pcpServer{start: time.Now(), fw: &firewall{holeIn: make(chan []portMapping, 1)}}
	req := func(lifetime uint32, port, suggested uint16, nonce string, opts ...[]byte) []byte {
		d := mapData(pcpProtoTCP, port)
		copy(d, nonce)
		binary.BigEndian.PutUint16(d[18:], suggested)
		return pcpReq(pcpOpMap, lifetime, d, opts...)
	}
	addr, port := external(t, p.handle(req(3600, 8080, 0, "nonce-aaaaaa"), pcpHost, time.Now()))
	if addr != pcpHost || port != 8080 {
		t.Fatalf("a pinhole is the host's own address and port, got [%s]:%d", addr, port)
	}
	if ms := <-p.fw.holeIn; len(ms) != 1 || ms[0].internal != netip.AddrPortFrom(pcpHost, 8080) || ms[0].proto != pcpProtoTCP {
		t.Fatalf("the filter was handed %+v", ms)
	}
	if resp := p.handle(req(3600, 8080, 0, "nonce-bbbbbb"), pcpHost, time.Now()); resp[3] != pcpNotAuthorized {
		t.Fatalf("a foreign nonce: want NOT_AUTHORIZED, got %d", resp[3])
	}
	prefer := []byte{pcpOptPreferFailure, 0, 0, 0}
	if resp := p.handle(req(3600, 9000, 9001, "pf", prefer), pcpHost, time.Now()); resp[3] != pcpCannotProvideExternal {
		t.Fatalf("PREFER_FAILURE on another port: want CANNOT_PROVIDE_EXTERNAL, got %d", resp[3])
	}

	// A tunnel change concerns the IPv4 mappings only
	p.nat = &natManager{mapIn: make(chan []portMapping, 1)}
	p.ipv4 = netip.MustParseAddr("203.0.113.9")
	p.setTunnel(Snapshot{})
	if len(p.maps) != 1 {
		t.Fatalf("the pinhole must survive the tunnel going: %+v", p.maps)
	}

	p.handle(req(0, 8080, 0, "nonce-aaaaaa"), pcpHost, time.Now())
	if ms := <-p.fw.holeIn; len(ms) != 0 {
		t.Fatalf("after the delete the filter holds %+v", ms)
	}
	for i := range pcpMaxPerHost {
		p.handle(req(3600, uint16(10000+i), 0, "quota"), pcpHost, time.Now())
	}
	if resp := p.handle(req(3600, 20000, 0, "quota"), pcpHost, time.Now()); resp[3] != pcpUserExQuota {
		t.Fatalf("pinhole %d: want USER_EX_QUOTA, got %d", pcpMaxPerHost+1, resp[3])
	}
}

// natpmpMap is a NAT-PMP mapping request.
func natpmpMap(op byte, internal, suggested uint16, lifetime uint32) []byte {
	b := make([]byte, 12)
	b[1] = op
	binary.BigEndian.PutUint16(b[4:], internal)
	binary.BigEndian.PutUint16(b[6:], suggested)
	binary.BigEndian.PutUint32(b[8:], lifetime)
	return b
}

// NAT-PMP (RFC 6886): the external address, a mapping as PCP would make it and shared with PCP's,
// its renewal and deletion, and the deletion of all of a host's mappings.
func TestNATPMP(t *testing.T) {
	p := pcpServer4(nil)
	now := time.Now()
	resp := p.handle([]byte{0, natpmpOpAddress}, pcpHost4, now)
	if len(resp) != 12 || resp[0] != 0 || resp[1] != 128 || binary.BigEndian.Uint16(resp[2:]) != natpmpSuccess || netip.AddrFrom4([4]byte(resp[8:12])) != p.ipv4 {
		t.Fatalf("external address: % x", resp)
	}

	resp = p.handle(natpmpMap(natpmpOpTCP, 8080, 9090, 7200), pcpHost4, now)
	if len(resp) != 16 || resp[1] != 130 || binary.BigEndian.Uint16(resp[2:]) != natpmpSuccess ||
		binary.BigEndian.Uint16(resp[8:]) != 8080 || binary.BigEndian.Uint16(resp[10:]) != 9090 || binary.BigEndian.Uint32(resp[12:]) != 7200 {
		t.Fatalf("mapping: % x", resp)
	}
	if ms := <-p.nat.mapIn; len(ms) != 1 || ms[0] != (portMapping{pcpProtoTCP, netip.AddrPortFrom(pcpHost4, 8080), 9090}) {
		t.Fatalf("the NAT was handed %+v", ms)
	}
	// Renewed on the same port; a PCP request with a nonce cannot take it over
	if resp = p.handle(natpmpMap(natpmpOpTCP, 8080, 0, 7200), pcpHost4, now); binary.BigEndian.Uint16(resp[10:]) != 9090 {
		t.Fatalf("renewal: % x", resp)
	}
	if code := p.handle(pcpReq4(pcpHost4, 3600, pcpProtoTCP, 8080, 0, "nonce-aaaaaa"), pcpHost4, now)[3]; code != pcpNotAuthorized {
		t.Fatalf("PCP over a NAT-PMP mapping: result %d", code)
	}
	// Deleted, and deleting again answers the same
	for range 2 {
		resp = p.handle(natpmpMap(natpmpOpTCP, 8080, 0, 0), pcpHost4, now)
		if binary.BigEndian.Uint16(resp[2:]) != natpmpSuccess || binary.BigEndian.Uint16(resp[8:]) != 8080 || binary.BigEndian.Uint16(resp[10:]) != 0 || binary.BigEndian.Uint32(resp[12:]) != 0 {
			t.Fatalf("deletion: % x", resp)
		}
	}
	// Internal port 0 with lifetime 0 deletes all of the host's mappings for the protocol
	p.handle(natpmpMap(natpmpOpUDP, 5000, 0, 7200), pcpHost4, now)
	p.handle(natpmpMap(natpmpOpUDP, 5001, 0, 7200), pcpHost4, now)
	p.handle(natpmpMap(natpmpOpUDP, 0, 0, 0), pcpHost4, now)
	if len(p.maps) != 0 {
		t.Fatalf("left: %+v", p.maps)
	}

	if resp = p.handle([]byte{0, 9}, pcpHost4, now); binary.BigEndian.Uint16(resp[2:]) != natpmpUnsuppOpcode {
		t.Fatalf("unknown opcode: % x", resp)
	}
	p.ipv4 = netip.Addr{}
	if resp = p.handle([]byte{0, natpmpOpAddress}, pcpHost4, now); binary.BigEndian.Uint16(resp[2:]) != natpmpNetworkFailure {
		t.Fatalf("no tunnel: % x", resp)
	}
	// Over IPv6, where NAT-PMP has no place, the PCP answer tells the client to use PCP
	if resp = p.handle([]byte{0, 0}, pcpHost, now); len(resp) < 4 || resp[0] != pcpVersion || resp[3] != pcpUnsuppVersion {
		t.Fatalf("over IPv6: % x", resp)
	}
}
