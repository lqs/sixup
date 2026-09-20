package main

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/insomniacslk/dhcp/rfc1035label"
	"golang.org/x/net/ipv6"
)

// Lease is one DHCPv6 IA_NA binding keyed by DUID+IAID, persisted to disk.
// serverMode is what -dhcp6s-mode selects. Stateless answers Information-Request only; stateful
// also hands out addresses and keeps leases.
type serverMode string

const (
	serverOff       serverMode = "off"
	serverStateless serverMode = "stateless"
	serverStateful  serverMode = "stateful"
)

type Lease struct {
	DUID      string     `json:"duid"`
	IAID      uint32     `json:"iaid"`
	Addr      netip.Addr `json:"addr"`
	Expires   time.Time  `json:"expires"`
	MAC       string     `json:"mac,omitempty"`
	Hostname  string     `json:"hostname,omitempty"`
	Peer      netip.Addr `json:"peer"` // client link-local, needed for Reconfigure
	ReconfKey string     `json:"reconf_key,omitempty"`
}

type staticBind struct {
	mac  string
	duid string
	addr netip.Addr // full address, or an IID when only the low 64 bits are set
}

// dhcpServer is the optional LAN-side DHCPv6 server.
type dhcpServer struct {
	ifname    string
	ifi       *net.Interface
	pc        *ipv6.PacketConn
	stateful  bool
	duid      dhcpv6.DUID
	leaseFile string
	statics   []staticBind
	poolStart uint64
	poolEnd   uint64
	preferred time.Duration
	valid     time.Duration
	dns       []netip.Addr

	mu     sync.Mutex
	snap   Snapshot
	leases map[string]*Lease
}

func leaseKey(duid string, iaid uint32) string { return fmt.Sprintf("%s/%d", duid, iaid) }

func (s *dhcpServer) run(ctx context.Context, hub *linkHub, store *Store, ch <-chan Snapshot) {
	s.loadLeases()
	hub.supervise(ctx, s.ifname, func(cctx context.Context, ifi *net.Interface) {
		s.mu.Lock()
		s.ifi = ifi
		s.snap = store.Current()
		s.mu.Unlock()
		s.serve(cctx, ch)
	})
}

func (s *dhcpServer) serve(ctx context.Context, ch <-chan Snapshot) {
	lc := net.ListenConfig{Control: reusePort}
	pconn, err := lc.ListenPacket(ctx, "udp6", "[::]:547")
	if err != nil {
		log.Printf("[dhcpv6-server %s] listen on 547 failed: %v", s.ifname, err)
		return
	}
	conn := pconn.(*net.UDPConn)
	defer conn.Close()
	pc := ipv6.NewPacketConn(conn)
	if err := pc.JoinGroup(s.ifi, &net.UDPAddr{IP: allRouters.AsSlice()}); err != nil {
		log.Printf("[dhcpv6-server %s] join ff02::1:2 failed: %v", s.ifname, err)
		return
	}
	pc.SetControlMessage(ipv6.FlagInterface, true)
	s.mu.Lock()
	s.pc = pc
	s.mu.Unlock()
	go s.reader(pc)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			s.saveLeases()
			s.mu.Unlock()
			return
		case snap := <-ch:
			s.mu.Lock()
			old := s.snap
			s.snap = snap
			s.mu.Unlock()
			if snap.Change == "revoke" || snap.Change == "add" {
				s.onPrefixChange(old)
			}
		case <-tick.C:
			s.expireLeases()
		}
	}
}

func (s *dhcpServer) reader(pc *ipv6.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, cm, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if cm == nil || cm.IfIndex != s.ifi.Index {
			continue
		}
		msg, err := dhcpv6.MessageFromBytes(buf[:n])
		if err != nil {
			log2("[dhcpv6-server %s] parse failed: %v", s.ifname, err)
			continue
		}
		udp, ok := src.(*net.UDPAddr)
		if !ok {
			continue
		}
		peer, _ := netip.AddrFromSlice(udp.IP)
		if resp := s.handle(msg, peer.Unmap()); resp != nil {
			if _, err := pc.WriteTo(resp.ToBytes(), &ipv6.ControlMessage{IfIndex: s.ifi.Index}, udp); err != nil {
				log2("[dhcpv6-server %s] send failed: %v", s.ifname, err)
			}
		}
	}
}

// activePrefix returns the prefix currently used for assignment on this LAN, preferring GUA over ULA.
func (s *dhcpServer) activePrefix() (Prefix, bool) {
	var ula *Prefix
	for _, p := range s.snap.LAN[s.ifname] {
		if p.Deprecated {
			continue
		}
		if p.Source == "ula" {
			if ula == nil {
				q := p
				ula = &q
			}
			continue
		}
		return p, true
	}
	if ula != nil {
		return *ula, true
	}
	return Prefix{}, false
}

func (s *dhcpServer) handle(msg *dhcpv6.Message, peer netip.Addr) *dhcpv6.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	cid := msg.Options.ClientID()
	if cid == nil {
		return nil
	}
	sid := msg.Options.ServerID()
	switch msg.MessageType {
	case dhcpv6.MessageTypeSolicit, dhcpv6.MessageTypeRebind, dhcpv6.MessageTypeConfirm, dhcpv6.MessageTypeInformationRequest:
		if sid != nil && !sid.Equal(s.duid) {
			return nil
		}
	default:
		if sid == nil || !sid.Equal(s.duid) {
			return nil
		}
	}
	resp, _ := dhcpv6.NewMessage()
	resp.MessageType = dhcpv6.MessageTypeReply
	resp.TransactionID = msg.TransactionID
	resp.AddOption(dhcpv6.OptServerID(s.duid))
	resp.AddOption(dhcpv6.OptClientID(cid))
	s.addInfo(resp)
	duidHex := hex.EncodeToString(cid.ToBytes())
	wantsReconf := msg.Options.GetOne(optionReconfAccept) != nil

	switch msg.MessageType {
	case dhcpv6.MessageTypeInformationRequest:
		return resp
	case dhcpv6.MessageTypeSolicit:
		if !s.stateful {
			// Stateless mode: answer IA_NA with NoAddrsAvail
			if len(msg.Options.IANA()) > 0 {
				resp.MessageType = dhcpv6.MessageTypeAdvertise
				for _, ia := range msg.Options.IANA() {
					resp.AddOption(s.iaStatus(ia.IaId, iana.StatusNoAddrsAvail, "stateless only"))
				}
				return resp
			}
			return nil
		}
		rapid := msg.Options.GetOne(dhcpv6.OptionRapidCommit) != nil
		if rapid {
			resp.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionRapidCommit})
		} else {
			resp.MessageType = dhcpv6.MessageTypeAdvertise
		}
		for _, ia := range msg.Options.IANA() {
			resp.AddOption(s.assign(duidHex, ia, cid, peer, msg, rapid, wantsReconf))
		}
		return resp
	case dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeRenew, dhcpv6.MessageTypeRebind:
		if !s.stateful {
			for _, ia := range msg.Options.IANA() {
				resp.AddOption(s.iaStatus(ia.IaId, iana.StatusNoAddrsAvail, "stateless only"))
			}
			return resp
		}
		for _, ia := range msg.Options.IANA() {
			resp.AddOption(s.assign(duidHex, ia, cid, peer, msg, true, wantsReconf))
		}
		for _, ia := range msg.Options.IAPD() {
			resp.AddOption(&dhcpv6.OptIAPD{IaId: ia.IaId, Options: dhcpv6.PDOptions{Options: dhcpv6.Options{&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoPrefixAvail, StatusMessage: "downstream PD not supported"}}}})
		}
		if wantsReconf {
			s.addReconfKey(resp, duidHex)
		}
		s.saveLeases()
		return resp
	case dhcpv6.MessageTypeConfirm:
		onlink := true
		for _, ia := range msg.Options.IANA() {
			for _, a := range ia.Options.Addresses() {
				addr, ok := netip.AddrFromSlice(a.IPv6Addr)
				if !ok {
					continue
				}
				if p, ok := s.activePrefix(); !ok || !p.Prefix.Contains(addr.Unmap()) {
					onlink = false
				}
			}
		}
		st := &dhcpv6.OptStatusCode{StatusCode: iana.StatusSuccess, StatusMessage: "all addresses on link"}
		if !onlink {
			st = &dhcpv6.OptStatusCode{StatusCode: iana.StatusNotOnLink, StatusMessage: "prefix changed"}
		}
		resp.AddOption(st)
		return resp
	case dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeDecline:
		for _, ia := range msg.Options.IANA() {
			delete(s.leases, leaseKey(duidHex, binary.BigEndian.Uint32(ia.IaId[:])))
		}
		resp.AddOption(&dhcpv6.OptStatusCode{StatusCode: iana.StatusSuccess, StatusMessage: "released"})
		s.saveLeases()
		return resp
	}
	return nil
}

func (s *dhcpServer) iaStatus(iaid [4]byte, code iana.StatusCode, text string) *dhcpv6.OptIANA {
	ia := &dhcpv6.OptIANA{IaId: iaid}
	ia.Options.Add(&dhcpv6.OptStatusCode{StatusCode: code, StatusMessage: text})
	return ia
}

// addInfo appends DNS and search list from upstream or the config override.
func (s *dhcpServer) addInfo(resp *dhcpv6.Message) {
	dns := s.dns
	if len(dns) == 0 {
		dns = routableDNS(s.snap.DNS)
	}
	if len(dns) > 0 {
		var ips []net.IP
		for _, d := range dns {
			ips = append(ips, d.AsSlice())
		}
		resp.AddOption(dhcpv6.OptDNS(ips...))
	}
	if len(s.snap.DNSSL) > 0 {
		resp.AddOption(dhcpv6.OptDomainSearchList(labelsFrom(s.snap.DNSSL)))
	}
}

// assign renews an existing binding while its prefix is valid, else allocates; addresses on stale prefixes are returned with lifetime 0.
func (s *dhcpServer) assign(duidHex string, ia *dhcpv6.OptIANA, cid dhcpv6.DUID, peer netip.Addr, msg *dhcpv6.Message, commit, wantsReconf bool) *dhcpv6.OptIANA {
	iaid := binary.BigEndian.Uint32(ia.IaId[:])
	now := time.Now()
	out := &dhcpv6.OptIANA{IaId: ia.IaId}
	p, ok := s.activePrefix()
	if !ok {
		out.Options.Add(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoAddrsAvail, StatusMessage: "no active prefix"})
		return out
	}
	// Explicitly invalidate client-supplied addresses outside the current prefix
	for _, a := range ia.Options.Addresses() {
		addr, ok := netip.AddrFromSlice(a.IPv6Addr)
		if ok && !p.Prefix.Contains(addr.Unmap()) {
			out.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: a.IPv6Addr, PreferredLifetime: 0, ValidLifetime: 0})
		}
	}
	key := leaseKey(duidHex, iaid)
	l := s.leases[key]
	if l != nil && !p.Prefix.Contains(l.Addr) {
		l = nil
	}
	if msg.MessageType == dhcpv6.MessageTypeRenew && l == nil {
		out.Options.Add(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoBinding, StatusMessage: "no binding"})
		return out
	}
	if l == nil {
		addr, ok := s.allocate(p.Prefix, duidHex, iaid, cid, msg)
		if !ok {
			out.Options.Add(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoAddrsAvail, StatusMessage: "pool exhausted"})
			return out
		}
		l = &Lease{DUID: duidHex, IAID: iaid, Addr: addr, MAC: macFromDUID(cid, msg)}
	}
	pref, valid := s.preferred, s.valid
	if left := p.preferredLeft(now); left < pref {
		pref = left
	}
	if left := p.validLeft(now); left < valid {
		valid = left
	}
	if pref > valid {
		pref = valid
	}
	out.T1 = pref / 2
	out.T2 = pref * 8 / 10
	out.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: l.Addr.AsSlice(), PreferredLifetime: pref, ValidLifetime: valid})
	if commit {
		l.Expires = now.Add(valid)
		l.Peer = peer
		if fq := msg.Options.FQDN(); fq != nil && fq.DomainName != nil && len(fq.DomainName.Labels) > 0 {
			l.Hostname = fq.DomainName.Labels[0]
		}
		if wantsReconf && l.ReconfKey == "" {
			k := make([]byte, 16)
			rand.Read(k)
			l.ReconfKey = hex.EncodeToString(k)
		}
		s.leases[key] = l
	}
	return out
}

func (s *dhcpServer) addReconfKey(resp *dhcpv6.Message, duidHex string) {
	for _, l := range s.leases {
		if l.DUID != duidHex || l.ReconfKey == "" {
			continue
		}
		k, _ := hex.DecodeString(l.ReconfKey)
		a := make([]byte, 28)
		a[0], a[1], a[2] = 3, 1, 0
		a[11] = 1
		copy(a[12:], k)
		resp.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionAuth, OptionData: a})
		return
	}
}

// allocate checks static bindings first, then hashes DUID+IAID into the pool with linear probing on collision.
func (s *dhcpServer) allocate(prefix netip.Prefix, duidHex string, iaid uint32, cid dhcpv6.DUID, msg *dhcpv6.Message) (netip.Addr, bool) {
	mac := macFromDUID(cid, msg)
	for _, st := range s.statics {
		if (st.duid != "" && st.duid == duidHex) || (st.mac != "" && strings.EqualFold(st.mac, mac)) {
			b := st.addr.As16()
			if b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 {
				pb := prefix.Masked().Addr().As16()
				copy(b[:8], pb[:8])
			}
			return netip.AddrFrom16(b), true
		}
	}
	used := map[netip.Addr]bool{}
	for _, l := range s.leases {
		used[l.Addr] = true
	}
	for _, st := range s.statics {
		used[st.addr] = true
	}
	size := s.poolEnd - s.poolStart + 1
	h := fnv.New64a()
	h.Write([]byte(duidHex))
	binary.Write(h, binary.BigEndian, iaid)
	start := h.Sum64() % size
	pb := prefix.Masked().Addr().As16()
	for i := uint64(0); i < size; i++ {
		iid := s.poolStart + (start+i)%size
		b := pb
		binary.BigEndian.PutUint64(b[8:], iid)
		a := netip.AddrFrom16(b)
		if !used[a] {
			return a, true
		}
	}
	return netip.Addr{}, false
}

func macFromDUID(d dhcpv6.DUID, msg *dhcpv6.Message) string {
	switch x := d.(type) {
	case *dhcpv6.DUIDLLT:
		return x.LinkLayerAddr.String()
	case *dhcpv6.DUIDLL:
		return x.LinkLayerAddr.String()
	}
	if o := msg.Options.GetOne(dhcpv6.OptionClientLinkLayerAddr); o != nil {
		if b := o.ToBytes(); len(b) == 8 {
			return net.HardwareAddr(b[2:]).String()
		}
	}
	return ""
}

// onPrefixChange sends Reconfigure(Renew) to leases on the old prefix so clients fetch new addresses immediately.
func (s *dhcpServer) onPrefixChange(old Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.activePrefix()
	for key, l := range s.leases {
		if ok && p.Prefix.Contains(l.Addr) {
			continue
		}
		if l.ReconfKey == "" || !l.Peer.IsValid() {
			delete(s.leases, key)
			continue
		}
		s.sendReconfigure(l)
	}
	s.saveLeases()
}

func (s *dhcpServer) sendReconfigure(l *Lease) {
	raw, ok := buildReconfigure(s.duid, l, time.Now())
	if !ok {
		return
	}
	dst := &net.UDPAddr{IP: l.Peer.AsSlice(), Port: 546, Zone: s.ifname}
	if _, err := s.pc.WriteTo(raw, &ipv6.ControlMessage{IfIndex: s.ifi.Index}, dst); err != nil {
		log2("[dhcpv6-server %s] send Reconfigure to %s failed: %v", s.ifname, l.Peer, err)
		return
	}
	log.Printf("[dhcpv6-server %s] sent Reconfigure to %s", s.ifname, l.Peer)
}

// buildReconfigure signs a Reconfigure(Renew) with the lease's RKAP key (RFC 8415 §20.4).
// The HMAC-MD5 covers the whole message with the value field zeroed, then is written in place.
func buildReconfigure(serverID dhcpv6.DUID, l *Lease, now time.Time) ([]byte, bool) {
	duid, err := hex.DecodeString(l.DUID)
	if err != nil {
		return nil, false
	}
	cid, err := dhcpv6.DUIDFromBytes(duid)
	if err != nil {
		return nil, false
	}
	key, err := hex.DecodeString(l.ReconfKey)
	if err != nil || len(key) == 0 {
		return nil, false
	}
	msg, _ := dhcpv6.NewMessage()
	msg.MessageType = dhcpv6.MessageTypeReconfigure
	msg.AddOption(dhcpv6.OptServerID(serverID))
	msg.AddOption(dhcpv6.OptClientID(cid))
	msg.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionReconfMessage, OptionData: []byte{byte(dhcpv6.MessageTypeRenew)}})
	a := make([]byte, 28)
	a[0], a[1], a[2] = 3, 1, 0 // protocol RKAP, algorithm HMAC-MD5, RDM monotonic
	binary.BigEndian.PutUint64(a[3:11], uint64(now.UnixNano()))
	a[11] = 2 // type: HMAC-MD5 digest
	msg.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionAuth, OptionData: a})
	raw := msg.ToBytes()
	idx := findAuthValue(raw)
	if idx < 0 {
		return nil, false
	}
	mac := hmac.New(md5.New, key)
	mac.Write(raw)
	copy(raw[idx:], mac.Sum(nil))
	return raw, true
}

func (s *dhcpServer) expireLeases() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	changed := false
	for k, l := range s.leases {
		if now.After(l.Expires) {
			delete(s.leases, k)
			changed = true
		}
	}
	if changed {
		s.saveLeases()
	}
}

func (s *dhcpServer) loadLeases() {
	s.leases = map[string]*Lease{}
	b, err := os.ReadFile(s.leaseFile)
	if err != nil {
		return
	}
	var list []*Lease
	if err := json.Unmarshal(b, &list); err != nil {
		log.Printf("[dhcpv6-server] lease file corrupt, ignoring: %v", err)
		return
	}
	for _, l := range list {
		s.leases[leaseKey(l.DUID, l.IAID)] = l
	}
	log.Printf("[dhcpv6-server %s] loaded %d leases", s.ifname, len(list))
}

// saveLeases requires the caller to hold the lock.
func (s *dhcpServer) saveLeases() {
	if s.leaseFile == "" {
		return
	}
	list := s.leaseList()
	b, _ := json.MarshalIndent(list, "", "  ")
	tmp := s.leaseFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log2("[dhcpv6-server] write leases failed: %v", err)
		return
	}
	os.Rename(tmp, s.leaseFile)
}

func (s *dhcpServer) leaseList() []*Lease {
	list := make([]*Lease, 0, len(s.leases))
	for _, l := range s.leases {
		list = append(list, l)
	}
	slices.SortFunc(list, func(a, b *Lease) int { return a.Addr.Compare(b.Addr) })
	return list
}

func labelsFrom(names []string) *rfc1035label.Labels {
	return &rfc1035label.Labels{Labels: names}
}

func serverDUID(ctx context.Context, c *dhcpClient, stateDir, wan string) dhcpv6.DUID {
	if c != nil {
		for c.duid == nil {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(200 * time.Millisecond):
			}
		}
		return c.duid
	}
	tmp := newDHCPClient(wan, nil, stateDir, 0, false)
	if tmp.ifi = waitIface(ctx, wan); tmp.ifi == nil {
		return nil
	}
	if err := tmp.loadDUID(); err != nil {
		log.Printf("[dhcpv6-server] DUID: %v", err)
		return nil
	}
	return tmp.duid
}

// runDry only runs the DHCPv6 client and the upstream RA listener and prints the parameters it gets as JSON.
