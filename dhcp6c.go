package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

// RFC 8415 §7.6 transmission parameters
var (
	solParams = retransParams{irt: time.Second, mrt: 3600 * time.Second}
	reqParams = retransParams{irt: time.Second, mrt: 30 * time.Second, mrc: 10}
	renParams = retransParams{irt: 10 * time.Second, mrt: 600 * time.Second}
	rebParams = retransParams{irt: 10 * time.Second, mrt: 600 * time.Second}
	infParams = retransParams{irt: time.Second, mrt: 3600 * time.Second}
	relParams = retransParams{irt: time.Second, mrc: 5}
	decParams = retransParams{irt: time.Second, mrc: 5}
)

// clientMode is what -dhcp6c-mode selects: auto follows the M and O bits of the upstream RA.
type clientMode string

const (
	clientAuto clientMode = "auto"
	clientOn   clientMode = "on"
	clientOff  clientMode = "off"
)

type retransParams struct {
	irt, mrt, mrd time.Duration
	mrc           int
}

var (
	errLinkDown  = errors.New("link down")
	errReconfirm = errors.New("reconfirm needed")
	errTimeout   = errors.New("retransmissions exhausted")
	errNoPrefix  = errors.New("server replied NoPrefixAvail")
)

const optionReconfAccept dhcpv6.OptionCode = 20

// passedOn are the options of the upstream that the LAN's DHCPv6 server hands on as they came, for
// the hosts that ask (RFC 7084 L-12): the SIP servers of RFC 3319, the last of the configuration
// options RFC 3736 section 5.3 lists. DNS and NTP are read instead, as the RA and the config
// overrides need them too.
var passedOn = []dhcpv6.OptionCode{dhcpv6.OptionSIPServersDomainNameList, dhcpv6.OptionSIPServersIPv6AddressList}

// dhcpOption is an option of the upstream kept as it came.
type dhcpOption struct {
	Code dhcpv6.OptionCode `json:"code"`
	Data []byte            `json:"data"`
}

func (o dhcpOption) equal(p dhcpOption) bool { return o.Code == p.Code && bytes.Equal(o.Data, p.Data) }

var allRouters = netip.MustParseAddr("ff02::1:2")

// dhcpClient is the WAN-side DHCPv6 client, the information source for the whole process.
type dhcpClient struct {
	ifname   string
	ifi      *net.Interface
	store    *Store
	stateDir string
	pdLen    int  // IA_PD length hint; 0 means no PD request
	unhinted bool // the hint was refused; SOLICIT with an empty IA_PD until the next backoff
	wantNA   bool // request IA_NA
	infoOnly bool // Information-Request only (upstream RA has only O bit and PD probing failed)
	raOther  bool // upstream RA set only the O bit

	duid      dhcpv6.DUID
	iaid      [4]byte
	conn      *net.UDPConn
	recv      chan *dhcpv6.Message
	link      chan linkEvent
	reconfirm chan string  // fired when upstream RA prefixes change; REBIND to reconfirm PD
	start     chan raFlags // fired on first upstream RA, carrying the M/O bits

	linkUp    bool
	solMaxRT  time.Duration
	infMaxRT  time.Duration
	serverID  dhcpv6.DUID
	reconfKey []byte
	reconfig  chan dhcpv6.MessageType

	naAddrs []netip.Addr // IA_NA addresses configured on the WAN interface
	fresh   []netip.Addr // those the last Reply added, whose DAD is still to be seen
	pub     SourceUpdate // what was last published to the Store

	// Backoff after an explicit NoPrefixAvail: starts at 5 min, doubles, capped at 1 h, reset on binding
	refuseBackoff time.Duration

	done      chan struct{} // closed after run returns (including RELEASE on exit)
	releaseOn bool          // RELEASE on exit; dry-run always releases, normal mode keeps the binding for prefix stability
}

func newDHCPClient(ifname string, store *Store, stateDir string, pdLen int, wantNA bool) *dhcpClient {
	return &dhcpClient{
		ifname:    ifname,
		store:     store,
		stateDir:  stateDir,
		pdLen:     pdLen,
		wantNA:    wantNA,
		recv:      make(chan *dhcpv6.Message, 16),
		link:      make(chan linkEvent, 8),
		reconfirm: make(chan string, 1),
		start:     make(chan raFlags, 1),
		reconfig:  make(chan dhcpv6.MessageType, 1),
		done:      make(chan struct{}),
		solMaxRT:  solParams.mrt,
		infMaxRT:  infParams.mrt,
		linkUp:    true,
	}
}

// Reconfirm is called when the upstream link may have changed (RA prefix set changed).
// In BOUND it skips RENEW and goes straight to REBIND so any server can confirm the prefix.
// Ignored when not bound: SOLICIT is in progress and will fetch a fresh prefix anyway.
func (c *dhcpClient) Reconfirm(reason string) {
	select {
	case c.reconfirm <- reason:
	default:
	}
}

func (c *dhcpClient) loadDUID() error {
	p := filepath.Join(c.stateDir, "duid")
	if b, err := os.ReadFile(p); err == nil {
		raw, err := hex.DecodeString(string(trimSpace(b)))
		if err == nil {
			if d, err := dhcpv6.DUIDFromBytes(raw); err == nil {
				c.duid = d
				return nil
			}
		}
		warnf("[dhcpv6-client] state file %s corrupt, regenerating DUID", p)
	}
	// ppp interfaces (PPPoE) have no MAC; use 6 random bytes, persisted with the DUID in normal mode
	hw := c.ifi.HardwareAddr
	if len(hw) == 0 {
		hw = make(net.HardwareAddr, 6)
		crand.Read(hw)
		hw[0] = hw[0]&0xfe | 0x02
		warnf("[dhcpv6-client] interface %s has no MAC (PPPoE?), DUID uses a random link-layer address", c.ifname)
	}
	if dryRun {
		// Stable without persisting: DUID-LL from MAC only, so repeated dry-runs look like one client
		// to the server; otherwise each run burns a /64 until the pool answers NoPrefixAvail
		c.duid = &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: hw}
		infof("[dhcpv6-client] dry-run, using MAC-derived stable DUID %s, not persisted", c.duid)
		return nil
	}
	c.duid = &dhcpv6.DUIDLLT{
		HWType:        iana.HWTypeEthernet,
		Time:          uint32(time.Now().Unix() - 946684800),
		LinkLayerAddr: hw,
	}
	os.MkdirAll(c.stateDir, 0o755)
	if err := os.WriteFile(p, []byte(hex.EncodeToString(c.duid.ToBytes())+"\n"), 0o600); err != nil {
		return err
	}
	infof("[dhcpv6-client] generated new DUID %s", c.duid)
	return nil
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func (c *dhcpClient) openSocket() error {
	if old := c.conn; old != nil {
		// Clear the reference before closing so the old reader sees conn != c.conn and does not report link down
		c.conn = nil
		old.Close()
	}
	ll, err := linkLocalOf(c.ifi)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: ll.AsSlice(), Port: 546, Zone: c.ifi.Name})
	if err != nil {
		return err
	}
	c.conn = conn
	go c.reader(conn)
	return nil
}

func linkLocalOf(ifi *net.Interface) (netip.Addr, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Is6() && ip.IsLinkLocalUnicast() {
				return ip.Unmap(), nil
			}
		}
	}
	return netip.Addr{}, errors.New("interface has no link-local address")
}

func (c *dhcpClient) reader(conn *net.UDPConn) {
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if conn == c.conn {
				select {
				case c.link <- linkEvent{Name: c.ifname, Up: false}:
				default:
				}
			}
			return
		}
		msg, err := dhcpv6.MessageFromBytes(buf[:n])
		if err != nil {
			debugf("[dhcpv6-client] packet parse failed: %v", err)
			continue
		}
		statInc(strings.ToLower(msg.MessageType.String()) + "_recv")
		debugf("[dhcpv6-client] received %s", msg.MessageType)
		if debugEnabled() {
			// Dump all options: IA_PD/IA_NA addresses and lifetimes, DNS, tunnel options, status codes
			for _, line := range strings.Split(strings.TrimRight(msg.LongString(2), "\n"), "\n") {
				debugf("[dhcpv6-client]   %s", line)
			}
			// The library prints tunnel options as raw bytes; add a parsed line
			if t := parseTunnel(msg); t != nil {
				extra := ""
				if t.MAPE != nil {
					extra = " MAPE=" + s46Env(t.MAPE)
				}
				debugf("[dhcpv6-client]   tunnel options: AFTR=%q%s parse errors=%v", t.AFTRName, extra, t.Errors)
			}
		}
		select {
		case c.recv <- msg:
		default:
		}
	}
}

func (c *dhcpClient) send(msg *dhcpv6.Message) error {
	if c.conn == nil {
		if err := c.openSocket(); err != nil {
			return err
		}
	}
	_, err := c.conn.WriteToUDP(msg.ToBytes(), &net.UDPAddr{IP: allRouters.AsSlice(), Port: 547, Zone: c.ifi.Name})
	if err != nil {
		old := c.conn
		c.conn = nil
		old.Close()
	}
	return err
}

func (c *dhcpClient) run(ctx context.Context, wait bool) {
	defer close(c.done)
	if c.ifi = waitIface(ctx, c.ifname); c.ifi == nil {
		return
	}
	c.iaid = iaidFor(c.ifi)
	for c.loadDUID() != nil {
		warnf("[dhcpv6-client] writing DUID failed, retrying in 5s")
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
	if wait {
		infof("[dhcpv6-client] waiting for upstream RA M/O flags before starting")
		select {
		case <-ctx.Done():
			return
		case f := <-c.start:
			switch {
			case f.managed:
				infof("[dhcpv6-client] upstream RA has M bit, starting in stateful mode")
			case f.other:
				// O bit only calls for Information-Request, but Japanese IPoE often serves PD on O-only lines
				c.raOther = true
				infof("[dhcpv6-client] upstream RA has only O bit, still requesting IA_PD (falling back to Information-Request if none)")
			default:
				infof("[dhcpv6-client] upstream RA has no M/O bits, RFC says no DHCPv6 needed; still probing PD with SOLICIT, retrying silently with backoff if unanswered")
			}
		case <-time.After(8 * time.Second):
			warnf("[dhcpv6-client] no upstream RA within 8s, starting in stateful mode")
		}
	}
	for ctx.Err() == nil {
		c.cycle(ctx)
	}
}

func padMAC(hw net.HardwareAddr) []byte {
	b := make([]byte, 4)
	if len(hw) >= 4 {
		copy(b, hw[len(hw)-4:])
	}
	return b
}

// iaidFor uses the last 4 MAC bytes as IAID. An interface without a MAC, such as ppp0, takes the
// first 4 bytes of the MD5 of its name, as OpenWrt's odhcp6c does: the index would change with
// every redial, and with it the prefix (RFC 9096 WPD-10).
func iaidFor(ifi *net.Interface) [4]byte {
	var id [4]byte
	if len(ifi.HardwareAddr) >= 4 {
		copy(id[:], padMAC(ifi.HardwareAddr))
		return id
	}
	sum := md5.Sum([]byte(ifi.Name))
	copy(id[:], sum[:4])
	return id
}

// waitLinkUp blocks until the link is back, re-resolves the interface (index changes on recreation) and reopens the socket.
// The old socket is bound to the old link-local address and is unusable after recreation.
func (c *dhcpClient) waitLinkUp(ctx context.Context) {
	for !c.linkUp {
		select {
		case <-ctx.Done():
			return
		case ev := <-c.link:
			c.linkUp = ev.Up
		}
	}
	for {
		ifi := waitIface(ctx, c.ifname)
		if ifi == nil {
			return
		}
		c.ifi = ifi
		if err := c.openSocket(); err == nil {
			return
		} else {
			// link-local may still be in DAD; retry shortly
			debugf("[dhcpv6-client] opening socket failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// rejoinParams are Confirm's, which RFC 8415 section 18.2.12 gives the Rebind after a link change.
var rejoinParams = retransParams{irt: time.Second, mrt: 4 * time.Second}

// rejoin keeps the binding while the link is down, and confirms it once the link is back (RFC 8415
// section 18.2.12), so that a modem restarting does not renumber the LAN: with a Rebind while
// there is a delegation, else with a Confirm of the addresses. Without a Reply within 10 s the
// binding is kept as it was. It returns the binding, or nil once it is gone: it expired while the
// link was down, the server took it back or said the addresses are not on this link, or ctx ended.
func (c *dhcpClient) rejoin(ctx context.Context, l *lease) *lease {
	for {
		infof("[dhcpv6-client] link down, keeping the binding until %s", l.valid.Format(time.TimeOnly))
		wctx, cancel := context.WithDeadline(ctx, l.valid)
		c.waitLinkUp(wctx)
		cancel()
		if !c.linkUp || ctx.Err() != nil {
			return nil
		}
		// the link going down flushed the addresses; they are still ours until a Reply says otherwise
		for _, a := range l.addrs {
			if life := l.addrLife[a]; time.Until(life[1]) > 0 {
				if err := addrSet(c.ifi.Index, a, 128, time.Until(life[0]), time.Until(life[1]), false, 0); err != nil {
					errorf("[dhcpv6-client] restoring WAN address %s failed: %v", a, err)
				}
			}
		}
		mt := dhcpv6.MessageTypeRebind
		if len(l.prefixes) == 0 {
			mt = dhcpv6.MessageTypeConfirm
		}
		var reply *dhcpv6.Message
		var err error
		if mt == dhcpv6.MessageTypeConfirm {
			reply, err = c.confirm(ctx, l)
		} else {
			reply, err = c.renewOrRebind(ctx, mt, rejoinParams, 10*time.Second, l)
		}
		switch {
		case err == nil && mt == dhcpv6.MessageTypeConfirm:
			if st := reply.Options.Status(); st != nil && st.StatusCode == iana.StatusNotOnLink {
				infof("[dhcpv6-client] link back, the server says the addresses are not on this link, back to SOLICIT")
				return nil
			}
			infof("[dhcpv6-client] link back, the server confirmed the addresses")
			return l
		case err == nil:
			return c.bind(ctx, reply)
		case errors.Is(err, errLinkDown):
			continue
		case errors.Is(err, errTimeout):
			infof("[dhcpv6-client] link back, no server answered the %s, keeping the binding", mt)
			return l
		}
		return nil
	}
}

// cycle runs one full SOLICIT -> REQUEST -> BOUND -> RENEW/REBIND lifecycle.
func (c *dhcpClient) cycle(ctx context.Context) {
	c.waitLinkUp(ctx)
	if ctx.Err() != nil {
		return
	}
	if c.infoOnly {
		c.infoCycle(ctx)
		return
	}
	adv, err := c.solicit(ctx)
	if errors.Is(err, errNoPrefix) {
		if c.retryUnhinted() {
			return
		}
		statInc("pd_refused")
		c.store.Set("pd", SourceUpdate{})
		if c.fallbackInfo() {
			// O-only line: PD refused, switch to Information-Request for DNS right away without backoff
			return
		}
		c.refusedWait(ctx, "server replied NoPrefixAvail / NoAddrsAvail")
		return
	}
	if err != nil {
		c.onExchangeErr(err)
		if ctx.Err() == nil {
			c.fallbackInfo()
		}
		return
	}
	c.serverID = adv.Options.ServerID()
	reply, err := c.request(ctx, adv)
	if err != nil {
		c.onExchangeErr(err)
		return
	}
	lease := c.bind(ctx, reply)
	if lease == nil {
		if refusesEverything(reply) {
			if c.retryUnhinted() {
				return
			}
			statInc("pd_refused")
			if c.fallbackInfo() {
				return
			}
			c.refusedWait(ctx, "REPLY refused every IA")
			return
		}
		c.fallbackInfo()
		warnf("[dhcpv6-client] server gave no binding, retrying in 10s")
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
		}
		return
	}
	c.refuseBackoff = 0
	for {
		reason := c.waitBound(ctx, lease.t1)
		switch reason {
		case "ctx":
			if c.releaseOn || dryRun {
				c.release(lease)
			} else {
				infof("[dhcpv6-client] exiting, keeping DHCPv6 binding (-dhcp6c-release to release instead)")
			}
			return
		case "down":
			if lease = c.rejoin(ctx, lease); lease == nil {
				if ctx.Err() == nil {
					c.clearLease()
				}
				return
			}
			continue
		}
		mrd := time.Until(lease.t2)
		if mrd < time.Second {
			mrd = time.Second
		}
		if reason == "reconfirm" {
			// Link may have changed; RENEW to the old server is pointless, go straight to REBIND
			err = errReconfirm
		} else {
			reply, err = c.renewOrRebind(ctx, dhcpv6.MessageTypeRenew, renParams, mrd, lease)
		}
		if err == nil {
			if l := c.bind(ctx, reply); l != nil {
				lease = l
				continue
			}
			c.clearLease()
			return
		}
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errLinkDown) {
			if lease = c.rejoin(ctx, lease); lease == nil {
				if ctx.Err() == nil {
					c.clearLease()
				}
				return
			}
			continue
		}
		mrd = time.Until(lease.valid)
		if mrd < time.Second {
			mrd = time.Second
		}
		if reason == "reconfirm" {
			// Reconfirm need not wait for valid expiry; no reply within 30s means the prefix is gone
			mrd = 30 * time.Second
		}
		reply, err = c.renewOrRebind(ctx, dhcpv6.MessageTypeRebind, rebParams, mrd, lease)
		if err == nil {
			if l := c.bind(ctx, reply); l != nil {
				lease = l
				continue
			}
		}
		warnf("[dhcpv6-client] REBIND failed: %v, back to SOLICIT", err)
		c.clearLease()
		return
	}
}

func (c *dhcpClient) onExchangeErr(err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	if errors.Is(err, errLinkDown) {
		infof("[dhcpv6-client] link down, pausing")
		return
	}
	debugf("[dhcpv6-client] %v", err)
}

// waitBound waits in BOUND and returns "t1" / "reconf" / "down" / "ctx".
func (c *dhcpClient) waitBound(ctx context.Context, t1 time.Time) string {
	t := time.NewTimer(time.Until(t1))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return "ctx"
		case <-t.C:
			return "t1"
		case why := <-c.reconfirm:
			infof("[dhcpv6-client] %s, REBIND to reconfirm PD", why)
			return "reconfirm"
		case mt := <-c.reconfig:
			infof("[dhcpv6-client] received Reconfigure(%s)", mt)
			return "reconf"
		case ev := <-c.link:
			c.linkUp = ev.Up
			if !ev.Up {
				return "down"
			}
		case msg := <-c.recv:
			c.handleUnsolicited(msg)
		}
	}
}

// handleUnsolicited handles Reconfigure while BOUND.
func (c *dhcpClient) handleUnsolicited(msg *dhcpv6.Message) {
	if msg.MessageType != dhcpv6.MessageTypeReconfigure {
		return
	}
	if !c.verifyReconfigure(msg) {
		warnf("[dhcpv6-client] Reconfigure verification failed, dropped")
		return
	}
	mt := dhcpv6.MessageTypeRenew
	if o := msg.Options.GetOne(dhcpv6.OptionReconfMessage); o != nil {
		if b := o.ToBytes(); len(b) == 1 {
			mt = dhcpv6.MessageType(b[0])
		}
	}
	select {
	case c.reconfig <- mt:
	default:
	}
}

// verifyReconfigure checks Reconfigure Key authentication per RFC 8415 §20.4.
func (c *dhcpClient) verifyReconfigure(msg *dhcpv6.Message) bool {
	if c.serverID == nil || msg.Options.ServerID() == nil || !c.serverID.Equal(msg.Options.ServerID()) {
		return false
	}
	if cid := msg.Options.ClientID(); cid == nil || !cid.Equal(c.duid) {
		return false
	}
	if c.reconfKey == nil {
		return false
	}
	auth := msg.Options.GetOne(dhcpv6.OptionAuth)
	if auth == nil {
		return false
	}
	a := auth.ToBytes()
	// protocol(1) algorithm(1) RDM(1) replay(8) type(1) value(16)
	if len(a) != 28 || a[0] != 3 || a[1] != 1 || a[11] != 2 {
		return false
	}
	got := make([]byte, 16)
	copy(got, a[12:28])
	// Recompute with the HMAC field zeroed
	raw := msg.ToBytes()
	idx := findAuthValue(raw)
	for i := range 16 {
		raw[idx+i] = 0
	}
	mac := hmac.New(md5.New, c.reconfKey)
	mac.Write(raw)
	return hmac.Equal(mac.Sum(nil), got)
}

// findAuthValue locates the HMAC field offset of the AUTH option in the serialized message.
func findAuthValue(raw []byte) int {
	if len(raw) < 4 {
		return -1
	}
	off := -1
	walkOptionsOffset(raw[4:], func(code uint16, start, l int) {
		if code == uint16(dhcpv6.OptionAuth) && l == 28 {
			off = 4 + start + 12
		}
	})
	return off
}

func walkOptionsOffset(b []byte, fn func(code uint16, start, l int)) {
	for i := 0; i+4 <= len(b); {
		code := uint16(b[i])<<8 | uint16(b[i+1])
		l := int(b[i+2])<<8 | int(b[i+3])
		i += 4
		if i+l > len(b) {
			return
		}
		fn(code, i, l)
		i += l
	}
}

func (c *dhcpClient) baseOptions(elapsed time.Duration) []dhcpv6.Modifier {
	mods := []dhcpv6.Modifier{
		dhcpv6.WithClientID(c.duid),
		dhcpv6.WithOption(dhcpv6.OptElapsedTime(elapsed)),
		dhcpv6.WithOption(&dhcpv6.OptionGeneric{OptionCode: optionReconfAccept}),
		dhcpv6.WithRequestedOptions(append([]dhcpv6.OptionCode{
			dhcpv6.OptionDNSRecursiveNameServer, dhcpv6.OptionDomainSearchList,
			dhcpv6.OptionAFTRName, dhcpv6.OptionS46ContMapE, dhcpv6.OptionS46ContMapT, dhcpv6.OptionS46ContLW,
			dhcpv6.OptionSolMaxRT, dhcpv6.OptionInfMaxRT, dhcpv6.OptionInformationRefreshTime,
			dhcpv6.OptionNTPServer, dhcpv6.OptionSNTPServerList, dhcpv6.OptionPDExclude,
		}, passedOn...)...),
	}
	return mods
}

func (c *dhcpClient) iaOptions(lease *lease) []dhcpv6.Modifier {
	var mods []dhcpv6.Modifier
	if c.pdLen > 0 {
		pd := &dhcpv6.OptIAPD{IaId: c.iaid}
		if lease != nil {
			for _, p := range lease.prefixes {
				pd.Options.Add(&dhcpv6.OptIAPrefix{Prefix: prefixToIPNet(p.Prefix), PreferredLifetime: p.preferredLeft(time.Now()), ValidLifetime: p.validLeft(time.Now())})
			}
		} else if !c.unhinted {
			pd.Options.Add(&dhcpv6.OptIAPrefix{Prefix: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(c.pdLen, 128)}})
		}
		mods = append(mods, dhcpv6.WithOption(pd))
	}
	if c.wantNA {
		na := &dhcpv6.OptIANA{IaId: c.iaid}
		if lease != nil {
			for _, a := range lease.addrs {
				na.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: a.AsSlice()})
			}
		}
		mods = append(mods, dhcpv6.WithOption(na))
	}
	return mods
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), 128)}
}

// solicit sends SOLICIT, collects ADVERTISEs and picks the best by preference.
func (c *dhcpClient) solicit(ctx context.Context) (*dhcpv6.Message, error) {
	var best *dhcpv6.Message
	refused := 0
	p := solParams
	p.mrt = c.solMaxRT
	err := c.exchange(ctx, dhcpv6.MessageTypeSolicit, p, func(el time.Duration, tid dhcpv6.TransactionID) *dhcpv6.Message {
		mods := append(c.baseOptions(el), c.iaOptions(nil)...)
		m, _ := dhcpv6.NewMessage(mods...)
		m.MessageType = dhcpv6.MessageTypeSolicit
		m.TransactionID = tid
		return m
	}, func(m *dhcpv6.Message) (bool, bool) {
		if m.MessageType != dhcpv6.MessageTypeAdvertise || !c.forUs(m) {
			return false, false
		}
		if st := m.Options.Status(); st != nil && st.StatusCode != iana.StatusSuccess {
			// Top-level status: NoPrefixAvail / NoAddrsAvail is an explicit refusal, other errors are treated as invalid
			if st.StatusCode == iana.StatusNoPrefixAvail || st.StatusCode == iana.StatusNoAddrsAvail {
				refused++
				return true, false
			}
			return false, false
		}
		if c.pdLen > 0 && len(m.Options.IAPD()) == 0 {
			return false, false
		}
		if refusesEverything(m) {
			refused++
			return true, false
		}
		if best == nil || m.Options.Preference() > best.Options.Preference() {
			best = m
		}
		// preference 255 ends immediately, otherwise wait out this RT
		return true, best.Options.Preference() == 255
	})
	if best != nil {
		return best, nil
	}
	if refused > 0 {
		return nil, errNoPrefix
	}
	return nil, err
}

// refusesEverything reports whether an ADVERTISE/REPLY refused every IA.
func refusesEverything(m *dhcpv6.Message) bool {
	if st := m.Options.Status(); st != nil && (st.StatusCode == iana.StatusNoPrefixAvail || st.StatusCode == iana.StatusNoAddrsAvail) {
		return true
	}
	ias := 0
	for _, ia := range m.Options.IAPD() {
		ias++
		st := ia.Options.Status()
		if st == nil || st.StatusCode != iana.StatusNoPrefixAvail {
			return false
		}
	}
	for _, ia := range m.Options.IANA() {
		ias++
		st := ia.Options.Status()
		if st == nil || st.StatusCode != iana.StatusNoAddrsAvail {
			return false
		}
	}
	return ias > 0
}

// refusedWait waits after an explicit refusal, doubling the backoff up to 1 hour.
// retryUnhinted reports whether a refusal is to be retried at once without the length hint. Some
// servers refuse a length they cannot supply instead of delegating what they have, as a router
// with a /56 of its own does when asked for another /56.
func (c *dhcpClient) retryUnhinted() bool {
	if c.pdLen == 0 || c.unhinted {
		return false
	}
	c.unhinted = true
	infof("[dhcpv6-client] request with a /%d hint refused, asking again without a length hint", c.pdLen)
	return true
}

func (c *dhcpClient) refusedWait(ctx context.Context, why string) {
	c.unhinted = false // after the backoff, try the hint again
	if c.refuseBackoff == 0 {
		c.refuseBackoff = 5 * time.Minute
	} else if c.refuseBackoff < time.Hour {
		c.refuseBackoff *= 2
		if c.refuseBackoff > time.Hour {
			c.refuseBackoff = time.Hour
		}
	}
	// Tell the prefix state machine PD is settled (none) so it can use RA prefixes
	c.store.Set("pd", SourceUpdate{})
	warnf("[dhcpv6-client] %s, retrying in %s (unaffected while upstream RA prefixes exist)", why, c.refuseBackoff)
	select {
	case <-ctx.Done():
	case <-time.After(c.refuseBackoff):
	}
}

func (c *dhcpClient) request(ctx context.Context, adv *dhcpv6.Message) (*dhcpv6.Message, error) {
	var reply *dhcpv6.Message
	err := c.exchange(ctx, dhcpv6.MessageTypeRequest, reqParams, func(el time.Duration, tid dhcpv6.TransactionID) *dhcpv6.Message {
		mods := append(c.baseOptions(el), dhcpv6.WithServerID(c.serverID))
		mods = append(mods, c.iaOptions(nil)...)
		m, _ := dhcpv6.NewMessage(mods...)
		m.MessageType = dhcpv6.MessageTypeRequest
		m.TransactionID = tid
		// Echo the IAs from the ADVERTISE unchanged
		for _, ia := range adv.Options.IAPD() {
			m.Options.Update(ia)
		}
		for _, ia := range adv.Options.IANA() {
			m.Options.Update(ia)
		}
		return m
	}, func(m *dhcpv6.Message) (bool, bool) {
		if m.MessageType != dhcpv6.MessageTypeReply || !c.forUs(m) || !m.Options.ServerID().Equal(c.serverID) {
			return false, false
		}
		reply = m
		return true, true
	})
	return reply, err
}

// forUs reports whether a server's message names a server and this client, as RFC 8415 section
// 16.3 and 16.10 require of an Advertise and a Reply.
func (c *dhcpClient) forUs(m *dhcpv6.Message) bool {
	return m.Options.ServerID() != nil && m.Options.ClientID() != nil && m.Options.ClientID().Equal(c.duid)
}

func (c *dhcpClient) renewOrRebind(ctx context.Context, mt dhcpv6.MessageType, p retransParams, mrd time.Duration, l *lease) (*dhcpv6.Message, error) {
	p.mrd = mrd
	var reply *dhcpv6.Message
	err := c.exchange(ctx, mt, p, func(el time.Duration, tid dhcpv6.TransactionID) *dhcpv6.Message {
		mods := c.baseOptions(el)
		if mt == dhcpv6.MessageTypeRenew {
			mods = append(mods, dhcpv6.WithServerID(c.serverID))
		}
		mods = append(mods, c.iaOptions(l)...)
		m, _ := dhcpv6.NewMessage(mods...)
		m.MessageType = mt
		m.TransactionID = tid
		return m
	}, func(m *dhcpv6.Message) (bool, bool) {
		if m.MessageType != dhcpv6.MessageTypeReply || !c.forUs(m) {
			return false, false
		}
		if mt == dhcpv6.MessageTypeRenew && !m.Options.ServerID().Equal(c.serverID) {
			return false, false
		}
		if st := m.Options.Status(); st != nil && st.StatusCode != iana.StatusSuccess {
			warnf("[dhcpv6-client] %s rejected: %s", mt, st.StatusMessage)
			return false, false
		}
		reply = m
		if mt == dhcpv6.MessageTypeRebind {
			c.serverID = m.Options.ServerID()
		}
		return true, true
	})
	return reply, err
}

// confirm asks whether the addresses of l are still on this link (RFC 8415 section 18.2.3). Any
// server may answer, so the message names none, and the lifetimes are left at 0.
func (c *dhcpClient) confirm(ctx context.Context, l *lease) (*dhcpv6.Message, error) {
	p := rejoinParams
	p.mrd = 10 * time.Second
	var reply *dhcpv6.Message
	err := c.exchange(ctx, dhcpv6.MessageTypeConfirm, p, func(el time.Duration, tid dhcpv6.TransactionID) *dhcpv6.Message {
		na := &dhcpv6.OptIANA{IaId: c.iaid}
		for _, a := range l.addrs {
			na.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: a.AsSlice()})
		}
		m, _ := dhcpv6.NewMessage(dhcpv6.WithClientID(c.duid), dhcpv6.WithOption(dhcpv6.OptElapsedTime(el)), dhcpv6.WithOption(na))
		m.MessageType = dhcpv6.MessageTypeConfirm
		m.TransactionID = tid
		return m
	}, func(m *dhcpv6.Message) (bool, bool) {
		if m.MessageType != dhcpv6.MessageTypeReply || !c.forUs(m) {
			return false, false
		}
		reply = m
		return true, true
	})
	return reply, err
}

// infoCycle sends only Information-Request, for upstream RA with only the O bit.
func (c *dhcpClient) infoCycle(ctx context.Context) {
	var reply *dhcpv6.Message
	p := infParams
	p.mrt = c.infMaxRT
	err := c.exchange(ctx, dhcpv6.MessageTypeInformationRequest, p, func(el time.Duration, tid dhcpv6.TransactionID) *dhcpv6.Message {
		m, _ := dhcpv6.NewMessage(c.baseOptions(el)...)
		m.MessageType = dhcpv6.MessageTypeInformationRequest
		m.TransactionID = tid
		return m
	}, func(m *dhcpv6.Message) (bool, bool) {
		if m.MessageType != dhcpv6.MessageTypeReply {
			return false, false
		}
		reply = m
		return true, true
	})
	if err != nil {
		c.onExchangeErr(err)
		return
	}
	c.serverID = reply.Options.ServerID()
	upd := c.parseCommon(reply)
	c.store.Set("pd", upd)
	refresh := reply.Options.InformationRefreshTime(24 * time.Hour)
	if refresh < 10*time.Minute {
		refresh = 10 * time.Minute
	}
	c.waitBound(ctx, time.Now().Add(refresh))
}

// exchange implements RFC 8415 §15 retransmission: RT = IRT + RAND*IRT, then RT = 2RT + RAND*RT, bounded by MRT/MRC/MRD.
// accept returns (matched, done): matched means the message belongs to this transaction, done means we can stop.
func (c *dhcpClient) exchange(ctx context.Context, mt dhcpv6.MessageType, p retransParams,
	build func(elapsed time.Duration, tid dhcpv6.TransactionID) *dhcpv6.Message,
	accept func(*dhcpv6.Message) (bool, bool)) error {
	var tid dhcpv6.TransactionID
	for i := range tid {
		tid[i] = byte(rand.IntN(256))
	}
	begin := time.Now()
	var deadline time.Time
	if p.mrd > 0 {
		deadline = begin.Add(p.mrd)
	}
	// Random delay 0..SOL_MAX_DELAY, INF_MAX_DELAY or CNF_MAX_DELAY before the first message
	if mt == dhcpv6.MessageTypeSolicit || mt == dhcpv6.MessageTypeInformationRequest || mt == dhcpv6.MessageTypeConfirm {
		select {
		case <-time.After(time.Duration(rand.Int64N(int64(time.Second)))):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	rt := jitter(p.irt, mt == dhcpv6.MessageTypeSolicit)
	matched := false
	for count := 0; ; count++ {
		if p.mrc > 0 && count >= p.mrc {
			return errTimeout
		}
		// the option counts hundredths of a second in 16 bits and stays at 0xffff past that (RFC 8415 section 21.9)
		elapsed := min(time.Since(begin), 0xffff*10*time.Millisecond)
		if count == 0 {
			elapsed = 0
		}
		msg := build(elapsed, tid)
		if err := c.send(msg); err != nil {
			debugf("[dhcpv6-client] sending %s failed: %v", mt, err)
			statInc("send_error")
		} else {
			debugf("[dhcpv6-client] sent %s (attempt %d, RT=%s)", mt, count+1, rt.Round(time.Millisecond))
			statInc(strings.ToLower(mt.String()) + "_sent")
		}
		wait := rt
		if !deadline.IsZero() && time.Until(deadline) < wait {
			wait = time.Until(deadline)
			if wait <= 0 {
				return errTimeout
			}
		}
		timer := time.NewTimer(wait)
	recv:
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case ev := <-c.link:
				c.linkUp = ev.Up
				if !ev.Up {
					timer.Stop()
					return errLinkDown
				}
			case m := <-c.recv:
				if m.TransactionID != tid {
					c.handleUnsolicited(m)
					continue
				}
				ok, done := accept(m)
				if !ok {
					continue
				}
				matched = true
				// past the first RT, the first Advertise is taken at once (RFC 8415 section 18.2.1)
				if done || mt == dhcpv6.MessageTypeSolicit && count > 0 {
					timer.Stop()
					return nil
				}
			case <-timer.C:
				break recv
			}
		}
		if matched {
			// SOLICIT collected a full round of ADVERTISEs
			return nil
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return errTimeout
		}
		rt = nextRT(rt, p.mrt)
	}
}

func jitter(irt time.Duration, positiveOnly bool) time.Duration {
	r := rand.Float64()*0.2 - 0.1
	if positiveOnly {
		r = rand.Float64() * 0.1
	}
	return irt + time.Duration(float64(irt)*r)
}

func nextRT(prev, mrt time.Duration) time.Duration {
	r := rand.Float64()*0.2 - 0.1
	rt := 2*prev + time.Duration(float64(prev)*r)
	if mrt > 0 && rt > mrt {
		rt = mrt + time.Duration(float64(mrt)*r)
	}
	return rt
}

type lease struct {
	prefixes []Prefix
	addrs    []netip.Addr
	// When each address stops being preferred and valid, to put it back on the WAN after the
	// link went down: the kernel flushes addresses with a lifetime then
	addrLife map[netip.Addr][2]time.Time
	t1, t2   time.Time
	valid    time.Time
}

// parseCommon extracts DNS, search domains, time servers, the options passed on, tunnel parameters and SOL_MAX_RT.
func (c *dhcpClient) parseCommon(reply *dhcpv6.Message) SourceUpdate {
	var upd SourceUpdate
	for _, ip := range reply.Options.DNS() {
		if a, ok := netip.AddrFromSlice(ip); ok {
			upd.DNS = append(upd.DNS, a.Unmap())
		}
	}
	if dl := reply.Options.DomainSearchList(); dl != nil {
		upd.DNSSL = dl.Labels
	}
	for _, ip := range append(reply.Options.NTPServers(), reply.Options.SNTP()...) {
		if a, ok := netip.AddrFromSlice(ip); ok && !slices.Contains(upd.NTP, a.Unmap()) {
			upd.NTP = append(upd.NTP, a.Unmap())
		}
	}
	for _, code := range passedOn {
		if o := reply.Options.GetOne(code); o != nil {
			upd.Options = append(upd.Options, dhcpOption{code, o.ToBytes()})
		}
	}
	if o := reply.Options.GetOne(dhcpv6.OptionSolMaxRT); o != nil {
		if b := o.ToBytes(); len(b) == 4 {
			v := time.Duration(uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3])) * time.Second
			if v >= 60*time.Second && v <= 86400*time.Second {
				c.solMaxRT = v
			}
		}
	}
	if o := reply.Options.GetOne(dhcpv6.OptionInfMaxRT); o != nil {
		if b := o.ToBytes(); len(b) == 4 {
			v := time.Duration(uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3])) * time.Second
			if v >= 60*time.Second && v <= 86400*time.Second {
				c.infMaxRT = v
			}
		}
	}
	// Reconfigure Key (RKAP, type 1)
	if o := reply.Options.GetOne(dhcpv6.OptionAuth); o != nil {
		if a := o.ToBytes(); len(a) == 28 && a[0] == 3 && a[11] == 1 {
			c.reconfKey = append([]byte(nil), a[12:28]...)
		}
	}
	upd.Tunnel = parseTunnel(reply)
	return upd
}

// parsePDExclude reads OPTION_PD_EXCLUDE (RFC 6603 section 4.2): the length of the excluded prefix,
// then the bits of it that follow the delegated prefix, left-aligned.
func parsePDExclude(pd netip.Prefix, b []byte) (netip.Prefix, bool) {
	if len(b) < 2 {
		return netip.Prefix{}, false
	}
	plen, n := int(b[0]), int(b[0])-pd.Bits()
	if n <= 0 || plen > 128 || len(b)-1 < (n+7)/8 {
		return netip.Prefix{}, false
	}
	a := pd.Masked().Addr().As16()
	for i := range n {
		if b[1+i/8]&(0x80>>(i%8)) != 0 {
			bit := pd.Bits() + i
			a[bit/8] |= 0x80 >> (bit % 8)
		}
	}
	return netip.PrefixFrom(netip.AddrFrom16(a), plen), true
}

// apply handles a REPLY: extracts prefixes and addresses, configures the WAN address, publishes to the Store.
// Returns nil when there is no usable binding and a new SOLICIT is needed.
func (c *dhcpClient) apply(reply *dhcpv6.Message) *lease {
	now := time.Now()
	l := &lease{addrLife: map[netip.Addr][2]time.Time{}}
	upd := c.parseCommon(reply)
	var t1, t2, minPref, maxValid time.Duration
	pickT := func(cur, v time.Duration) time.Duration {
		if v == 0 {
			return cur
		}
		if cur == 0 || v < cur {
			return v
		}
		return cur
	}
	// An IA whose T1 is past its T2, and a lease preferred longer than it is valid, are invalid
	// (RFC 8415 sections 18.2.10.1, 21.6 and 21.22)
	badT := func(t1, t2 time.Duration) bool { return t1 > 0 && t2 > 0 && t1 > t2 }
	for _, ia := range reply.Options.IAPD() {
		if st := ia.Options.Status(); st != nil && st.StatusCode != iana.StatusSuccess {
			warnf("[dhcpv6-client] IA_PD status %s: %s", st.StatusCode, st.StatusMessage)
			continue
		}
		if badT(ia.T1, ia.T2) {
			warnf("[dhcpv6-client] IA_PD with T1 %s past T2 %s ignored", ia.T1, ia.T2)
			continue
		}
		t1, t2 = pickT(t1, ia.T1), pickT(t2, ia.T2)
		for _, p := range ia.Options.Prefixes() {
			if p.ValidLifetime == 0 || p.Prefix == nil {
				infof("[dhcpv6-client] prefix %v lifetime=0, withdrawn", p.Prefix)
				continue
			}
			if p.PreferredLifetime > p.ValidLifetime {
				warnf("[dhcpv6-client] prefix %v preferred longer than valid, ignored", p.Prefix)
				continue
			}
			addr, ok := netip.AddrFromSlice(p.Prefix.IP)
			if !ok {
				continue
			}
			ones, _ := p.Prefix.Mask.Size()
			pf := netip.PrefixFrom(addr.Unmap(), ones).Masked()
			np := Prefix{Prefix: pf, Preferred: now.Add(p.PreferredLifetime), Valid: now.Add(p.ValidLifetime), Source: "pd"}
			if o := p.Options.GetOne(dhcpv6.OptionPDExclude); o != nil {
				if ex, ok := parsePDExclude(pf, o.ToBytes()); ok {
					np.Exclude = ex
					infof("[dhcpv6-client] %s is kept for the WAN link (RFC 6603 Prefix Exclude)", ex)
				}
			}
			l.prefixes = append(l.prefixes, np)
			minPref = pickT(minPref, p.PreferredLifetime)
			if p.ValidLifetime > maxValid {
				maxValid = p.ValidLifetime
			}
		}
	}
	for _, ia := range reply.Options.IANA() {
		if st := ia.Options.Status(); st != nil && st.StatusCode != iana.StatusSuccess {
			warnf("[dhcpv6-client] IA_NA status %s: %s", st.StatusCode, st.StatusMessage)
			continue
		}
		if badT(ia.T1, ia.T2) {
			warnf("[dhcpv6-client] IA_NA with T1 %s past T2 %s ignored", ia.T1, ia.T2)
			continue
		}
		t1, t2 = pickT(t1, ia.T1), pickT(t2, ia.T2)
		for _, a := range ia.Options.Addresses() {
			addr, ok := netip.AddrFromSlice(a.IPv6Addr)
			if !ok || a.ValidLifetime == 0 || a.PreferredLifetime > a.ValidLifetime {
				continue
			}
			addr = addr.Unmap()
			l.addrs = append(l.addrs, addr)
			l.addrLife[addr] = [2]time.Time{now.Add(a.PreferredLifetime), now.Add(a.ValidLifetime)}
			minPref = pickT(minPref, a.PreferredLifetime)
			if a.ValidLifetime > maxValid {
				maxValid = a.ValidLifetime
			}
			if err := addrSet(c.ifi.Index, addr, 128, a.PreferredLifetime, a.ValidLifetime, false, 0); err != nil {
				errorf("[dhcpv6-client] configuring WAN address %s failed: %v", addr, err)
			}
		}
	}
	c.fresh = c.fresh[:0]
	for _, a := range l.addrs {
		if !slices.Contains(c.naAddrs, a) {
			c.fresh = append(c.fresh, a)
		}
	}
	// Remove IA_NA addresses no longer assigned
	for _, old := range c.naAddrs {
		keep := false
		for _, a := range l.addrs {
			keep = keep || a == old
		}
		if !keep {
			addrDel(c.ifi.Index, old, 128)
		}
	}
	c.naAddrs = l.addrs
	if len(l.addrs) > 0 {
		upd.WANAddr = l.addrs[0]
	}
	upd.Prefixes = l.prefixes
	c.pub = upd
	c.store.Set("pd", upd)
	if len(l.prefixes) == 0 && len(l.addrs) == 0 {
		return nil
	}
	if t1 == 0 {
		t1 = minPref / 2
	}
	if t2 == 0 {
		t2 = minPref * 8 / 10
	}
	if t2 < t1 {
		t2 = t1
	}
	l.t1, l.t2, l.valid = now.Add(t1), now.Add(t2), now.Add(maxValid)
	infof("[dhcpv6-client] bound %d prefixes %d addresses, T1=%s T2=%s", len(l.prefixes), len(l.addrs), t1, t2)
	return l
}

// bind applies a Reply, then waits for the kernel's DAD on the addresses it added and declines
// those another node already uses (RFC 8415 sections 18.2.8 and 18.2.10.1). It returns nil when
// nothing is left of the binding, so that a new Solicit asks for other addresses.
func (c *dhcpClient) bind(ctx context.Context, reply *dhcpv6.Message) *lease {
	l := c.apply(reply)
	if l == nil || len(c.fresh) == 0 || dryRun {
		return l
	}
	dup := c.awaitDAD(ctx, c.fresh)
	if len(dup) == 0 {
		return l
	}
	for _, a := range dup {
		warnf("[dhcpv6-client] WAN address %s failed DAD: another node on the link uses it, declining it", a)
		addrDel(c.ifi.Index, a, 128)
	}
	l.addrs = slices.DeleteFunc(l.addrs, func(a netip.Addr) bool { return slices.Contains(dup, a) })
	c.naAddrs = l.addrs
	c.pub.WANAddr = netip.Addr{}
	if len(l.addrs) > 0 {
		c.pub.WANAddr = l.addrs[0]
	}
	c.store.Set("pd", c.pub)
	c.decline(ctx, dup)
	if len(l.prefixes) == 0 && len(l.addrs) == 0 {
		return nil
	}
	return l
}

// awaitDAD polls the WAN interface until none of addrs is tentative, and returns those that failed.
// The kernel marks a failed address only when it has no lifetime; one with a lifetime, as these
// have, it deletes, so an address gone from an interface still up failed too. It gives up after 10 s,
// enough for DupAddrDetectTransmits well above the default of 1.
func (c *dhcpClient) awaitDAD(ctx context.Context, addrs []netip.Addr) []netip.Addr {
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	limit := time.After(10 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-limit:
			return nil
		case <-t.C:
		}
		list, err := addrList(c.ifi.Index)
		if err != nil {
			continue
		}
		var failed []netip.Addr
		pending := false
		for _, a := range addrs {
			i := slices.IndexFunc(list, func(ia ifAddr) bool { return ia.Addr == a })
			if i < 0 {
				// gone because the link went down and the kernel flushed its addresses: no DAD
				// failed, and what follows the link coming back decides on the binding
				if ifi, err := net.InterfaceByIndex(c.ifi.Index); err != nil || ifi.Flags&net.FlagUp == 0 {
					return nil
				}
			}
			switch {
			case i < 0 || list[i].Flags&ifaFDadFailed != 0:
				failed = append(failed, a)
			case list[i].Flags&ifaFTentative != 0:
				pending = true
			}
		}
		if !pending {
			return failed
		}
	}
}

// decline tells the server that addrs are in use by another node (RFC 8415 section 18.2.8). Any
// Reply ends the exchange; without one, the addresses are given up all the same.
func (c *dhcpClient) decline(ctx context.Context, addrs []netip.Addr) {
	err := c.exchange(ctx, dhcpv6.MessageTypeDecline, decParams, func(el time.Duration, tid dhcpv6.TransactionID) *dhcpv6.Message {
		na := &dhcpv6.OptIANA{IaId: c.iaid}
		for _, a := range addrs {
			na.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: a.AsSlice()})
		}
		m, _ := dhcpv6.NewMessage(dhcpv6.WithClientID(c.duid), dhcpv6.WithOption(dhcpv6.OptElapsedTime(el)),
			dhcpv6.WithServerID(c.serverID), dhcpv6.WithOption(na))
		m.MessageType = dhcpv6.MessageTypeDecline
		m.TransactionID = tid
		return m
	}, func(m *dhcpv6.Message) (bool, bool) {
		ok := m.MessageType == dhcpv6.MessageTypeReply && c.forUs(m)
		return ok, ok
	})
	if err != nil {
		debugf("[dhcpv6-client] DECLINE not acknowledged: %v", err)
		return
	}
	infof("[dhcpv6-client] DECLINE acknowledged")
}

func (c *dhcpClient) clearLease() {
	for _, a := range c.naAddrs {
		addrDel(c.ifi.Index, a, 128)
	}
	c.naAddrs = nil
	c.store.Set("pd", SourceUpdate{})
}

// raFlags holds the M/O bits of the upstream RA.
type raFlags struct {
	managed, other bool
}

// fallbackInfo falls back to Information-Request (DNS etc. only) when the upstream RA has only the O bit and PD probing got nothing.
// Returns whether the mode was just switched.
func (c *dhcpClient) fallbackInfo() bool {
	if c.raOther && !c.infoOnly {
		c.infoOnly = true
		infof("[dhcpv6-client] PD probing got nothing and upstream RA has only O bit, switching to Information-Request for DNS etc.")
		return true
	}
	return false
}

// release returns the binding on exit (RFC 8415 §18.2.7) so the server reclaims prefixes and addresses
// immediately instead of waiting for valid lifetime expiry. Uses a short standalone timeout, at most REL_MAX_RC retransmissions.
func (c *dhcpClient) release(l *lease) {
	if l == nil || c.serverID == nil || (len(l.prefixes) == 0 && len(l.addrs) == 0) {
		return
	}
	rctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	infof("[dhcpv6-client] exiting, sending RELEASE for %d prefixes %d addresses", len(l.prefixes), len(l.addrs))
	err := c.exchange(rctx, dhcpv6.MessageTypeRelease, relParams, func(el time.Duration, tid dhcpv6.TransactionID) *dhcpv6.Message {
		mods := append(c.baseOptions(el), dhcpv6.WithServerID(c.serverID))
		mods = append(mods, c.iaOptions(l)...)
		m, _ := dhcpv6.NewMessage(mods...)
		m.MessageType = dhcpv6.MessageTypeRelease
		m.TransactionID = tid
		return m
	}, func(m *dhcpv6.Message) (bool, bool) {
		return m.MessageType == dhcpv6.MessageTypeReply, true
	})
	if err != nil {
		debugf("[dhcpv6-client] RELEASE not acknowledged: %v", err)
		return
	}
	infof("[dhcpv6-client] RELEASE acknowledged")
	c.clearLease()
}

// WaitDone waits up to 4s for the client to finish (RELEASE).
func (c *dhcpClient) WaitDone() {
	select {
	case <-c.done:
	case <-time.After(4 * time.Second):
	}
}
