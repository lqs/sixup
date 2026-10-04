//go:build linux && integration

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/mdlayher/netlink"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// ownNetns runs the calling test again in a process of its own inside a fresh network namespace,
// where every thread of it is, as the DHCPv6 client's goroutines need; enterNetNS moves only one.
// It returns true in that process, and false in the parent once the child has passed.
func ownNetns(t *testing.T) bool {
	t.Helper()
	if os.Getenv("SIXUP_OWN_NETNS") == "1" {
		return true
	}
	if os.Geteuid() != 0 {
		t.Skip("a network namespace needs root")
	}
	args := []string{"-test.run=^" + t.Name() + "$", "-test.v"}
	// under -cover the child writes its counters into the parent's directory, which go test merges
	if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+f.Value.String())
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "SIXUP_OWN_NETNS=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("in its own namespace: %v\n%s", err, out)
	}
	return false
}

func linkDown(t *testing.T, index int) {
	t.Helper()
	c, err := rtDial()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	hdr := make([]byte, 16)
	nativeEndian.PutUint32(hdr[4:8], uint32(index))
	nativeEndian.PutUint32(hdr[12:16], unix.IFF_UP)
	if _, err := c.Execute(netlink.Message{Header: netlink.Header{Type: unix.RTM_NEWLINK, Flags: netlink.Request | netlink.Acknowledge}, Data: hdr}); err != nil {
		t.Fatalf("link %d down: %v", index, err)
	}
}

// fakeServer delegates one prefix to whoever asks, and can be told to stay silent.
type fakeServer struct {
	pc     *ipv6.PacketConn
	ifi    *net.Interface
	duid   dhcpv6.DUID
	prefix netip.Prefix
	na     netip.Addr // the address of an IA_NA, if any
	seen   chan *dhcpv6.Message
	silent atomic.Bool
	short  atomic.Bool // T1 of 2 s in the next Reply, to see a Renew soon
	moved  atomic.Bool // answer a Confirm with NotOnLink
}

func (s *fakeServer) serve() {
	buf := make([]byte, 1500)
	for {
		n, cm, src, err := s.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if cm == nil || cm.IfIndex != s.ifi.Index {
			continue
		}
		msg, err := dhcpv6.MessageFromBytes(buf[:n])
		if err != nil {
			continue
		}
		select {
		case s.seen <- msg:
		default:
		}
		if s.silent.Load() {
			continue
		}
		resp, _ := dhcpv6.NewMessage()
		resp.MessageType = dhcpv6.MessageTypeReply
		if msg.MessageType == dhcpv6.MessageTypeSolicit {
			resp.MessageType = dhcpv6.MessageTypeAdvertise
		}
		resp.TransactionID = msg.TransactionID
		resp.AddOption(dhcpv6.OptServerID(s.duid))
		resp.AddOption(dhcpv6.OptClientID(msg.Options.ClientID()))
		if msg.MessageType == dhcpv6.MessageTypeConfirm {
			st := &dhcpv6.OptStatusCode{StatusCode: iana.StatusSuccess}
			if s.moved.Load() {
				st.StatusCode = iana.StatusNotOnLink
			}
			resp.AddOption(st)
			s.pc.WriteTo(resp.ToBytes(), &ipv6.ControlMessage{IfIndex: s.ifi.Index}, src)
			continue
		}
		for _, ia := range msg.Options.IAPD() {
			t1 := 300 * time.Second
			if s.short.Load() && msg.MessageType != dhcpv6.MessageTypeSolicit {
				t1 = 2 * time.Second
				s.short.Store(false)
			}
			pd := &dhcpv6.OptIAPD{IaId: ia.IaId, T1: t1, T2: 2 * t1}
			pd.Options.Add(&dhcpv6.OptIAPrefix{Prefix: prefixToIPNet(s.prefix), PreferredLifetime: time.Hour, ValidLifetime: 2 * time.Hour})
			resp.AddOption(pd)
		}
		for _, ia := range msg.Options.IANA() {
			if !s.na.IsValid() || msg.MessageType == dhcpv6.MessageTypeDecline {
				continue
			}
			na := &dhcpv6.OptIANA{IaId: ia.IaId, T1: 300 * time.Second, T2: 600 * time.Second}
			na.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: s.na.AsSlice(), PreferredLifetime: time.Hour, ValidLifetime: 2 * time.Hour})
			resp.AddOption(na)
		}
		s.pc.WriteTo(resp.ToBytes(), &ipv6.ControlMessage{IfIndex: s.ifi.Index}, src)
	}
}

func (s *fakeServer) expect(t *testing.T, mt dhcpv6.MessageType, within time.Duration) *dhcpv6.Message {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case got := <-s.seen:
			if got.MessageType == mt {
				return got
			}
		case <-deadline:
			t.Fatalf("no %s within %s", mt, within)
		}
	}
}

// dhcpv6Link sets up, in the test's own namespace, the WAN wan-test0 and on its far end a server
// that delegates 2001:db8:100::/56.
func dhcpv6Link(t *testing.T) *fakeServer {
	t.Helper()
	loUp(t)
	for _, k := range []string{"all", "default"} {
		if err := sysctlWrite("/proc/sys/net/ipv6/conf/"+k+"/accept_dad", "0"); err != nil {
			t.Fatal(err)
		}
	}
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	if err := vethAdd("wan-test0", "srv-test0", int(ns.Fd())); err != nil {
		t.Fatal(err)
	}
	linkUp(t, mustIface(t, "srv-test0"))
	linkUp(t, mustIface(t, "wan-test0"))
	time.Sleep(200 * time.Millisecond) // the link-local addresses, DAD off

	conn, err := net.ListenPacket("udp6", "[::]:547")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	srvIfi, _ := net.InterfaceByName("srv-test0")
	s := &fakeServer{pc: ipv6.NewPacketConn(conn), ifi: srvIfi, prefix: netip.MustParsePrefix("2001:db8:100::/56"),
		duid: &dhcpv6.DUIDLL{HWType: 1, LinkLayerAddr: net.HardwareAddr{2, 0, 0, 0, 0, 0x53}}, seen: make(chan *dhcpv6.Message, 64)}
	if err := s.pc.JoinGroup(srvIfi, &net.UDPAddr{IP: net.ParseIP("ff02::1:2")}); err != nil {
		t.Fatal(err)
	}
	s.pc.SetControlMessage(ipv6.FlagInterface, true)
	go s.serve()
	return s
}

// The client's lifecycle against a server: the delegation, a Renew at T1, and a link that goes down
// and comes back, after which the binding is confirmed with a Rebind (RFC 8415 section 18.2.12)
// and never leaves the store, whether or not the server answers.
func TestDHCPv6ClientAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	s := dhcpv6Link(t)
	wan := mustIface(t, "wan-test0")
	s.short.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newStore("pd", []lanDef{{"lan0", 0}}, time.Minute, nil, false, 0, 0, "")
	snaps := store.Subscribe()
	c := newDHCPClient("wan-test0", store, t.TempDir(), 56, false)
	c.link = newLinkHub(ctx).Subscribe("wan-test0")
	go c.run(ctx, false)

	// Delegated
	s.expect(t, dhcpv6.MessageTypeSolicit, 5*time.Second)
	s.expect(t, dhcpv6.MessageTypeRequest, 5*time.Second)
	hasPrefix := func(snap Snapshot) bool {
		for _, p := range snap.WAN {
			if p.Source == sourcePD && p.Prefix == s.prefix {
				return true
			}
		}
		return false
	}
	deadline := time.After(5 * time.Second)
	for got := false; !got; {
		select {
		case snap := <-snaps:
			got = hasPrefix(snap)
		case <-deadline:
			t.Fatal("the delegation never reached the store")
		}
	}

	// Renewed at T1
	s.expect(t, dhcpv6.MessageTypeRenew, 5*time.Second)

	// Whatever happens to the link from here, the store must keep the prefix
	lost := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case snap := <-snaps:
				if !hasPrefix(snap) {
					select {
					case lost <- struct{}{}:
					default:
					}
				}
			}
		}
	}()

	// The link goes down and comes back: a Rebind confirms the binding
	linkDown(t, wan)
	time.Sleep(time.Second)
	linkUp(t, wan)
	s.expect(t, dhcpv6.MessageTypeRebind, 10*time.Second)

	// Again, with the server silent: the binding is kept
	s.silent.Store(true)
	linkDown(t, wan)
	time.Sleep(time.Second)
	linkUp(t, wan)
	s.expect(t, dhcpv6.MessageTypeRebind, 10*time.Second)
	time.Sleep(12 * time.Second) // past the 10 s the Rebind waits for a Reply
	select {
	case <-lost:
		t.Fatal("the store lost the prefix over a link going down")
	default:
	}
}

// An IA_NA address another node on the link already has fails DAD, and is declined and given up
// (RFC 8415 section 18.2.8, CE Router test 1.1.1 part F), while the delegation is kept.
func TestDHCPv6ClientDeclinesAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	s := dhcpv6Link(t)
	s.na = netip.MustParseAddr("2001:db8:1::99")
	// the server's side holds the address, and answers the client's DAD for it
	if err := addrSet(mustIface(t, "srv-test0"), s.na, 64, time.Hour, time.Hour, false, ifaFNodad); err != nil {
		t.Fatal(err)
	}
	if err := sysctlWrite("/proc/sys/net/ipv6/conf/wan-test0/accept_dad", "1"); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newStore("pd", []lanDef{{"lan0", 0}}, time.Minute, nil, false, 0, 0, "")
	c := newDHCPClient("wan-test0", store, t.TempDir(), 56, true)
	go c.run(ctx, false)

	s.expect(t, dhcpv6.MessageTypeRequest, 5*time.Second)
	dec := s.expect(t, dhcpv6.MessageTypeDecline, 5*time.Second)
	if !dec.Options.ServerID().Equal(s.duid) || dec.Options.ElapsedTime() != 0 {
		t.Fatalf("Decline without the server or with an elapsed time: %v", dec)
	}
	ias := dec.Options.IANA()
	if len(ias) != 1 || len(ias[0].Options.Addresses()) != 1 || !ias[0].Options.Addresses()[0].IPv6Addr.Equal(s.na.AsSlice()) {
		t.Fatalf("Decline does not name %s: %v", s.na, dec)
	}
	time.Sleep(200 * time.Millisecond) // the Reply to the Decline
	list, err := addrList(mustIface(t, "wan-test0"))
	if err != nil {
		t.Fatal(err)
	}
	for _, ia := range list {
		if ia.Addr == s.na {
			t.Fatalf("%s still on the WAN after the Decline", s.na)
		}
	}
	snap := store.Current()
	if snap.WANAddr == s.na {
		t.Fatalf("%s still the WAN address", s.na)
	}
	if len(snap.WAN) == 0 {
		t.Fatal("the delegation went with the declined address")
	}
}

// Without a delegation, a link that comes back has its addresses confirmed with a Confirm (RFC 8415
// sections 18.2.3 and 18.2.12, CE Router test 1.1.10), which names no server and leaves the
// lifetimes at 0. The binding stays on Success, and a NotOnLink sends the client back to Solicit.
func TestDHCPv6ClientConfirmsAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	s := dhcpv6Link(t)
	s.na = netip.MustParseAddr("2001:db8:1::99")
	wan := mustIface(t, "wan-test0")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newStore("pd", []lanDef{{"lan0", 0}}, time.Minute, nil, false, 0, 0, "")
	c := newDHCPClient("wan-test0", store, t.TempDir(), 0, true)
	c.link = newLinkHub(ctx).Subscribe("wan-test0")
	go c.run(ctx, false)
	s.expect(t, dhcpv6.MessageTypeRequest, 5*time.Second)
	time.Sleep(200 * time.Millisecond) // the Reply applied

	flap := func() *dhcpv6.Message {
		t.Helper()
		linkDown(t, wan)
		time.Sleep(time.Second)
		linkUp(t, wan)
		return s.expect(t, dhcpv6.MessageTypeConfirm, 10*time.Second)
	}
	cnf := flap()
	if cnf.Options.ServerID() != nil || cnf.Options.ElapsedTime() != 0 {
		t.Fatalf("Confirm names a server or starts with an elapsed time: %v", cnf)
	}
	ias := cnf.Options.IANA()
	if len(ias) != 1 || len(ias[0].Options.Addresses()) != 1 {
		t.Fatalf("Confirm without the address: %v", cnf)
	}
	if a := ias[0].Options.Addresses()[0]; !a.IPv6Addr.Equal(s.na.AsSlice()) || a.PreferredLifetime != 0 || a.ValidLifetime != 0 {
		t.Fatalf("Confirm names %v with lifetimes %s and %s", a.IPv6Addr, a.PreferredLifetime, a.ValidLifetime)
	}
	time.Sleep(300 * time.Millisecond)
	if store.Current().WANAddr != s.na {
		t.Fatal("the confirmed address left the store")
	}
	// the link going down flushed the address from the interface; the client puts it back
	netlinkWaitFor(t, "the confirmed address back on the WAN", func() bool {
		list, err := addrList(wan)
		return err == nil && slices.ContainsFunc(list, func(ia ifAddr) bool { return ia.Addr == s.na })
	})

	s.moved.Store(true)
	flap()
	s.expect(t, dhcpv6.MessageTypeSolicit, 5*time.Second)
}

// Waiting for the RA as main does, the client starts on its M or O flags and asks for a prefix
// whichever it is (RFC 7084 WPD-4), with IA_NA too (WAA-6).
func TestDHCPv6ClientStartsOnTheRAAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	s := dhcpv6Link(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newStore("pd", []lanDef{{"lan0", 0}}, time.Minute, nil, false, 0, 0, "")
	c := newDHCPClient("wan-test0", store, t.TempDir(), 56, true)
	c.link = newLinkHub(ctx).Subscribe("wan-test0")
	go c.run(ctx, true)
	select {
	case m := <-s.seen:
		t.Fatalf("%s before the RA", m.MessageType)
	case <-time.After(2 * time.Second):
	}
	c.start <- raFlags{other: true}
	sol := s.expect(t, dhcpv6.MessageTypeSolicit, 5*time.Second)
	if len(sol.Options.IAPD()) != 1 || len(sol.Options.IANA()) != 1 {
		t.Fatalf("an O-only RA still gets IA_PD, and IA_NA: %v", sol.Options)
	}
}

// With -wan-prefix the client asks only for DNS and the like: an Information-Request, no Solicit.
func TestDHCPv6ClientInfoOnlyAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	s := dhcpv6Link(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newStore("pd", []lanDef{{"lan0", 0}}, time.Minute, nil, false, 0, 0, "")
	c := newDHCPClient("wan-test0", store, t.TempDir(), 56, true)
	c.link = newLinkHub(ctx).Subscribe("wan-test0")
	c.infoOnly = true
	go c.run(ctx, false)
	m := <-s.seen
	if m.MessageType != dhcpv6.MessageTypeInformationRequest || len(m.Options.IAPD()) != 0 || len(m.Options.IANA()) != 0 {
		t.Fatalf("want an Information-Request without IAs, got %s %v", m.MessageType, m.Options)
	}
}

// dhcp6cRig drives a client on wan-test0 by hand: the fake server stays silent and only shows what
// the client sends, and the test puts the answers straight into the client's queue.
type dhcp6cRig struct {
	t      *testing.T
	s      *fakeServer
	c      *dhcpClient
	cancel context.CancelFunc
	done   chan struct{}
}

func dhcp6cNewRig(t *testing.T, s *fakeServer, pdLen int, wantNA bool) *dhcp6cRig {
	t.Helper()
	s.silent.Store(true)
	for len(s.seen) > 0 {
		<-s.seen
	}
	store := newStore("pd", []lanDef{{"lan0", 0}}, time.Minute, nil, false, 0, 0, "")
	c := newDHCPClient("wan-test0", store, t.TempDir(), pdLen, wantNA)
	ifi, err := net.InterfaceByName("wan-test0")
	if err != nil {
		t.Fatal(err)
	}
	c.ifi, c.iaid = ifi, iaidFor(ifi)
	if err := c.loadDUID(); err != nil {
		t.Fatal(err)
	}
	r := &dhcp6cRig{t: t, s: s, c: c}
	t.Cleanup(func() {
		if r.done != nil {
			r.cancel()
			<-r.done
		}
		if c.conn != nil {
			c.conn.Close()
		}
	})
	return r
}

// cycle starts one cycle of the client.
func (r *dhcp6cRig) cycle() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel, r.done = cancel, make(chan struct{})
	go func() {
		defer close(r.done)
		r.c.cycle(ctx)
	}()
}

// wait waits for the cycle to end by itself.
func (r *dhcp6cRig) wait() {
	r.t.Helper()
	select {
	case <-r.done:
	case <-time.After(10 * time.Second):
		r.t.Fatal("the cycle did not end")
	}
}

// stop ends the cycle.
func (r *dhcp6cRig) stop() {
	r.t.Helper()
	r.cancel()
	r.wait()
}

func (r *dhcp6cRig) expect(mt dhcpv6.MessageType) *dhcpv6.Message {
	r.t.Helper()
	return r.s.expect(r.t, mt, 5*time.Second)
}

// settled waits until the client has taken everything from its queue.
func (r *dhcp6cRig) settled() {
	r.t.Helper()
	for deadline := time.Now().Add(5 * time.Second); len(r.c.recv) > 0; {
		if time.Now().After(deadline) {
			r.t.Fatal("the client left its queue alone")
		}
		time.Sleep(time.Millisecond)
	}
}

func (r *dhcp6cRig) link(up bool) { r.c.link <- linkEvent{Name: "wan-test0", Up: up} }

// dhcp6cMsg is a message of type mt answering req, with opts and nothing else.
func dhcp6cMsg(req *dhcpv6.Message, mt dhcpv6.MessageType, opts ...dhcpv6.Option) *dhcpv6.Message {
	m, _ := dhcpv6.NewMessage()
	m.MessageType = mt
	m.TransactionID = req.TransactionID
	for _, o := range opts {
		m.AddOption(o)
	}
	return m
}

// answer puts the server's message of type mt to req into the client's queue.
func (r *dhcp6cRig) answer(req *dhcpv6.Message, mt dhcpv6.MessageType, opts ...dhcpv6.Option) {
	r.c.recv <- dhcp6cMsg(req, mt, append([]dhcpv6.Option{dhcpv6.OptServerID(r.s.duid), dhcpv6.OptClientID(r.c.duid)}, opts...)...)
}

// advertise answers the next Solicit with an Advertise of the highest preference.
func (r *dhcp6cRig) advertise(ias ...dhcpv6.Option) {
	r.t.Helper()
	r.answer(r.expect(dhcpv6.MessageTypeSolicit), dhcpv6.MessageTypeAdvertise, append([]dhcpv6.Option{dhcpv6.OptPreference(255)}, ias...)...)
}

// bound takes the client through Solicit and Request to a binding of ias.
func (r *dhcp6cRig) bound(ias ...dhcpv6.Option) {
	r.t.Helper()
	r.advertise(ias...)
	r.answer(r.expect(dhcpv6.MessageTypeRequest), dhcpv6.MessageTypeReply, ias...)
	r.settled()
}

// dhcp6cPD delegates 2001:db8:100::/56.
func dhcp6cPD(t1, t2, pref, valid time.Duration) *dhcpv6.OptIAPD {
	pd := &dhcpv6.OptIAPD{IaId: [4]byte{1}, T1: t1, T2: t2}
	pd.Options.Add(&dhcpv6.OptIAPrefix{Prefix: prefixToIPNet(netip.MustParsePrefix("2001:db8:100::/56")), PreferredLifetime: pref, ValidLifetime: valid})
	return pd
}

// dhcp6cNA assigns addrs for an hour.
func dhcp6cNA(addrs ...netip.Addr) *dhcpv6.OptIANA {
	na := &dhcpv6.OptIANA{IaId: [4]byte{2}, T1: 300 * time.Second, T2: 600 * time.Second}
	for _, a := range addrs {
		na.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: a.AsSlice(), PreferredLifetime: time.Hour, ValidLifetime: time.Hour})
	}
	return na
}

// The client's ways through its states against answers scripted for each turn: refusals, broken
// exchanges, bindings that end, a link that flaps, Release and Confirm, and addresses that fail DAD.
func TestDHCPv6ClientScriptedAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	s := dhcpv6Link(t)

	// Meanwhile, the waits that only time ends, so that the suite does not wait for them in turn:
	// run starts without the RA after 8 s, and awaitDAD gives up on an address still tentative
	// after 10 s
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	if err := vethAdd("dad-test0", "dad-test1", int(ns.Fd())); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"accept_dad": "1", "dad_transmits": "30"} {
		if err := sysctlWrite("/proc/sys/net/ipv6/conf/dad-test0/"+k, v); err != nil {
			t.Fatal(err)
		}
	}
	dad := mustIface(t, "dad-test0")
	linkUp(t, mustIface(t, "dad-test1"))
	linkUp(t, dad)
	tentative := netip.MustParseAddr("2001:db8:2::55")
	if err := addrSet(dad, tentative, 128, time.Hour, time.Hour, false, 0); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() {
		begin := time.Now()
		d := &dhcpClient{ifi: &net.Interface{Index: dad}}
		var err error
		if failed := d.awaitDAD(context.Background(), []netip.Addr{tentative}); failed != nil || time.Since(begin) < 10*time.Second {
			err = fmt.Errorf("awaitDAD: %v after %s", failed, time.Since(begin))
		}
		waited <- err
	}()
	store := newStore("pd", []lanDef{{"lan0", 0}}, time.Minute, nil, false, 0, 0, "")
	c := newDHCPClient("lo", store, t.TempDir(), 56, false)
	c.linkUp = false // after the 8 s, the cycle waits for the link
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.run(ctx, true)

	pd := func(t1, t2 time.Duration) dhcpv6.Option { return dhcp6cPD(t1, t2, time.Hour, 2*time.Hour) }
	gone := dhcp6cPD(300*time.Second, 300*time.Second, 0, 0)
	refusedPD := &dhcpv6.OptIAPD{IaId: [4]byte{1}}
	refusedPD.Options.Add(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoPrefixAvail})
	noPrefix := &dhcpv6.OptStatusCode{StatusCode: iana.StatusNoPrefixAvail}
	failed := &dhcpv6.OptStatusCode{StatusCode: iana.StatusUnspecFail}
	other := dhcpv6.OptServerID(&dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{2, 0, 0, 0, 0, 0x54}})

	t.Run("refused Solicit", func(t *testing.T) {
		r := dhcp6cNewRig(t, s, 56, false)
		r.cycle()
		sol := r.expect(dhcpv6.MessageTypeSolicit)
		r.c.recv <- dhcp6cMsg(sol, dhcpv6.MessageTypeAdvertise) // names neither server nor client
		r.answer(sol, dhcpv6.MessageTypeAdvertise, failed)
		r.answer(sol, dhcpv6.MessageTypeAdvertise) // no IA_PD
		r.answer(sol, dhcpv6.MessageTypeAdvertise, refusedPD)
		r.answer(sol, dhcpv6.MessageTypeAdvertise, noPrefix)
		r.settled()
		r.stop()
		if !r.c.unhinted {
			t.Fatal("a refused hint is retried without one")
		}

		r.cycle()
		sol = r.expect(dhcpv6.MessageTypeSolicit)
		if ps := sol.Options.IAPD()[0].Options.Prefixes(); len(ps) != 0 {
			t.Fatalf("still a hint: %v", ps)
		}
		r.answer(sol, dhcpv6.MessageTypeAdvertise, noPrefix)
		r.settled()
		r.stop()
		if r.c.unhinted || r.c.refuseBackoff != 5*time.Minute {
			t.Fatalf("refused without the hint: backoff %s", r.c.refuseBackoff)
		}

		// on an O-only line a refusal switches to Information-Request
		r.c.unhinted, r.c.raOther = true, true
		r.cycle()
		r.answer(r.expect(dhcpv6.MessageTypeSolicit), dhcpv6.MessageTypeAdvertise, noPrefix)
		r.settled()
		r.stop()
		if !r.c.infoOnly {
			t.Fatal("no Information-Request after the refusal")
		}

		r.cycle()
		inf := r.expect(dhcpv6.MessageTypeInformationRequest)
		r.answer(inf, dhcpv6.MessageTypeAdvertise)
		r.answer(inf, dhcpv6.MessageTypeReply, dhcpv6.OptDNS(net.ParseIP("2001:db8::53")), dhcpv6.OptInformationRefreshTime(time.Minute))
		r.settled()
		r.stop()
		if !r.c.serverID.Equal(s.duid) {
			t.Fatalf("server %v", r.c.serverID)
		}

		r.cycle()
		r.expect(dhcpv6.MessageTypeInformationRequest)
		r.link(false)
		r.wait()
	})

	t.Run("broken Solicit and Request", func(t *testing.T) {
		r := dhcp6cNewRig(t, s, 56, false)
		r.cycle()
		r.expect(dhcpv6.MessageTypeSolicit)
		r.link(false)
		r.wait()

		r.link(true)
		r.cycle()
		r.advertise(pd(300*time.Second, 300*time.Second))
		req := r.expect(dhcpv6.MessageTypeRequest)
		r.c.recv <- dhcp6cMsg(req, dhcpv6.MessageTypeReply, other, dhcpv6.OptClientID(r.c.duid))
		r.settled()
		r.link(false)
		r.wait()
	})

	t.Run("Reply without a binding", func(t *testing.T) {
		r := dhcp6cNewRig(t, s, 56, false)
		refuse := func() {
			t.Helper()
			r.cycle()
			r.advertise(pd(300*time.Second, 300*time.Second))
			r.answer(r.expect(dhcpv6.MessageTypeRequest), dhcpv6.MessageTypeReply, refusedPD)
			r.settled()
		}
		refuse()
		r.wait()
		if !r.c.unhinted {
			t.Fatal("a refused hint is retried without one")
		}
		refuse()
		r.stop()
		if r.c.refuseBackoff != 5*time.Minute {
			t.Fatalf("backoff %s", r.c.refuseBackoff)
		}
		r.c.unhinted, r.c.raOther = true, true
		refuse()
		r.wait()
		if !r.c.infoOnly {
			t.Fatal("no Information-Request after the refusal")
		}

		r.c.infoOnly, r.c.raOther = false, false
		r.cycle()
		r.advertise(pd(300*time.Second, 300*time.Second))
		r.answer(r.expect(dhcpv6.MessageTypeRequest), dhcpv6.MessageTypeReply, gone)
		r.settled()
		r.stop()
	})

	t.Run("Renew and Rebind", func(t *testing.T) {
		r := dhcp6cNewRig(t, s, 56, false)
		r.cycle()
		r.bound(pd(time.Second, time.Second))
		ren := r.expect(dhcpv6.MessageTypeRenew)
		r.c.recv <- dhcp6cMsg(ren, dhcpv6.MessageTypeReply, dhcpv6.OptServerID(s.duid)) // names no client
		r.c.recv <- dhcp6cMsg(ren, dhcpv6.MessageTypeReply, other, dhcpv6.OptClientID(r.c.duid))
		r.answer(ren, dhcpv6.MessageTypeReply, failed)
		r.answer(ren, dhcpv6.MessageTypeReply, pd(300*time.Second, 300*time.Second))
		r.settled()

		r.c.Reconfirm("test")
		reb := r.expect(dhcpv6.MessageTypeRebind)
		if reb.Options.ServerID() != nil {
			t.Fatal("a Rebind names no server")
		}
		r.answer(reb, dhcpv6.MessageTypeReply, pd(time.Second, time.Second))

		r.answer(r.expect(dhcpv6.MessageTypeRenew), dhcpv6.MessageTypeReply, gone)
		r.wait()
	})

	t.Run("Renew and Rebind unanswered", func(t *testing.T) {
		r := dhcp6cNewRig(t, s, 56, false)
		r.cycle()
		r.bound(dhcp6cPD(time.Second, time.Second, time.Second, 2*time.Second))
		r.expect(dhcpv6.MessageTypeRenew)
		r.expect(dhcpv6.MessageTypeRebind)
		r.wait()
	})

	t.Run("link flaps while bound", func(t *testing.T) {
		r := dhcp6cNewRig(t, s, 56, false)
		r.cycle()
		r.bound(pd(300*time.Second, 300*time.Second))
		r.link(false)
		r.link(true)
		r.expect(dhcpv6.MessageTypeRebind)
		r.link(false) // again, during the Rebind
		r.link(true)
		r.answer(r.expect(dhcpv6.MessageTypeRebind), dhcpv6.MessageTypeReply, pd(300*time.Second, 300*time.Second))
		r.settled()
		r.link(false)
		r.link(true)
		r.answer(r.expect(dhcpv6.MessageTypeRebind), dhcpv6.MessageTypeReply, gone)
		r.wait()
	})

	t.Run("link down during Renew", func(t *testing.T) {
		r := dhcp6cNewRig(t, s, 56, false)
		r.cycle()
		r.bound(pd(time.Second, 300*time.Second))
		r.expect(dhcpv6.MessageTypeRenew)
		r.link(false)
		r.link(true)
		r.answer(r.expect(dhcpv6.MessageTypeRebind), dhcpv6.MessageTypeReply, pd(time.Second, 300*time.Second))
		r.expect(dhcpv6.MessageTypeRenew)
		r.link(false)
		r.link(true)
		r.answer(r.expect(dhcpv6.MessageTypeRebind), dhcpv6.MessageTypeReply, gone)
		r.wait()

		// ended during the Renew, and during the Rebind after the link came back
		r.cycle()
		r.bound(pd(time.Second, 300*time.Second))
		r.expect(dhcpv6.MessageTypeRenew)
		r.stop()
		r.cycle()
		r.bound(pd(300*time.Second, 300*time.Second))
		r.link(false)
		r.link(true)
		r.expect(dhcpv6.MessageTypeRebind)
		r.stop()
	})

	t.Run("Release on exit", func(t *testing.T) {
		r := dhcp6cNewRig(t, s, 56, false)
		r.c.releaseOn = true
		r.cycle()
		r.bound(pd(300*time.Second, 300*time.Second))
		r.cancel()
		r.answer(r.expect(dhcpv6.MessageTypeRelease), dhcpv6.MessageTypeReply)
		r.wait()
	})

	t.Run("Confirm", func(t *testing.T) {
		r := dhcp6cNewRig(t, s, 0, true)
		r.cycle()
		r.bound(dhcp6cNA(netip.MustParseAddr("2001:db8:1::77")))
		r.link(false)
		r.link(true)
		cnf := r.expect(dhcpv6.MessageTypeConfirm)
		r.answer(cnf, dhcpv6.MessageTypeAdvertise)
		r.answer(cnf, dhcpv6.MessageTypeReply, &dhcpv6.OptStatusCode{StatusCode: iana.StatusSuccess})
		r.settled()

		// the client holds port 546 on the link-local address
		c := &dhcpClient{ifi: r.c.ifi}
		if err := c.openSocket(); err == nil {
			c.conn.Close()
			t.Fatal("a second socket on the client's port")
		}
		r.stop()
	})

	t.Run("WAN address refused by the kernel", func(t *testing.T) {
		store := newStore("pd", []lanDef{{"lan0", 0}}, time.Minute, nil, false, 0, 0, "")
		c := &dhcpClient{ifi: &net.Interface{Index: 1 << 20}, store: store}
		rep, _ := dhcpv6.NewMessage()
		rep.AddOption(dhcp6cNA(netip.MustParseAddr("2001:db8:1::78")))
		if l := c.apply(rep); l == nil || len(l.addrs) != 1 {
			t.Fatalf("the binding stands whatever the kernel says: %+v", l)
		}
	})

	t.Run("DAD", func(t *testing.T) {
		dup := netip.MustParseAddr("2001:db8:1::99")
		if err := addrSet(mustIface(t, "srv-test0"), dup, 64, time.Hour, time.Hour, false, ifaFNodad); err != nil {
			t.Fatal(err)
		}
		// DAD on, and quick: one probe of 100 ms
		for k, v := range map[string]string{"conf/wan-test0/accept_dad": "1", "neigh/wan-test0/retrans_time_ms": "100"} {
			if err := sysctlWrite("/proc/sys/net/ipv6/"+k, v); err != nil {
				t.Fatal(err)
			}
		}
		r := dhcp6cNewRig(t, s, 0, true)
		r.c.serverID = s.duid
		a := netip.MustParseAddr("2001:db8:1::a1")
		reply := func(addrs ...netip.Addr) *dhcpv6.Message {
			m, _ := dhcpv6.NewMessage()
			m.MessageType = dhcpv6.MessageTypeReply
			m.AddOption(dhcp6cNA(addrs...))
			return m
		}
		ctx := context.Background()
		r.link(false) // ends the Decline at once, unacknowledged
		if l := r.c.bind(ctx, reply(dup, a)); l == nil || !slices.Equal(l.addrs, []netip.Addr{a}) {
			t.Fatalf("want only %s, got %+v", a, l)
		}
		r.link(false)
		if l := r.c.bind(ctx, reply(dup)); l != nil {
			t.Fatalf("nothing left after the Decline: %+v", l)
		}
	})

	if err := <-waited; err != nil {
		t.Error(err)
	}
	cancel()
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
		t.Error("run did not return")
	}
}

// A link that goes down while the client waits for DAD takes the address with it (the kernel
// flushes addresses with a lifetime on a down link): that is no failed DAD, and nothing is declined.
func TestDHCPv6ClientAwaitDADLinkDownAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	dhcpv6Link(t)
	wan := mustIface(t, "wan-test0")
	a := netip.MustParseAddr("2001:db8:1::99")
	if err := addrSet(wan, a, 128, time.Hour, time.Hour, false, 0); err != nil {
		t.Fatal(err)
	}
	linkDown(t, wan)
	c := &dhcpClient{ifi: &net.Interface{Index: wan}}
	if failed := c.awaitDAD(context.Background(), []netip.Addr{a}); failed != nil {
		t.Fatalf("awaitDAD on a down link reports %v as failed", failed)
	}
}
