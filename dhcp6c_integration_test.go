//go:build linux && integration

package main

import (
	"context"
	"flag"
	"net"
	"net/netip"
	"os"
	"os/exec"
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
	// under -coverprofile the child writes a profile of its own next to the parent's
	if f := flag.Lookup("test.coverprofile"); f != nil && f.Value.String() != "" {
		args = append(args, "-test.coverprofile="+f.Value.String()+"."+t.Name())
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
