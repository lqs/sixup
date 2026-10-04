//go:build linux && integration

package main

import (
	"context"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// pkthubTap creates a TAP device and brings it up; frames written to it arrive on the interface.
func pkthubTap(t *testing.T, name string) *os.File {
	t.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no TUN device: %v", err)
	}
	ifr, _ := unix.NewIfreq(name)
	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		t.Fatalf("TUNSETIFF %s: %v", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	t.Cleanup(func() { f.Close() })
	linkUp(t, mustIface(t, name))
	return f
}

// pkthubWait polls cond under the hub's lock until it holds.
func pkthubWait(t *testing.T, h *packetHub, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		h.mu.Lock()
		ok := cond()
		h.mu.Unlock()
		if ok {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// pkthubReceive writes f into the TAP until it shows up on the listener.
func pkthubReceive(t *testing.T, tap *os.File, s *packetSub, f []byte) {
	t.Helper()
	for range 20 {
		if _, err := tap.Write(f); err != nil {
			t.Fatal(err)
		}
		select {
		case <-s.C:
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("the frame never reached the listener")
}

// The capture socket opens once the interface appears, follows the listeners' filter, comes back
// after the link went down, and closes with the last listener.
func TestPacketHubAgainstKernel(t *testing.T) {
	if !ownNetns(t) { // the hub retries from timer goroutines
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newPacketHub(ctx, "pkt-test0")
	first := h.Subscribe(kindTunnel) // no such interface yet
	tap := pkthubTap(t, "pkt-test0")

	// A thread without CAP_NET_RAW finds the interface but cannot open the socket.
	denied := make(chan bool)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread goes with its reduced capabilities
		hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var caps [2]unix.CapUserData
		if err := unix.Capget(&hdr, &caps[0]); err != nil {
			t.Error(err)
		}
		caps[0].Effective &^= 1 << unix.CAP_NET_RAW
		if err := unix.Capset(&hdr, &caps[0]); err != nil {
			t.Error(err)
		}
		other := newPacketHub(ctx, "pkt-test0")
		s := other.Subscribe(kindTunnel)
		denied <- other.stop == nil && other.lastErr != ""
		s.Close()
	}()
	if !<-denied {
		t.Fatal("the socket should not open without CAP_NET_RAW")
	}

	pkthubWait(t, h, "the retry to open the socket", func() bool { return h.stop != nil })
	tunnel := captureFrame(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), 4, captureInner4(netip.MustParseAddr("192.0.0.2"), 6, 0, 80))
	pkthubReceive(t, tap, first, tunnel)

	h.mu.Lock()
	gen := h.gen
	h.mu.Unlock()
	idx := mustIface(t, "pkt-test0")
	linkDown(t, idx)
	pkthubWait(t, h, "the socket to go", func() bool { return h.stop == nil })
	linkUp(t, idx)
	pkthubWait(t, h, "the socket to come back", func() bool { return h.gen == gen+1 && h.stop != nil })
	pkthubReceive(t, tap, first, tunnel)

	same := h.Subscribe(kindTunnel)      // the same filter keeps the socket
	wider := h.Subscribe(kindTunnel | 2) // a wider one reopens it
	wider.Close()                        // and narrowing reopens it again
	same.Close()
	h.mu.Lock()
	if h.gen != gen+3 || h.stop == nil {
		t.Fatalf("generation %d, want %d", h.gen, gen+3)
	}
	h.mu.Unlock()
	// The readers of the closed sockets are gone: frames and the next link-down reach the current one
	pkthubReceive(t, tap, first, tunnel)
	linkDown(t, idx)
	pkthubWait(t, h, "the socket to go again", func() bool { return h.stop == nil })
	linkUp(t, idx)
	pkthubWait(t, h, "the socket to come back again", func() bool { return h.gen == gen+4 && h.stop != nil })
	pkthubReceive(t, tap, first, tunnel)

	first.Close()
	if h.stop != nil {
		t.Fatal("the last listener leaving closes the socket")
	}
}
