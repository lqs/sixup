//go:build linux

package main

import (
	"bytes"
	"log"
	"os"
	"testing"

	"github.com/google/nftables"
)

// An element the library cannot put in a set is reported and the update dropped, before anything
// reaches the kernel.
func TestFirewallReplaceReportsABadSet(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	f := &firewall{}
	f.replace(&nftables.Set{Table: f.table(), Name: "anon", Anonymous: true, Constant: true, KeyType: nftables.TypeIP6Addr},
		[]nftables.SetElement{{Key: make([]byte, 16)}})
	if !bytes.Contains(logged.Bytes(), []byte("[firewall] anon:")) {
		t.Fatalf("the refused update should be reported:\n%s", logged.String())
	}
}
