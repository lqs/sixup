//go:build !linux

package main

import (
	"context"
	"net/netip"
)

// firewall writes nftables through netlink, which exists only on Linux.
type firewall struct {
	wan     string
	inbound bool
	source  bool
	holeIn  chan []portMapping
	delegIn chan []netip.Prefix
}

func (f *firewall) run(ctx context.Context, ch <-chan Snapshot) { <-ctx.Done() }
