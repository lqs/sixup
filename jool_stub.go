//go:build !linux

package main

import (
	"context"
	"net/netip"
)

// joolManager speaks generic netlink to a Linux kernel module; the other platforms build for
// -dry-run, which configures nothing.
type joolManager struct {
	prefix netip.Prefix
	link   netip.Prefix
	store  *Store
}

func (m *joolManager) run(ctx context.Context) { <-ctx.Done() }

func checkJoolIPv4(netip.Prefix) error { return nil }
