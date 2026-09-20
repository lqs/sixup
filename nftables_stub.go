//go:build !linux

package main

import "context"

// natManager configures nftables through netlink, which exists only on Linux. The other platforms
// build for -dry-run, where no ruleset is written in any case.
type natManager struct {
	dev        string
	mtu        int
	joolRanges int
}

func (m *natManager) run(ctx context.Context, ch <-chan Snapshot) { <-ctx.Done() }
