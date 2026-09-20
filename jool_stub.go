//go:build !linux

package main

import "context"

// joolManager speaks generic netlink to a Linux kernel module; the other platforms build for
// -dry-run, which configures nothing.
type joolManager struct {
	iname  string
	ranges int
}

func (m *joolManager) run(ctx context.Context, ch <-chan Snapshot) { <-ctx.Done() }
