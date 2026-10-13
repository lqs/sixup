//go:build !linux

package main

import "context"

// clatManager builds a CLAT with BPF, which only Linux has; the other platforms build for
// -dry-run, which configures nothing.
type clatManager struct {
	wan    string
	secret []byte
	sysctl bool
}

func (c *clatManager) run(ctx context.Context, _ <-chan Snapshot) { <-ctx.Done() }
