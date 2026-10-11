//go:build !linux

package main

import (
	"context"
	"net/netip"
)

type bpfNAT64 struct {
	prefix netip.Prefix
	lans   []string
	store  *Store
}

func (b *bpfNAT64) run(ctx context.Context) { <-ctx.Done() }
