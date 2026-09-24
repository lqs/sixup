//go:build linux

package main

import (
	"strings"
	"testing"
)

func TestClaimInterfaces(t *testing.T) {
	first, err := claimInterfaces([]string{"sixup-test0", "sixup-test1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := claimInterfaces([]string{"sixup-test2", "sixup-test1"}); err == nil || !strings.Contains(err.Error(), "sixup-test1") {
		t.Fatalf("second claim on sixup-test1: got %v, want an error naming it", err)
	}
	// The failed claim must not keep sixup-test2.
	second, err := claimInterfaces([]string{"sixup-test2"})
	if err != nil {
		t.Fatal(err)
	}
	closeAll(second)
	closeAll(first)
	again, err := claimInterfaces([]string{"sixup-test0", "sixup-test1"})
	if err != nil {
		t.Fatalf("claim after release: %v", err)
	}
	closeAll(again)
}
