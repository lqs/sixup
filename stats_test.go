package main

import (
	"slices"
	"strings"
	"testing"
)

func TestDiagnose(t *testing.T) {
	for _, c := range []struct {
		m    map[string]int
		want []string
	}{
		{map[string]int{}, []string{"No RS sent", "No DHCPv6 SOLICIT sent", "No IPv4-in-IPv6"}},
		{map[string]int{"rs_sent": 1, "ppp_default_route": 1, "solicit_sent": 1, "tunnel_pkt": 1}, []string{"PPP link", "no ADVERTISE"}},
		{map[string]int{"rs_sent": 1, "solicit_sent": 1, "advertise_recv": 1, "request_sent": 1, "tunnel_pkt": 1, "pd_refused": 1}, []string{"upstream does not send RA", "REQUEST sent but no REPLY", "NoPrefixAvail"}},
		{map[string]int{"ra_recv": 1, "solicit_sent": 1, "reply_recv": 1, "tunnel_pkt": 1}, []string{"without a prefix option"}},
		{map[string]int{"ra_recv": 1, "ra_prefix": 1, "solicit_sent": 1, "reply_recv": 1, "tunnel_pkt": 1}, nil},
	} {
		got := diagnose(c.m)
		if len(got) != len(c.want) {
			t.Errorf("%v: got %q, want %q", c.m, got, c.want)
			continue
		}
		for i, w := range c.want {
			if !strings.Contains(got[i], w) {
				t.Errorf("%v: hint %d is %q, want %q", c.m, i, got[i], w)
			}
		}
	}
}

func TestStatSnapshot(t *testing.T) {
	statInc("test_b")
	statInc("test_a")
	statInc("test_a")
	m := statSnapshot()
	if m["test_a"] != 2 || m["test_b"] != 1 {
		t.Errorf("got %v", m)
	}
	m["test_a"] = 9 // a copy, not the live map
	if statSnapshot()["test_a"] != 2 {
		t.Error("the snapshot shares the live counters")
	}
	if got := statKeys(map[string]int{"b": 1, "a": 1, "c": 1}); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Errorf("statKeys = %v", got)
	}
}
