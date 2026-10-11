//go:build linux && integration

package main

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A program whose read-only data cannot be written is refused before it is loaded.
func TestBPFLoadRefusesUnwritableData(t *testing.T) {
	_, err := bpfLoad(bpfProgram{
		maps:   []bpfMapSpec{{name: ".rodata", typ: unix.BPF_MAP_TYPE_ARRAY, keySize: 4, valueSize: 4, maxEntries: 1, flags: unix.BPF_F_RDONLY}},
		rodata: make([]byte, 4),
	})
	if err == nil || !strings.Contains(err.Error(), "read-only data") {
		t.Fatalf("want the data refused, got %v", err)
	}
}

// A ring buffer reader needs a map it can map, twice over past the first page; once its epoll
// set is gone, reading fails.
func TestRingReaderFailures(t *testing.T) {
	for name, spec := range map[string]bpfMapSpec{
		"a hash map":       {typ: unix.BPF_MAP_TYPE_HASH, keySize: 4, valueSize: 4, maxEntries: 1},
		"a one-page array": {typ: unix.BPF_MAP_TYPE_ARRAY, keySize: 4, valueSize: 8, maxEntries: 1, flags: unix.BPF_F_MMAPABLE},
	} {
		m, err := bpfMapCreate(spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := newRingReader(m); err == nil {
			t.Errorf("%s: want the reader refused", name)
		}
		m.close()
	}
	m, err := bpfMapCreate(bpfMapSpec{typ: unix.BPF_MAP_TYPE_RINGBUF, maxEntries: 1 << 12})
	if err != nil {
		t.Fatal(err)
	}
	defer m.close()
	r, err := newRingReader(m)
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(r.epfd)
	if _, err := r.read(); err == nil {
		t.Fatal("want reading without an epoll set to fail")
	}
	r.epfd = -1
	r.free()
}
