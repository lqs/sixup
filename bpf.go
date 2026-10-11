//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A small loader for the programs tools/bpfgen prepares: the bpf() system call and nothing else,
// so that sixup carries no ELF or BTF parser. The attribute layouts are those of union bpf_attr
// in linux/bpf.h.

type bpfMapSpec struct {
	name                                       string
	typ, keySize, valueSize, maxEntries, flags uint32
}

// bpfReloc points a 64-bit load of the code at a map, or at an offset into the read-only data.
type bpfReloc struct {
	insn, m int
	off     int64 // -1 for the map itself
}

type bpfVar struct{ off, size int }

// bpfProgram is what tools/bpfgen writes for one program, with the read-only data filled in.
type bpfProgram struct {
	code    []byte
	maps    []bpfMapSpec
	relocs  []bpfReloc
	rodata  []byte
	license string
}

// bpfObjects is a program loaded with its maps.
type bpfObjects struct {
	maps []*bpfMap
	prog int
}

// srcShift is where the source register sits in the second byte of an instruction: its high
// nibble on a little-endian machine, its low one on a big-endian one.
var srcShift = 4 * (nativeEndian.Uint16([]byte{1, 0}) & 1)

func bpfSys(cmd int, attr unsafe.Pointer, size uintptr) (int, error) {
	r, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
	runtime.KeepAlive(attr)
	if errno != 0 {
		return -1, errno
	}
	return int(r), nil
}

func ptr(b []byte) uint64 {
	if len(b) == 0 {
		return 0
	}
	return uint64(uintptr(unsafe.Pointer(&b[0])))
}

type bpfMap struct {
	fd        int
	spec      bpfMapSpec
	valueSize int // per CPU too for the per-CPU ones
}

func bpfMapCreate(spec bpfMapSpec) (*bpfMap, error) {
	attr := struct {
		typ, keySize, valueSize, maxEntries, flags, innerMapFd, numaNode uint32
		name                                                             [16]byte
	}{typ: spec.typ, keySize: spec.keySize, valueSize: spec.valueSize, maxEntries: spec.maxEntries, flags: spec.flags}
	copy(attr.name[:15], strings.TrimPrefix(spec.name, "."))
	fd, err := bpfSys(unix.BPF_MAP_CREATE, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return nil, fmt.Errorf("creating the map %s: %w", spec.name, err)
	}
	m := &bpfMap{fd: fd, spec: spec, valueSize: int(spec.valueSize)}
	if spec.typ == unix.BPF_MAP_TYPE_PERCPU_ARRAY || spec.typ == unix.BPF_MAP_TYPE_PERCPU_HASH {
		m.valueSize = ((m.valueSize + 7) &^ 7) * possibleCPUs() // each CPU's rounded up to 8 bytes
	}
	return m, nil
}

func (m *bpfMap) close() { unix.Close(m.fd) }

// elem is one of the map element commands, with key, and value or next key.
func (m *bpfMap) elem(cmd int, key, value []byte, flags uint64) error {
	attr := struct {
		fd, _      uint32
		key, value uint64
		flags      uint64
	}{fd: uint32(m.fd), key: ptr(key), value: ptr(value), flags: flags}
	_, err := bpfSys(cmd, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return err
}

// lookup fills value, which for a per-CPU map holds every CPU's, and fails with ENOENT for a key
// the map does not have.
func (m *bpfMap) lookup(key, value []byte) error {
	return m.elem(unix.BPF_MAP_LOOKUP_ELEM, key, value, 0)
}

func (m *bpfMap) update(key, value []byte, flags uint64) error {
	return m.elem(unix.BPF_MAP_UPDATE_ELEM, key, value, flags)
}

func (m *bpfMap) delete(key []byte) error { return m.elem(unix.BPF_MAP_DELETE_ELEM, key, nil, 0) }

// keys returns the keys in the map, as many as it lists in one pass.
func (m *bpfMap) keys() [][]byte {
	var keys [][]byte
	var key []byte // nil asks for the first
	for {
		next := make([]byte, m.spec.keySize)
		if m.elem(unix.BPF_MAP_GET_NEXT_KEY, key, next, 0) != nil {
			return keys
		}
		keys = append(keys, next)
		key = next
	}
}

// possibleCPUs counts the CPUs a per-CPU map has a value for: /sys/devices/system/cpu/possible,
// such as 0-3 or 0,2-5.
func possibleCPUs() int {
	b, _ := os.ReadFile("/sys/devices/system/cpu/possible") // sysfs is there wherever BPF is
	n := 0
	for r := range strings.SplitSeq(strings.TrimSpace(string(b)), ",") {
		lo, hi, ok := strings.Cut(r, "-")
		first, _ := strconv.Atoi(lo)
		last := first
		if ok {
			last, _ = strconv.Atoi(hi)
		}
		n += last - first + 1
	}
	return n
}

// bpfLoad creates the maps, fills in and freezes the read-only data, points the code at both
// and loads it as a tc program. A program the verifier refuses comes back with the end of its log.
func bpfLoad(p bpfProgram) (_ *bpfObjects, err error) {
	objs := &bpfObjects{prog: -1}
	defer func() {
		if err != nil {
			objs.close()
		}
	}()
	for _, spec := range p.maps {
		m, err := bpfMapCreate(spec)
		if err != nil {
			return nil, err
		}
		objs.maps = append(objs.maps, m)
	}
	ro := objs.maps[len(objs.maps)-1]
	freeze := func() error {
		attr := struct{ fd uint32 }{uint32(ro.fd)}
		_, err := bpfSys(unix.BPF_MAP_FREEZE, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
		return err
	}
	if err := errors.Join(ro.update(make([]byte, 4), p.rodata, 0), freeze()); err != nil {
		return nil, fmt.Errorf("filling in and freezing the read-only data: %w", err)
	}

	code := append([]byte(nil), p.code...)
	for _, r := range p.relocs {
		insn := code[r.insn*8:]
		src := byte(unix.BPF_PSEUDO_MAP_FD)
		if r.off >= 0 {
			src = unix.BPF_PSEUDO_MAP_VALUE
			nativeEndian.PutUint32(insn[12:], uint32(r.off)) // the second half of the 64-bit load
		}
		insn[1] = insn[1]&^(0xf<<srcShift) | src<<srcShift
		nativeEndian.PutUint32(insn[4:], uint32(objs.maps[r.m].fd))
	}
	license := append([]byte(p.license), 0)
	load := func(log []byte) (int, error) {
		attr := struct {
			typ, insnCnt      uint32
			insns, license    uint64
			logLevel, logSize uint32
			logBuf            uint64
		}{typ: unix.BPF_PROG_TYPE_SCHED_CLS, insnCnt: uint32(len(code) / 8), insns: ptr(code), license: ptr(license), logSize: uint32(len(log)), logBuf: ptr(log)}
		if log != nil {
			attr.logLevel = 1
		}
		fd, err := bpfSys(unix.BPF_PROG_LOAD, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
		runtime.KeepAlive(code)
		runtime.KeepAlive(license)
		runtime.KeepAlive(log)
		return fd, err
	}
	if objs.prog, err = load(nil); err != nil {
		log := make([]byte, 1<<20)
		load(log)
		lines := strings.Split(strings.TrimRight(string(log[:max(0, bytes.IndexByte(log, 0))]), "\n"), "\n")
		return nil, fmt.Errorf("loading the program: %w: %s", err, strings.Join(lines[max(0, len(lines)-3):], "; "))
	}
	return objs, nil
}

func (o *bpfObjects) close() {
	for _, m := range o.maps {
		m.close()
	}
	if o.prog >= 0 {
		unix.Close(o.prog)
	}
}

// attachTCX attaches the program to the egress of a device; closing the descriptor it returns
// detaches it, and so does sixup ending.
func (o *bpfObjects) attachTCX(ifindex int) (int, error) {
	attr := struct {
		prog, ifindex, attachType, flags uint32
		relative, _                      uint32
		expectedRevision                 uint64
	}{prog: uint32(o.prog), ifindex: uint32(ifindex), attachType: unix.BPF_TCX_EGRESS}
	return bpfSys(unix.BPF_LINK_CREATE, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
}

// errRingClosed is what a ring buffer reader returns once closed.
var errRingClosed = errors.New("ring buffer closed")

// ringReader reads the records of a BPF ring buffer: the consumer position on a page it writes,
// the producer position on the next, and the data mapped twice after it, so that a record that
// wraps around reads straight through. An eventfd in the same epoll set wakes it to stop.
type ringReader struct {
	cons, prod []byte
	mask       uint64
	epfd, evfd int
}

func newRingReader(m *bpfMap) (_ *ringReader, err error) {
	page := os.Getpagesize()
	r := &ringReader{mask: uint64(m.spec.maxEntries) - 1, epfd: -1, evfd: -1}
	defer func() {
		if err != nil {
			r.free()
		}
	}()
	if r.cons, err = unix.Mmap(m.fd, 0, page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED); err != nil {
		return nil, err
	}
	if r.prod, err = unix.Mmap(m.fd, int64(page), page+2*int(m.spec.maxEntries), unix.PROT_READ, unix.MAP_SHARED); err != nil {
		return nil, err
	}
	if r.epfd, err = unix.EpollCreate1(unix.EPOLL_CLOEXEC); err != nil {
		return nil, err
	}
	if r.evfd, err = unix.Eventfd(0, unix.EFD_CLOEXEC); err != nil {
		return nil, err
	}
	for _, fd := range []int{m.fd, r.evfd} {
		// A new descriptor in a new set, which fails only for want of memory
		unix.EpollCtl(r.epfd, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)})
	}
	return r, nil
}

// read returns the next record, waiting for one, or errRingClosed once close is called.
func (r *ringReader) read() ([]byte, error) {
	page := uint64(os.Getpagesize())
	cons := (*uint64)(unsafe.Pointer(&r.cons[0]))
	prod := (*uint64)(unsafe.Pointer(&r.prod[0]))
	events := make([]unix.EpollEvent, 2)
	for {
		// A record the program is still writing is waited for like none: committing it wakes
		// the reader that has not consumed it. The program discards none.
		if c := atomic.LoadUint64(cons); c < atomic.LoadUint64(prod) {
			off := page + c&r.mask
			if hdr := atomic.LoadUint32((*uint32)(unsafe.Pointer(&r.prod[off]))); hdr&unix.BPF_RINGBUF_BUSY_BIT == 0 {
				n := uint64(hdr)
				rec := append([]byte(nil), r.prod[off+unix.BPF_RINGBUF_HDR_SZ:][:n]...)
				atomic.StoreUint64(cons, c+(n+unix.BPF_RINGBUF_HDR_SZ+7)&^7)
				return rec, nil
			}
		}
		n, err := unix.EpollWait(r.epfd, events, -1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range events[:n] {
			if int(e.Fd) == r.evfd {
				return nil, errRingClosed
			}
		}
	}
}

// close makes read return; free releases the reader once nothing reads.
func (r *ringReader) close() { unix.Write(r.evfd, []byte{1, 0, 0, 0, 0, 0, 0, 0}) }

func (r *ringReader) free() {
	for _, b := range [][]byte{r.cons, r.prod} {
		if b != nil {
			unix.Munmap(b)
		}
	}
	for _, fd := range []int{r.epfd, r.evfd} {
		if fd >= 0 {
			unix.Close(fd)
		}
	}
}
