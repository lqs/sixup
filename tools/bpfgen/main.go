// Command bpfgen compiles a BPF program for either byte order and writes what sixup loads it with,
// so that sixup itself parses no ELF and no BTF: the instructions, the maps, the read-only data and
// the relocations that tie them together. It wants clang and the libbpf headers.
//
// Usage: go run ./tools/bpfgen bpf/nat64.c nat64
//
// The program is one function in one section. Its maps are struct map_def values in the section
// maps, and its variables are volatile const ones in .rodata, which sixup fills in and freezes.
package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// The architectures Go builds for, by byte order
var orders = []struct {
	target string
	order  binary.ByteOrder
	arches string
}{
	{"bpfel", binary.LittleEndian, "386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64"},
	{"bpfeb", binary.BigEndian, "mips || mips64 || ppc64 || s390x"},
}

const rBPF6464 = 1 // R_BPF_64_64, the relocation of a 64-bit load, which debug/elf does not name

type mapDef struct {
	name                                string
	typ, keySize, valueSize, max, flags uint32
}

type varDef struct {
	name      string
	off, size uint64
}

type reloc struct {
	insn, m int
	off     int64 // where in the read-only data, or -1 for the map itself
}

type object struct {
	code    []byte
	maps    []mapDef // the read-only data last
	rodata  []byte
	vars    []varDef
	relocs  []reloc
	license string
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: bpfgen <program.c> <identifier>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "bpfgen:", err)
		os.Exit(1)
	}
}

func run(src, ident string) error {
	dir, err := os.MkdirTemp("", "bpfgen")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	var first *object
	for _, o := range orders {
		path := filepath.Join(dir, o.target+".o")
		cmd := exec.Command("clang", "-O2", "-Wall", "-Werror", "-target", o.target, "-mcpu=v3", "-c", src, "-o", path)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("clang -target %s: %w", o.target, err)
		}
		obj, err := parse(path, o.order)
		if err != nil {
			return fmt.Errorf("%s: %w", o.target, err)
		}
		if first == nil {
			first = obj
		} else if !slices.Equal(first.maps, obj.maps) || !slices.Equal(first.vars, obj.vars) {
			return errors.New("the byte orders disagree on the maps or the variables")
		}
		base := ident + "_" + o.target
		if err := os.WriteFile(base+".bin", obj.code, 0o644); err != nil {
			return err
		}
		if err := write(base+".go", perOrder(src, ident, base, o.arches, obj)); err != nil {
			return err
		}
	}
	return write(ident+"_bpf.go", shared(src, ident, first))
}

// parse reads the program, its maps, its read-only data and its relocations from an object.
func parse(path string, order binary.ByteOrder) (*object, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var prog *elf.Section
	section := map[string]elf.SectionIndex{}
	for i, s := range f.Sections {
		section[s.Name] = elf.SectionIndex(i)
		if s.Flags&elf.SHF_EXECINSTR != 0 && s.Size > 0 {
			if prog != nil {
				return nil, fmt.Errorf("one program section expected, found %s and %s", prog.Name, s.Name)
			}
			prog = s
		}
	}
	if prog == nil {
		return nil, errors.New("no program")
	}
	obj := &object{}
	if obj.code, err = prog.Data(); err != nil {
		return nil, err
	}
	data := func(name string) []byte {
		if s := f.Section(name); s != nil {
			b, _ := s.Data()
			return b
		}
		return nil
	}
	obj.license = strings.TrimRight(string(data("license")), "\x00")
	obj.rodata = data(".rodata")
	syms, err := f.Symbols()
	if err != nil {
		return nil, err
	}
	maps := data("maps")
	var mapOffs []uint64
	for _, s := range syms {
		switch {
		case s.Section == section["maps"] && len(maps) > 0:
			b := maps[s.Value:]
			obj.maps = append(obj.maps, mapDef{s.Name, order.Uint32(b), order.Uint32(b[4:]), order.Uint32(b[8:]), order.Uint32(b[12:]), order.Uint32(b[16:])})
			mapOffs = append(mapOffs, s.Value)
		case s.Section == section[".rodata"] && obj.rodata != nil && elf.ST_TYPE(s.Info) == elf.STT_OBJECT:
			obj.vars = append(obj.vars, varDef{s.Name, s.Value, s.Size})
		}
	}
	slices.SortFunc(obj.vars, func(a, b varDef) int { return int(a.off) - int(b.off) })
	rodataMap := len(obj.maps)
	obj.maps = append(obj.maps, mapDef{".rodata", 2, 4, uint32(len(obj.rodata)), 1, 0x80}) // BPF_MAP_TYPE_ARRAY, BPF_F_RDONLY_PROG

	rels := data(".rel" + prog.Name)
	for b := rels; len(b) >= 16; b = b[16:] {
		off, info := order.Uint64(b), order.Uint64(b[8:])
		if info&0xffffffff != rBPF6464 || info>>32 == 0 || int(info>>32) > len(syms) {
			return nil, fmt.Errorf("unsupported relocation %#x at %#x", info, off)
		}
		s := syms[info>>32-1] // Symbols leaves out the null symbol
		r := reloc{insn: int(off / 8), off: -1}
		switch s.Section {
		case section["maps"]:
			r.m = slices.Index(mapOffs, s.Value)
		case section[".rodata"]:
			r.m, r.off = rodataMap, int64(s.Value)+int64(int32(order.Uint32(obj.code[off+4:])))
		default:
			return nil, fmt.Errorf("relocation against %s, which is neither a map nor read-only data", s.Name)
		}
		obj.relocs = append(obj.relocs, r)
	}
	return obj, nil
}

func header(src, tags string) *bytes.Buffer {
	b := new(bytes.Buffer)
	fmt.Fprintf(b, "// Code generated by tools/bpfgen from %s; DO NOT EDIT.\n\n//go:build %s\n\npackage main\n\n", src, tags)
	return b
}

// perOrder is what differs between the byte orders: the code, its relocations and the read-only
// data as compiled.
func perOrder(src, ident, base, arches string, obj *object) []byte {
	b := header(src, "linux && ("+arches+")")
	fmt.Fprintf(b, "import _ \"embed\"\n\n//go:embed %s.bin\nvar %sCode []byte\n\n", base, ident)
	fmt.Fprintf(b, "var %sRodata = %#v\n\n", ident, obj.rodata)
	fmt.Fprintf(b, "var %sRelocs = []bpfReloc{\n", ident)
	for _, r := range obj.relocs {
		fmt.Fprintf(b, "\t{insn: %d, m: %s, off: %d},\n", r.insn, mapConst(ident, obj.maps[r.m].name), r.off)
	}
	b.WriteString("}\n")
	return b.Bytes()
}

// shared is what both byte orders have alike: the maps, the variables and the license.
func shared(src, ident string, obj *object) []byte {
	b := header(src, "linux")
	fmt.Fprintf(b, "const %sLicense = %q\n\n", ident, obj.license)
	fmt.Fprintf(b, "// The maps, the read-only data last\nconst (\n")
	for i, m := range obj.maps {
		fmt.Fprintf(b, "\t%s = %d\n", mapConst(ident, m.name), i)
	}
	fmt.Fprintf(b, ")\n\nvar %sMaps = []bpfMapSpec{\n", ident)
	for _, m := range obj.maps {
		fmt.Fprintf(b, "\t%s: {name: %q, typ: %d, keySize: %d, valueSize: %d, maxEntries: %d, flags: %#x},\n", mapConst(ident, m.name), m.name, m.typ, m.keySize, m.valueSize, m.max, m.flags)
	}
	fmt.Fprintf(b, "}\n\n// Where each variable sits in the read-only data, and its size\nvar (\n")
	for _, v := range obj.vars {
		fmt.Fprintf(b, "\t%sVar%s = bpfVar{off: %d, size: %d}\n", ident, camel(v.name), v.off, v.size)
	}
	b.WriteString(")\n")
	return b.Bytes()
}

func mapConst(ident, name string) string { return ident + "Map" + camel(name) }

// camel turns a C name into the rest of a Go one: v4_of becomes V4Of, .rodata Rodata.
func camel(name string) string {
	var b strings.Builder
	for w := range strings.FieldsFuncSeq(name, func(r rune) bool { return r == '_' || r == '.' }) {
		b.WriteString(strings.ToUpper(w[:1]) + w[1:])
	}
	return b.String()
}

func write(path string, src []byte) error {
	out, err := format.Source(src)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return os.WriteFile(path, out, 0o644)
}
