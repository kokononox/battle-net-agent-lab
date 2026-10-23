package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func put32(b []byte, o int, v uint32) { binary.LittleEndian.PutUint32(b[o:], v) }
func put64(b []byte, o int, v uint64) { binary.LittleEndian.PutUint64(b[o:], v) }
func fixture(memory64 bool) []byte {
	b := make([]byte, 1024)
	copy(b, "MDMP")
	put32(b, 4, 0xa793)
	put32(b, 8, 3)
	put32(b, 12, 32)
	// directory: module list, system info, memory stream
	put32(b, 32, 4)
	put32(b, 36, 112)
	put32(b, 40, 80)
	put32(b, 44, 7)
	put32(b, 48, 2)
	put32(b, 52, 200)
	binary.LittleEndian.PutUint16(b[200:], 9)
	put32(b, 80, 1)
	put64(b, 84, 0x150000000)
	put32(b, 92, 0x10000)
	put32(b, 100, 42)
	put32(b, 104, 220)
	name := []byte{'C', 0, ':', 0, '\\', 0, 'W', 0, 'o', 0, 'w', 0, '.', 0, 'e', 0, 'x', 0, 'e', 0}
	put32(b, 220, uint32(len(name)))
	copy(b[224:], name)
	if memory64 {
		put32(b, 56, 9)
		put32(b, 60, 48)
		put32(b, 64, 300)
		put64(b, 300, 2)
		put64(b, 308, 400)
		put64(b, 316, 0x150000000)
		put64(b, 324, 8)
		put64(b, 332, 0x150000008)
		put64(b, 340, 8)
	} else {
		put32(b, 56, 5)
		put32(b, 60, 36)
		put32(b, 64, 300)
		put32(b, 300, 2)
		put64(b, 304, 0x150000000)
		put32(b, 312, 8)
		put32(b, 316, 400)
		put64(b, 320, 0x150000008)
		put32(b, 328, 8)
		put32(b, 332, 408)
	}
	copy(b[400:], "0123456789abcdef")
	return b
}
func TestBothMemoryFormatsAndASLR(t *testing.T) {
	for _, m64 := range []bool{true, false} {
		b := fixture(m64)
		d, e := parseDump(bytes.NewReader(b), uint64(len(b)))
		if e != nil {
			t.Fatal(e)
		}
		m, e := d.wow()
		if e != nil || m.Base != 0x150000000 {
			t.Fatal(m, e)
		}
		v, e := d.memory(m.Base+5, 9)
		if e != nil || string(v) != "56789abcd" {
			t.Fatal(string(v), e)
		}
	}
}
func TestMissingAndOverflow(t *testing.T) {
	b := fixture(true)
	d, e := parseDump(bytes.NewReader(b), uint64(len(b)))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.memory(0x15000000f, 2); e == nil {
		t.Fatal("missing accepted")
	}
	if _, e = d.memory(^uint64(0)-1, 4); e == nil {
		t.Fatal("overflow accepted")
	}
}
func TestBadHeader(t *testing.T) {
	b := fixture(true)
	b[0] = 0
	if _, e := parseDump(bytes.NewReader(b), uint64(len(b))); e == nil {
		t.Fatal("bad header accepted")
	}
}
func TestBadArchitecture(t *testing.T) {
	b := fixture(true)
	put32(b, 200, 0)
	if _, e := parseDump(bytes.NewReader(b), uint64(len(b))); e == nil {
		t.Fatal("bad architecture accepted")
	}
}
func TestTruncated(t *testing.T) {
	for _, n := range []int{0, 16, 100, 350, 410} {
		b := fixture(true)[:n]
		if _, e := parseDump(bytes.NewReader(b), uint64(len(b))); e == nil {
			t.Fatal("truncated accepted", n)
		}
	}
}
func TestMappedOutOfFile(t *testing.T) {
	b := fixture(true)
	put64(b, 308, 1020)
	if _, e := parseDump(bytes.NewReader(b), uint64(len(b))); e == nil {
		t.Fatal("bad offset accepted")
	}
}
func TestOverlap(t *testing.T) {
	b := fixture(true)
	put64(b, 332, 0x150000004)
	if _, e := parseDump(bytes.NewReader(b), uint64(len(b))); e == nil {
		t.Fatal("overlap accepted")
	}
}
func TestVirtualOverflow(t *testing.T) {
	b := fixture(true)
	put64(b, 316, ^uint64(0)-1)
	if _, e := parseDump(bytes.NewReader(b), uint64(len(b))); e == nil {
		t.Fatal("VA overflow accepted")
	}
}
func TestOversizedCount(t *testing.T) {
	b := fixture(true)
	put64(b, 300, ^uint64(0))
	if _, e := parseDump(bytes.NewReader(b), uint64(len(b))); e == nil {
		t.Fatal("huge count accepted")
	}
}
func TestNoWow(t *testing.T) {
	b := fixture(true)
	b[230] = 'x'
	d, e := parseDump(bytes.NewReader(b), uint64(len(b)))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.wow(); e == nil {
		t.Fatal("wrong module accepted")
	}
}
func TestVersion(t *testing.T) {
	b := fixture(true)
	put32(b, 4, 0)
	if _, e := parseDump(bytes.NewReader(b), uint64(len(b))); e == nil {
		t.Fatal("wrong version accepted")
	}
}
func TestDuplicateStream(t *testing.T) {
	b := fixture(true)
	put32(b, 56, 4)
	if _, e := parseDump(bytes.NewReader(b), uint64(len(b))); e == nil {
		t.Fatal("duplicate stream accepted")
	}
}
func TestBadModuleSize(t *testing.T) {
	b := fixture(true)
	put32(b, 80, 2)
	if _, e := parseDump(bytes.NewReader(b), uint64(len(b))); e == nil {
		t.Fatal("bad module count accepted")
	}
}
func TestBadName(t *testing.T) {
	b := fixture(true)
	put32(b, 220, 19)
	if _, e := parseDump(bytes.NewReader(b), uint64(len(b))); e == nil {
		t.Fatal("odd name accepted")
	}
}
func TestBundleExcludesDump(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "snapshot.dmp"), []byte("private"), 0600)
	os.WriteFile(filepath.Join(d, "run.json"), []byte("{}"), 0600)
	dest := filepath.Join(t.TempDir(), "ready.zip")
	if e := bundle(d, dest); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(dest)
	if bytes.Contains(b, []byte("snapshot.dmp")) {
		t.Fatal("dump bundled")
	}
	if e := bundle(d, dest); e == nil {
		t.Fatal("overwritten zip")
	}
}
func TestWrongBuildRejected(t *testing.T) {
	d := t.TempDir()
	in := filepath.Join(d, "wrong.exe")
	os.WriteFile(in, []byte("wrong"), 0600)
	out := filepath.Join(d, "out")
	if e := extract("missing.dmp", in, out); e == nil {
		t.Fatal("wrong build accepted")
	}
	b, _ := os.ReadFile(filepath.Join(out, "analysis.json"))
	if !bytes.Contains(b, []byte("wrong Wow.exe SHA256")) {
		t.Fatal(string(b))
	}
}
func TestReadBounds(t *testing.T) {
	if _, e := readAt(bytes.NewReader([]byte("abcd")), 4, ^uint64(0), 4); e == nil {
		t.Fatal("offset overflow accepted")
	}
}
func TestUnicode(t *testing.T) {
	if decodeUTF16([]byte{0x3d, 0xd8, 0x00, 0xde}) != "😀" {
		t.Fatal("UTF16 surrogate failure")
	}
}
