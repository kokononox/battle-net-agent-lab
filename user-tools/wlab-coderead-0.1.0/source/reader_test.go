package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeTarget struct {
	meta                                      identity
	disk                                      diskSpec
	memory                                    map[uint64][]byte
	reads                                     []uint64
	guard, partial                            uint64
	denied                                    bool
	changedAfter, headerChanged, queryFailure bool
	identityCalls                             int
	headerReads                               int
}

func fixture() (*fakeTarget, diskSpec) {
	d := diskSpec{Stamp: 12345, Size: 0x4000000, Pages: map[uint32][]byte{}}
	base := uint64(0x150000000)
	h := make([]byte, 4096)
	copy(h, "MZ")
	le.PutUint32(h[0x3c:], 0x80)
	copy(h[0x80:], "PE\x00\x00")
	le.PutUint16(h[0x84:], 0x8664)
	le.PutUint32(h[0x88:], d.Stamp)
	le.PutUint16(h[0x80+24:], 0x20b)
	le.PutUint32(h[0x80+24+56:], d.Size)
	f := &fakeTarget{meta: identity{PID: 123, Start: 456, Path: `G:\Games\Wow.exe`, ModulePath: `G:\Games\Wow.exe`, Base: base, ImageSize: d.Size}, memory: map[uint64][]byte{base: h}}
	for _, rva := range pagePlan {
		b := bytes.Repeat([]byte{0x90}, 4096)
		d.Pages[rva] = append([]byte{}, b...)
		f.memory[base+uint64(rva)] = b
	}
	f.disk = d
	return f, d
}
func (f *fakeTarget) Identity() (identity, error) {
	f.identityCalls++
	id := f.meta
	if f.changedAfter && f.identityCalls >= 2 {
		id.Start++
	}
	return id, nil
}
func (f *fakeTarget) Region(a uint64) (region, error) {
	if f.queryFailure {
		return region{}, errors.New("mock query denied")
	}
	r := region{Base: a, AllocationBase: f.meta.Base, Size: 4096, State: 0x1000, Protect: 0x20, Type: 0x1000000}
	if a == f.guard {
		r.Protect |= 0x100
	}
	return r, nil
}
func (f *fakeTarget) Read(a uint64, n uint32) ([]byte, error) {
	f.reads = append(f.reads, a)
	if f.denied {
		return nil, &apiFailure{API: "ReadProcessMemory", Code: 5, Message: "mock access denied"}
	}
	b := append([]byte{}, f.memory[a]...)
	if a == f.partial {
		return b[:10], nil
	}
	if a == f.meta.Base {
		f.headerReads++
		if f.headerChanged && f.headerReads > 1 {
			b[0x200] ^= 1
		}
	}
	return b, nil
}
func (f *fakeTarget) Close() error { return nil }
func runFake(f *fakeTarget, d diskSpec) (map[string][]byte, map[string]any, error) {
	r := map[string]any{}
	b, e := collect(f, 123, 456, f.meta, d, r)
	return b, r, e
}
func TestBoundedReadUnchanged(t *testing.T) {
	f, d := fixture()
	files, r, e := runFake(f, d)
	if e != nil {
		t.Fatal(e)
	}
	if len(f.reads) != 5 || len(files) != 6 || r["bytes_exported"] != 12666 {
		t.Fatal(len(f.reads), len(files), r)
	}
	for _, c := range candidatePlan {
		if len(files[c.Name+".bin"]) != int(c.Size) {
			t.Fatal(c.Name)
		}
	}
}
func TestRawChangedCodeCapturedWithoutClaimingDecryption(t *testing.T) {
	f, d := fixture()
	f.memory[f.meta.Base+0x1b11000][0x190] = 0xc3
	files, _, e := runFake(f, d)
	if e != nil || files["creator_candidate.bin"][0] != 0xc3 {
		t.Fatal(e)
	}
}
func TestGuardStopsBeforePageRead(t *testing.T) {
	f, d := fixture()
	f.guard = f.meta.Base + uint64(pagePlan[0])
	files, _, e := runFake(f, d)
	if e == nil || files != nil || len(f.reads) != 1 {
		t.Fatal(e, files, f.reads)
	}
}
func TestPartialReadIsNotZeroFilledOrExported(t *testing.T) {
	f, d := fixture()
	f.partial = f.meta.Base + uint64(pagePlan[1])
	files, _, e := runFake(f, d)
	if e == nil || files != nil || len(f.reads) != 3 {
		t.Fatal(e)
	}
}
func TestAccessDeniedNoRetry(t *testing.T) {
	f, d := fixture()
	f.denied = true
	files, _, e := runFake(f, d)
	var native *apiFailure
	if e == nil || files != nil || len(f.reads) != 1 || !errors.As(e, &native) || native.Code != 5 {
		t.Fatal(e)
	}
}
func TestIdentityChangeDiscardsStagedBytes(t *testing.T) {
	f, d := fixture()
	f.changedAfter = true
	files, _, e := runFake(f, d)
	if e == nil || files != nil || len(f.reads) != 4 {
		t.Fatal(e)
	}
}
func TestHeaderChangeDiscardsStagedBytes(t *testing.T) {
	f, d := fixture()
	f.headerChanged = true
	files, _, e := runFake(f, d)
	if e == nil || files != nil || len(f.reads) != 5 {
		t.Fatal(e)
	}
}
func TestWrongLoadedHeaderStopsBeforeCode(t *testing.T) {
	f, d := fixture()
	f.memory[f.meta.Base][0x88] ^= 1
	files, _, e := runFake(f, d)
	if e == nil || files != nil || len(f.reads) != 1 {
		t.Fatal(e)
	}
}
func TestQueryFailureDoesNotCallRead(t *testing.T) {
	f, d := fixture()
	f.queryFailure = true
	files, _, e := runFake(f, d)
	if e == nil || files != nil || len(f.reads) != 0 {
		t.Fatal(e)
	}
}
func TestReadableRegionRules(t *testing.T) {
	good := region{Base: 0x1000, AllocationBase: 0x1000, Size: 4096, State: 0x1000, Protect: 0x20, Type: 0x1000000}
	for _, p := range []uint32{2, 4, 8, 0x20, 0x40, 0x80} {
		r := good
		r.Protect = p
		if validRegion(r, 0x1000, 0x1000, 4096) != nil {
			t.Fatal(p)
		}
	}
	for _, p := range []uint32{0, 1, 0x10, 0x120} {
		r := good
		r.Protect = p
		if validRegion(r, 0x1000, 0x1000, 4096) == nil {
			t.Fatal(p)
		}
	}
	r := good
	r.Type = 0x20000
	if validRegion(r, 0x1000, 0x1000, 4096) == nil {
		t.Fatal("private memory accepted")
	}
	r = good
	r.Size = 4000
	if validRegion(r, 0x1000, 0x1000, 4096) == nil {
		t.Fatal("bounds")
	}
}
func TestReportBundleWhitelist(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(t.TempDir(), "r.zip")
	for _, n := range []string{"run.json", "analysis.json", "creator_candidate.bin", "page-01b11000.bin", "snapshot.dmp", "arbitrary.bin", "read.result.json"} {
		os.WriteFile(filepath.Join(dir, n), []byte("test"), 0600)
	}
	if e := bundle(dir, dest); e != nil {
		t.Fatal(e)
	}
	z, e := zip.OpenReader(dest)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	if len(z.File) != 5 {
		t.Fatal(len(z.File))
	}
}
func TestNativeBackendDoesNotRequestWritesOrDebugger(t *testing.T) {
	b, e := os.ReadFile("native_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	if !strings.Contains(s, "0x0400|0x0010") && !strings.Contains(s, "0x0400 | 0x0010") {
		t.Fatal("unexpected process access rights")
	}
	for _, bad := range []string{"WriteProcessMemory", "VirtualProtectEx", "DebugActiveProcess", "CreateRemoteThread", "AdjustTokenPrivileges", "SuspendThread", "NtSuspendProcess", "PssCaptureSnapshot"} {
		if strings.Contains(s, bad) {
			t.Fatal("unapproved API", bad)
		}
	}
}
func TestPinnedDiskFixtureWhenAvailable(t *testing.T) {
	path := os.Getenv("WLAB_PINNED_WOW")
	if path == "" {
		t.Skip("external pinned disk fixture not configured")
	}
	d, e := loadDisk(path)
	if e != nil || len(d.Pages) != 3 || d.Size == 0 {
		t.Fatal(e)
	}
}
func TestWrongDiskHashRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "Wow.exe")
	os.WriteFile(p, []byte("not the pinned game"), 0600)
	if _, e := loadDisk(p); e == nil {
		t.Fatal("unpinned disk accepted")
	}
}

func TestStartTimeMismatchStopsBeforeRead(t *testing.T) {
	f, d := fixture()
	f.meta.Start++
	files, _, e := runFake(f, d)
	if e == nil || files != nil || len(f.reads) != 0 {
		t.Fatal(e)
	}
}
func TestModulePathMismatchStopsBeforeRead(t *testing.T) {
	f, d := fixture()
	f.meta.ModulePath = `G:\Other\Wow.exe`
	files, _, e := runFake(f, d)
	if e == nil || files != nil || len(f.reads) != 0 {
		t.Fatal(e)
	}
}
func TestModuleSizeMismatchStopsBeforeRead(t *testing.T) {
	f, d := fixture()
	f.meta.ImageSize++
	files, _, e := runFake(f, d)
	if e == nil || files != nil || len(f.reads) != 0 {
		t.Fatal(e)
	}
}
