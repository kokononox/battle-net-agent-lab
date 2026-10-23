package main

import (
	"archive/zip"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func tinyPE() []byte {
	b := make([]byte, 0x800)
	copy(b, "MZ")
	le.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	le.PutUint16(b[0x84:], 0x8664)
	le.PutUint16(b[0x86:], 1)
	le.PutUint16(b[0x94:], 0xf0)
	o := 0x98
	le.PutUint16(b[o:], 0x20b)
	le.PutUint64(b[o+24:], 0x180000000)
	le.PutUint32(b[o+32:], 0x1000)
	le.PutUint32(b[o+36:], 0x200)
	le.PutUint32(b[o+56:], 0x2000)
	le.PutUint32(b[o+60:], 0x200)
	le.PutUint32(b[o+108:], 16)
	le.PutUint32(b[o+112:], 0x1000)
	le.PutUint32(b[o+116:], 0x100)
	s := o + 0xf0
	copy(b[s:], ".rdata")
	le.PutUint32(b[s+8:], 0x1000)
	le.PutUint32(b[s+12:], 0x1000)
	le.PutUint32(b[s+16:], 0x600)
	le.PutUint32(b[s+20:], 0x200)
	le.PutUint32(b[s+36:], 0x40000040)
	e := 0x200
	for off, v := range map[int]uint32{16: 1, 20: 1, 24: 2, 28: 0x1080, 32: 0x1090, 36: 0x10a0} {
		le.PutUint32(b[e+off:], v)
	}
	le.PutUint32(b[0x280:], 0x1800)
	le.PutUint32(b[0x290:], 0x1120)
	le.PutUint32(b[0x294:], 0x1160)
	le.PutUint16(b[0x2a0:], 0)
	le.PutUint16(b[0x2a2:], 0)
	copy(b[0x320:], "SetUnhandledExceptionFilter\x00")
	copy(b[0x360:], "AliasFilter\x00")
	return b
}

var once sync.Once
var realWow, realLoader []byte
var fixtureErr error

func fixtures(t *testing.T) ([]byte, []byte) {
	t.Helper()
	once.Do(func() {
		realWow, fixtureErr = os.ReadFile("/data/wlab-inputs/Wow.exe")
		if fixtureErr == nil {
			realLoader, fixtureErr = os.ReadFile("/data/wlab-inputs/wow_loader.dll")
		}
	})
	if fixtureErr != nil {
		t.Skip("pinned fixture unavailable: " + fixtureErr.Error())
	}
	return realWow, realLoader
}

type fakeTarget struct {
	id                                    identity
	mods                                  []moduleInfo
	r                                     region
	idCalls, modCalls, regionCalls, reads int
	value                                 uint64
	partial                               bool
	readErr, errorRegion                  bool
	changeID, changeMods, changeRegion    bool
	lastN                                 uint32
	lastAddr                              uint64
}

func (f *fakeTarget) Identity() (identity, error) {
	f.idCalls++
	v := f.id
	if f.changeID && f.idCalls > 1 {
		v.Start++
	}
	return v, nil
}
func (f *fakeTarget) Modules() ([]moduleInfo, error) {
	f.modCalls++
	v := append([]moduleInfo{}, f.mods...)
	if f.changeMods && f.modCalls > 1 {
		v[1].Base++
	}
	return v, nil
}
func (f *fakeTarget) Region(a uint64) (region, error) {
	f.regionCalls++
	if f.errorRegion {
		return region{}, fmt.Errorf("query failed")
	}
	v := f.r
	if f.changeRegion && f.regionCalls > 1 {
		v.Protect = 4
	}
	return v, nil
}
func (f *fakeTarget) Read(a uint64, n uint32) ([]byte, error) {
	f.reads++
	f.lastN = n
	f.lastAddr = a
	if n != 8 || f.reads > 1 {
		panic("read cap")
	}
	b := make([]byte, 8)
	le.PutUint64(b, f.value)
	if f.readErr {
		return nil, &apiFailure{"ReadProcessMemory", 5, "fake denied"}
	}
	if f.partial {
		return b[:3], nil
	}
	return b, nil
}
func (f *fakeTarget) Close() error { return nil }
func setup(t *testing.T) (*fakeTarget, fileReader, trustManifest) {
	t.Helper()
	w, l := fixtures(t)
	dw, e := loadImage(w)
	if e != nil {
		t.Fatal(e)
	}
	dl, e := loadImage(l)
	if e != nil {
		t.Fatal(e)
	}
	if dw.Hash != wowHash || dl.Hash != loaderHash {
		t.Fatal("actual fixture pin mismatch")
	}
	owner := tinyPE()
	d, e := loadImage(owner)
	if e != nil {
		t.Fatal(e)
	}
	f := &fakeTarget{id: identity{77, 123, "G:/World of Warcraft/_retail_/Wow.exe"}, mods: []moduleInfo{{"Wow.exe", "G:/World of Warcraft/_retail_/Wow.exe", 0x140000000, dw.Size}, {"wow_loader.dll", "G:/World of Warcraft/_retail_/wow_loader.dll", 0x180000000, dl.Size}, {"KernelBase.dll", "C:/Windows/System32/KernelBase.dll", 0x7ffb00000000, d.Size}}, value: 0x7ffb00001800}
	a := f.mods[1].Base + slotRVA
	f.r = region{a &^ 4095, f.mods[1].Base, 4096, 0x1000, 2, 0x40000}
	fs := func(path string) ([]byte, error) {
		switch norm(path) {
		case norm(f.mods[0].Path):
			return w, nil
		case norm(f.mods[1].Path):
			return l, nil
		case norm(f.mods[2].Path):
			return owner, nil
		}
		return nil, fmt.Errorf("unexpected file path")
	}
	tm := trustManifest{"PowerShell Get-AuthenticodeSignature + Get-FileHash", []trustEntry{{f.mods[2].Path, d.Hash, "Valid", "CN=Microsoft Windows, O=Microsoft Corporation"}}}
	return f, fs, tm
}
func TestExportAliasesPreserved(t *testing.T) {
	d, e := loadImage(tinyPE())
	if e != nil {
		t.Fatal(e)
	}
	xs, e := d.exportsAt(0x1800)
	if e != nil || len(xs) != 2 {
		t.Fatalf("aliases %v %v", xs, e)
	}
}
func TestForwardedExportNotAddressMatched(t *testing.T) {
	b := tinyPE()
	le.PutUint32(b[0x280:], 0x1060)
	d, e := loadImage(b)
	if e != nil {
		t.Fatal(e)
	}
	xs, e := d.exportsAt(0x1060)
	if e != nil || len(xs) != 0 {
		t.Fatal(xs, e)
	}
}
func TestMalformedExportOrdinalRejected(t *testing.T) {
	b := tinyPE()
	le.PutUint16(b[0x2a0:], 12)
	d, _ := loadImage(b)
	if _, e := d.exportsAt(0x1800); e == nil {
		t.Fatal("invalid ordinal accepted")
	}
}
func TestMalformedExportCountRejected(t *testing.T) {
	b := tinyPE()
	le.PutUint32(b[0x214:], 131073)
	d, _ := loadImage(b)
	if _, e := d.exportsAt(0x1800); e == nil {
		t.Fatal("invalid count accepted")
	}
}
func TestGoodMappedSample(t *testing.T) {
	f, fs, tm := setup(t)
	r := probe(f, fs, tm, 77, 123, "C:/Windows/System32")
	if r.Status != "api_slot_sample_complete" || r.Resolution.Status != "signed_disk_export_address_match" || len(r.Resolution.Exports) != 2 || f.reads != 1 || f.lastN != 8 || f.lastAddr != 0x180000000+slotRVA {
		t.Fatalf("%+v", r)
	}
}
func TestGoodImageSample(t *testing.T) {
	f, fs, tm := setup(t)
	f.r.Type = 0x1000000
	r := probe(f, fs, tm, 77, 123, "C:/Windows/System32")
	if r.Status != "api_slot_sample_complete" || f.reads != 1 {
		t.Fatal(r)
	}
}
func TestPreReadGates(t *testing.T) {
	for _, test := range []string{"noaccess", "guard", "private", "allocation", "notcommitted", "range", "query", "identity", "manifest", "hash", "module-size"} {
		t.Run(test, func(t *testing.T) {
			f, fs, tm := setup(t)
			switch test {
			case "noaccess":
				f.r.Protect = 1
			case "guard":
				f.r.Protect = 0x102
			case "private":
				f.r.Type = 0x20000
			case "allocation":
				f.r.AllocationBase++
			case "notcommitted":
				f.r.State = 0x2000
			case "range":
				f.r.Size = 1
			case "query":
				f.errorRegion = true
			case "identity":
				f.id.Start++
			case "manifest":
				tm.Source = ""
			case "hash":
				old := fs
				fs = func(p string) ([]byte, error) {
					b, e := old(p)
					if samePath(p, f.mods[1].Path) {
						v := append([]byte{}, b...)
						v[len(v)-1] ^= 1
						return v, e
					}
					return b, e
				}
			case "module-size":
				f.mods[1].ImageSize--
			}
			r := probe(f, fs, tm, 77, 123, "C:/Windows/System32")
			if f.reads != 0 || r.Status != "read_stopped" || r.Pointer != "" {
				t.Fatal(r, f.reads)
			}
		})
	}
}
func TestPostReadFailuresDiscardPointer(t *testing.T) {
	for _, test := range []string{"partial", "read-error", "identity", "module", "region", "disk"} {
		t.Run(test, func(t *testing.T) {
			f, fs, tm := setup(t)
			switch test {
			case "partial":
				f.partial = true
			case "read-error":
				f.readErr = true
			case "identity":
				f.changeID = true
			case "module":
				f.changeMods = true
			case "region":
				f.changeRegion = true
			case "disk":
				old := fs
				fs = func(p string) ([]byte, error) {
					b, e := old(p)
					if f.reads > 0 && samePath(p, f.mods[1].Path) {
						v := append([]byte{}, b...)
						v[len(v)-1] ^= 1
						return v, e
					}
					return b, e
				}
			}
			r := probe(f, fs, tm, 77, 123, "C:/Windows/System32")
			if f.reads != 1 || r.Pointer != "" || r.Status != "read_stopped" || r.Resolution.Status != "unresolved" {
				t.Fatal(r, f.reads)
			}
		})
	}
}
func TestUntrustedAndUnknownStayUnresolved(t *testing.T) {
	for _, test := range []string{"zero", "nonexport", "untrusted", "hash", "publisher", "path"} {
		t.Run(test, func(t *testing.T) {
			f, fs, tm := setup(t)
			switch test {
			case "zero":
				f.value = 0
			case "nonexport":
				f.value++
			case "untrusted":
				tm.Entries[0].Status = "NotTrusted"
			case "hash":
				tm.Entries[0].SHA256 = "bad"
			case "publisher":
				tm.Entries[0].Subject = "CN=Other"
			case "path":
				f.mods[2].Path = "C:/Other/KernelBase.dll"
			}
			r := probe(f, fs, tm, 77, 123, "C:/Windows/System32")
			if f.reads != 1 || r.Status != "api_slot_sample_complete" || r.Resolution.Status != "unresolved" {
				t.Fatal(r)
			}
		})
	}
}
func TestRangeOverflowSafety(t *testing.T) {
	if inRange(1, 8, ^uint64(0)-5, 100) {
		t.Fatal("wrapped range")
	}
	m := moduleInfo{Base: 100, ImageSize: 20}
	if gate(region{Base: 100, AllocationBase: 100, Size: 20, State: 0x1000, Protect: 2, Type: 0x40000}, m, 115) == nil {
		t.Fatal("out of range")
	}
}
func TestBundleAllowlist(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"analysis.json", "run.json", "trust.json", "secret.bin", "snapshot.dmp", "Wow.exe"} {
		os.WriteFile(filepath.Join(dir, n), []byte("owned fixture"), 0600)
	}
	out := filepath.Join(t.TempDir(), "report.zip")
	if e := bundle(dir, out); e != nil {
		t.Fatal(e)
	}
	z, e := zip.OpenReader(out)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	if len(z.File) != 3 {
		t.Fatal(len(z.File))
	}
	for _, f := range z.File {
		if strings.HasSuffix(f.Name, ".bin") || f.Name == "snapshot.dmp" {
			t.Fatal(f.Name)
		}
	}
}
func TestAttemptMarkerStopsReuseBeforeOpen(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".api-slot-attempt"), nil, 0600)
	if e := runRead(77, 123, dir); e == nil {
		t.Fatal("repeated attempt accepted")
	}
}
func TestEndianSlot(t *testing.T) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, 0x7ffb00001800)
	if le.Uint64(b) != 0x7ffb00001800 {
		t.Fatal("pointer endian")
	}
}
