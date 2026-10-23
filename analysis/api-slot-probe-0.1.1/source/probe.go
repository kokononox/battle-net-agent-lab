package main

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
)

const wowHash = "1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a"
const loaderHash = "c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c"
const slotRVA uint64 = 0x20a0750

var le = binary.LittleEndian

type identity struct {
	PID   uint32 `json:"pid"`
	Start uint64 `json:"creation_filetime"`
	Path  string `json:"image_path"`
}
type moduleInfo struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Base      uint64 `json:"base"`
	ImageSize uint32 `json:"image_size"`
}
type region struct {
	Base           uint64 `json:"base"`
	AllocationBase uint64 `json:"allocation_base"`
	Size           uint64 `json:"size"`
	State          uint32 `json:"state"`
	Protect        uint32 `json:"protect"`
	Type           uint32 `json:"type"`
}
type targetReader interface {
	Identity() (identity, error)
	Modules() ([]moduleInfo, error)
	Region(uint64) (region, error)
	Backing(uint64, uint64, string) (backingProof, error)
	Read(uint64, uint32) ([]byte, error)
	Close() error
}
type apiFailure struct {
	API     string `json:"api"`
	Code    uint32 `json:"win32_error_code"`
	Message string `json:"message"`
}

func (e *apiFailure) Error() string {
	return fmt.Sprintf("%s failed (Win32 %d): %s", e.API, e.Code, e.Message)
}
func norm(p string) string {
	return strings.ToLower(strings.TrimRight(strings.ReplaceAll(p, "\\", "/"), "/"))
}
func samePath(a, b string) bool { return norm(a) == norm(b) }
func parent(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return ""
	}
	return p[:i]
}
func inRange(a, n, base, size uint64) bool {
	return n > 0 && size > 0 && base <= a && a-base <= size && n <= size-(a-base)
}

// gate validates the fixed slot geometry, without yet accepting backing-file identity.
func gate(r region, m moduleInfo, a uint64, d *diskImage) (string, error) {
	if !inRange(a, 8, m.Base, uint64(m.ImageSize)) {
		return "", fmt.Errorf("slot outside module bounds")
	}
	if !inRange(a, 8, r.Base, r.Size) {
		return "", fmt.Errorf("slot outside queried region bounds")
	}
	if r.AllocationBase > r.Base || r.AllocationBase < m.Base {
		return "", fmt.Errorf("allocation base outside supported geometry")
	}
	if r.State != 0x1000 {
		return "", fmt.Errorf("slot is not committed; no read requested")
	}
	if r.Type != 0x1000000 && r.Type != 0x40000 {
		return "", fmt.Errorf("slot is not image/mapped memory; no read requested")
	}
	if r.Protect&0x100 != 0 {
		return "", fmt.Errorf("slot is PAGE_GUARD; no read requested")
	}
	switch r.Protect & 0xff {
	case 2, 4, 8, 0x20, 0x40, 0x80:
	default:
		return "", fmt.Errorf("slot is not readable (protection %#x); no read requested", r.Protect)
	}
	if r.AllocationBase == m.Base {
		return "whole_module_allocation", nil
	}
	if r.Type != 0x40000 || d == nil {
		return "", fmt.Errorf("split allocation requires MEM_MAPPED and pinned section metadata")
	}
	// The only extra geometry admitted is the pinned .rdata section containing this slot.
	matches := 0
	for _, sec := range d.PE.Sections {
		if sec.Name != ".rdata" || sec.VirtualAddress%0x10000 != 0 {
			continue
		}
		if uint64(sec.VirtualAddress) > ^uint64(0)-m.Base {
			continue
		}
		base := m.Base + uint64(sec.VirtualAddress)
		if r.AllocationBase == base && inRange(a, 8, base, uint64(sec.VirtualSize)) {
			matches++
		}
	}
	if matches != 1 {
		return "", fmt.Errorf("allocation base does not uniquely match the pinned .rdata section")
	}
	return "pinned_rdata_section_allocation", nil
}

type backingProof struct {
	Method         string `json:"method"`
	MappedPath     string `json:"slot_mapped_nt_path"`
	AllocationPath string `json:"allocation_mapped_nt_path"`
	DiskPath       string `json:"opened_disk_final_nt_path"`
	DiskSHA256     string `json:"opened_disk_sha256"`
}

func verifyBacking(p backingProof) error {
	if p.Method != "K32GetMappedFileNameW + GetFinalPathNameByHandleW(VOLUME_NAME_NT) + same-handle SHA256" {
		return fmt.Errorf("unsupported backing proof method")
	}
	for _, path := range []string{p.MappedPath, p.AllocationPath, p.DiskPath} {
		if !strings.HasPrefix(norm(path), "/device/") || len(path) > 32768 {
			return fmt.Errorf("missing/unsupported backing NT path")
		}
	}
	if !samePath(p.MappedPath, p.DiskPath) || !samePath(p.AllocationPath, p.DiskPath) {
		return fmt.Errorf("mapped-file path differs from opened pinned DLL")
	}
	if p.DiskSHA256 != loaderHash {
		return fmt.Errorf("opened mapped-file identity hash differs from pinned DLL")
	}
	return nil
}

type trustEntry struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Status  string `json:"status"`
	Subject string `json:"subject"`
}
type trustManifest struct {
	Source  string       `json:"source"`
	Entries []trustEntry `json:"entries"`
}
type exportName struct {
	Name    string `json:"name"`
	Ordinal uint32 `json:"ordinal"`
	RVA     uint32 `json:"rva"`
}
type diskImage struct {
	Hash  string
	Size  uint32
	Bytes []byte
	PE    *pe.File
}

func loadImage(b []byte) (*diskImage, error) {
	if len(b) < 64 || len(b) > 160*1024*1024 {
		return nil, fmt.Errorf("disk image size rejected")
	}
	f, e := pe.NewFile(bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || f.Machine != pe.IMAGE_FILE_MACHINE_AMD64 || oh.SizeOfImage == 0 {
		return nil, fmt.Errorf("disk image is not AMD64 PE32+")
	}
	sum := sha256.Sum256(b)
	return &diskImage{hex.EncodeToString(sum[:]), oh.SizeOfImage, b, f}, nil
}
func (d *diskImage) rva(r uint32, n uint64) ([]byte, error) {
	for _, s := range d.PE.Sections {
		if uint64(r) >= uint64(s.VirtualAddress) {
			off := uint64(r) - uint64(s.VirtualAddress)
			if off <= uint64(s.Size) && n <= uint64(s.Size)-off {
				pos := uint64(s.Offset) + off
				if pos <= uint64(len(d.Bytes)) && n <= uint64(len(d.Bytes))-pos {
					return d.Bytes[pos : pos+n], nil
				}
			}
		}
	}
	return nil, fmt.Errorf("export data not file-backed or out of bounds")
}
func (d *diskImage) cstr(r uint32) (string, error) {
	for _, s := range d.PE.Sections {
		if uint64(r) >= uint64(s.VirtualAddress) {
			o := uint64(r) - uint64(s.VirtualAddress)
			if o < uint64(s.Size) {
				n := uint64(s.Size) - o
				if n > 4096 {
					n = 4096
				}
				b, e := d.rva(r, n)
				if e != nil {
					return "", e
				}
				i := bytes.IndexByte(b, 0)
				if i < 0 {
					return "", fmt.Errorf("unterminated export name")
				}
				return string(b[:i]), nil
			}
		}
	}
	return "", fmt.Errorf("export string unmapped")
}
func (d *diskImage) exportsAt(rva uint32) ([]exportName, error) {
	oh := d.PE.OptionalHeader.(*pe.OptionalHeader64)
	dir := oh.DataDirectory[0]
	if dir.VirtualAddress == 0 || dir.Size < 40 {
		return nil, nil
	}
	b, e := d.rva(dir.VirtualAddress, 40)
	if e != nil {
		return nil, e
	}
	base, nf, nn, fa, na, oa := le.Uint32(b[16:]), le.Uint32(b[20:]), le.Uint32(b[24:]), le.Uint32(b[28:]), le.Uint32(b[32:]), le.Uint32(b[36:])
	if nf > 131072 || nn > 131072 {
		return nil, fmt.Errorf("export count rejected")
	}
	fs, e := d.rva(fa, uint64(nf)*4)
	if e != nil {
		return nil, e
	}
	ns, e := d.rva(na, uint64(nn)*4)
	if e != nil {
		return nil, e
	}
	os_, e := d.rva(oa, uint64(nn)*2)
	if e != nil {
		return nil, e
	}
	var out []exportName
	for i := uint32(0); i < nn; i++ {
		idx := uint32(le.Uint16(os_[i*2:]))
		if idx >= nf {
			return nil, fmt.Errorf("invalid export ordinal")
		}
		v := le.Uint32(fs[idx*4:])
		if v != rva {
			continue
		}
		if uint64(v) >= uint64(dir.VirtualAddress) && uint64(v) < uint64(dir.VirtualAddress)+uint64(dir.Size) {
			continue
		}
		name, e := d.cstr(le.Uint32(ns[i*4:]))
		if e != nil {
			return nil, e
		}
		out = append(out, exportName{name, base + idx, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

type resolution struct {
	Status     string       `json:"status"`
	Owner      *moduleInfo  `json:"owner,omitempty"`
	DiskSHA256 string       `json:"disk_sha256,omitempty"`
	Exports    []exportName `json:"matching_exports,omitempty"`
	Signature  *trustEntry  `json:"signature_assertion,omitempty"`
	Detail     string       `json:"detail"`
}
type report struct {
	Tool          string        `json:"tool"`
	Status        string        `json:"status"`
	Error         string        `json:"error,omitempty"`
	Identity      *identity     `json:"identity,omitempty"`
	Main          *moduleInfo   `json:"main_module,omitempty"`
	Loader        *moduleInfo   `json:"loader_module,omitempty"`
	MappingMode   string        `json:"mapping_mode,omitempty"`
	BackingBefore *backingProof `json:"backing_before,omitempty"`
	BackingAfter  *backingProof `json:"backing_after,omitempty"`
	Before        *region       `json:"region_before,omitempty"`
	After         *region       `json:"region_after,omitempty"`
	ReadCalls     int           `json:"read_calls"`
	Requested     int           `json:"memory_bytes_requested"`
	Returned      int           `json:"memory_bytes_returned"`
	Pointer       string        `json:"sampled_pointer_hex,omitempty"`
	Resolution    resolution    `json:"resolution"`
	Notes         []string      `json:"notes"`
}
type fileReader func(string) ([]byte, error)

func moduleByPath(ms []moduleInfo, path string) (moduleInfo, error) {
	var found []moduleInfo
	for _, m := range ms {
		if samePath(m.Path, path) {
			found = append(found, m)
		}
	}
	if len(found) != 1 {
		return moduleInfo{}, fmt.Errorf("expected exactly one matching module: %s", path)
	}
	return found[0], nil
}
func checkDisk(fs fileReader, m moduleInfo, pin string) (*diskImage, error) {
	b, e := fs(m.Path)
	if e != nil {
		return nil, e
	}
	d, e := loadImage(b)
	if e != nil {
		return nil, e
	}
	if d.Hash != pin || d.Size != m.ImageSize {
		return nil, fmt.Errorf("pinned disk hash or module size mismatch: %s", m.Name)
	}
	return d, nil
}
func trustedOwner(fs fileReader, tm trustManifest, m moduleInfo, ptr uint64, sysdir string) resolution {
	r := resolution{Status: "unresolved", Owner: &m, Detail: "No supported exact signed-disk-export match."}
	name := strings.ToLower(m.Name)
	if name != "kernel32.dll" && name != "kernelbase.dll" && name != "ntdll.dll" {
		r.Detail = "Pointer owner is outside the fixed three Windows DLLs; no trampoline chasing."
		return r
	}
	if !samePath(m.Path, strings.TrimRight(sysdir, "/\\")+"/"+name) {
		r.Detail = "Pointer owner path does not equal the fixed system DLL path."
		return r
	}
	b, e := fs(m.Path)
	if e != nil {
		r.Detail = e.Error()
		return r
	}
	d, e := loadImage(b)
	if e != nil {
		r.Detail = e.Error()
		return r
	}
	r.DiskSHA256 = d.Hash
	if d.Size != m.ImageSize {
		r.Detail = "Owner disk image size differs from module metadata."
		return r
	}
	var matches []trustEntry
	for _, t := range tm.Entries {
		if samePath(t.Path, m.Path) {
			matches = append(matches, t)
		}
	}
	if tm.Source != "PowerShell Get-AuthenticodeSignature + Get-FileHash" || len(matches) != 1 {
		r.Detail = "Missing/ambiguous launcher signature assertion."
		return r
	}
	tr := matches[0]
	r.Signature = &tr
	if tr.SHA256 != d.Hash || tr.Status != "Valid" || !strings.Contains(strings.ToLower(tr.Subject), "o=microsoft corporation") {
		r.Detail = "Signature assertion is not Valid/Microsoft/hash-matched."
		return r
	}
	xs, e := d.exportsAt(uint32(ptr - m.Base))
	if e != nil {
		r.Detail = e.Error()
		return r
	}
	if len(xs) == 0 {
		r.Detail = "Pointer does not exactly match a named non-forwarder disk export; no offset/trampoline guessing."
		return r
	}
	r.Status = "signed_disk_export_address_match"
	r.Exports = xs
	r.Detail = "Sampled address equals disk-derived export address(es). Signature was checked by the launcher. This is not a proof of unmodified loaded code or execution."
	return r
}
func probe(t targetReader, fs fileReader, tm trustManifest, pid uint32, start uint64, sysdir string) (out report) {
	out.Tool = "WLab APIProbe 0.1.1"
	out.Status = "read_stopped"
	out.Resolution = resolution{Status: "unresolved", Detail: "No validated sample."}
	out.Notes = []string{"One explicit ReadProcessMemory request of exactly 8 bytes at most; no header/code-page reads.", "Metadata and local disk reads are separate from the process-memory byte cap.", "Backing file paths at slot and allocation base are compared with the final NT path and SHA256 of one opened pinned DLL handle, before and after the sample. This is not proof of file-object identity or mapped section offset; layout correspondence remains an assumption.", "Non-atomic sample; equality to signed disk export assumes the loaded image layout corresponds to that file. No code bytes or EAT memory are read.", "No CPU/BIOS collection, serialization or network-send conclusion."}
	fail := func(e error) report {
		out.Error = e.Error()
		out.Pointer = ""
		out.Resolution = resolution{Status: "unresolved", Detail: "Sample not validated: " + e.Error()}
		return out
	}
	id, e := t.Identity()
	if e != nil {
		return fail(e)
	}
	out.Identity = &id
	if id.PID != pid || id.Start != start || start == 0 {
		return fail(fmt.Errorf("process creation identity mismatch"))
	}
	ms, e := t.Modules()
	if e != nil {
		return fail(e)
	}
	main, e := moduleByPath(ms, id.Path)
	if e != nil {
		return fail(e)
	}
	out.Main = &main
	lm, e := moduleByPath(ms, parent(id.Path)+"/wow_loader.dll")
	if e != nil {
		return fail(e)
	}
	out.Loader = &lm
	if _, e = checkDisk(fs, main, wowHash); e != nil {
		return fail(e)
	}
	ld, e := checkDisk(fs, lm, loaderHash)
	if e != nil {
		return fail(e)
	}
	if slotRVA+8 > uint64(ld.Size) || lm.Base > ^uint64(0)-slotRVA {
		return fail(fmt.Errorf("slot image bounds rejected"))
	}
	if _, e = ld.rva(uint32(slotRVA), 8); e != nil {
		return fail(e)
	}
	if tm.Source != "PowerShell Get-AuthenticodeSignature + Get-FileHash" || len(tm.Entries) == 0 {
		return fail(fmt.Errorf("launcher signature manifest missing; no read requested"))
	}
	addr := lm.Base + slotRVA
	r, e := t.Region(addr)
	out.Before = &r
	if e != nil {
		return fail(e)
	}
	mode, e := gate(r, lm, addr, ld)
	if e != nil {
		return fail(e)
	}
	out.MappingMode = mode
	proof, e := t.Backing(addr, r.AllocationBase, lm.Path)
	out.BackingBefore = &proof
	if e != nil {
		return fail(e)
	}
	if e = verifyBacking(proof); e != nil {
		return fail(e)
	}
	out.ReadCalls = 1
	out.Requested = 8
	b, e := t.Read(addr, 8)
	out.Returned = len(b)
	if e != nil {
		return fail(e)
	}
	if len(b) != 8 {
		return fail(fmt.Errorf("partial/invalid slot read: %d bytes", len(b)))
	}
	ptr := le.Uint64(b)
	// All postconditions must pass before exposing the pointer as a validated sample.
	id2, e := t.Identity()
	if e != nil {
		return fail(e)
	}
	if id2 != id {
		return fail(fmt.Errorf("process identity changed"))
	}
	ms2, e := t.Modules()
	if e != nil {
		return fail(e)
	}
	for _, old := range []moduleInfo{main, lm} {
		now, e := moduleByPath(ms2, old.Path)
		if e != nil || now != old {
			return fail(fmt.Errorf("selected module metadata changed"))
		}
	}
	r2, e := t.Region(addr)
	out.After = &r2
	if e != nil {
		return fail(e)
	}
	if r2 != r {
		return fail(fmt.Errorf("slot mapping/protection changed"))
	}
	mode2, e := gate(r2, lm, addr, ld)
	if e != nil || mode2 != mode {
		return fail(fmt.Errorf("post-read mapping geometry failed or changed: %v", e))
	}
	proof2, e := t.Backing(addr, r2.AllocationBase, lm.Path)
	out.BackingAfter = &proof2
	if e != nil {
		return fail(e)
	}
	if e = verifyBacking(proof2); e != nil {
		return fail(e)
	}
	if proof2 != proof {
		return fail(fmt.Errorf("mapped-file identity metadata changed after sample"))
	}
	if _, e = checkDisk(fs, main, wowHash); e != nil {
		return fail(e)
	}
	if _, e = checkDisk(fs, lm, loaderHash); e != nil {
		return fail(e)
	}
	out.Pointer = fmt.Sprintf("0x%016x", ptr)
	out.Status = "api_slot_sample_complete"
	out.Resolution = resolution{Status: "unresolved", Detail: "Pointer not in a uniquely supported module; no chasing or retry."}
	var owners []moduleInfo
	for _, mod := range ms {
		if inRange(ptr, 1, mod.Base, uint64(mod.ImageSize)) {
			owners = append(owners, mod)
		}
	}
	if len(owners) == 1 {
		old := owners[0]
		now, e := moduleByPath(ms2, old.Path)
		if e != nil || now != old {
			return fail(fmt.Errorf("pointer owner metadata changed"))
		}
		out.Resolution = trustedOwner(fs, tm, old, ptr, sysdir)
	}
	return out
}
func readDiskFile(path string) ([]byte, error) {
	s, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if !s.Mode().IsRegular() || s.Size() < 64 || s.Size() > 160*1024*1024 {
		return nil, fmt.Errorf("disk file size/type rejected")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	after, e := os.Stat(path)
	if e != nil || after.Size() != s.Size() || !after.ModTime().Equal(s.ModTime()) {
		return nil, fmt.Errorf("disk file changed during read")
	}
	return b, nil
}
