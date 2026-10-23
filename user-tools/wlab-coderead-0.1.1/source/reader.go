package main

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const wowHash = "1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a"

var le = binary.LittleEndian
var pagePlan = []uint32{0x1b11000, 0x1b14000, 0x3306000}

type candidate struct {
	Name      string
	RVA, Size uint32
}

var candidatePlan = []candidate{{"merge_candidate", 0x1b14120, 24}, {"creator_candidate", 0x1b11190, 110}, {"parse_fallback_candidate", 0x33068c0, 244}}

type identity struct {
	PID        uint32 `json:"pid"`
	Start      uint64 `json:"creation_filetime"`
	Path       string `json:"image_path"`
	Base       uint64 `json:"module_base"`
	ImageSize  uint32 `json:"module_image_size"`
	ModulePath string `json:"module_path"`
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
	Region(uint64) (region, error)
	Read(uint64, uint32) ([]byte, error)
	Close() error
}
type apiFailure struct {
	API     string `json:"api"`
	Code    uint32 `json:"win32_error_code"`
	Message string `json:"message"`
}

func (e *apiFailure) Error() string {
	return fmt.Sprintf("%s failed (Win32 %d): %s; no debug privilege enablement, protection change or retry", e.API, e.Code, e.Message)
}

func regionTypeName(n uint32) string {
	switch n {
	case 0x1000000:
		return "MEM_IMAGE"
	case 0x40000:
		return "MEM_MAPPED"
	case 0x20000:
		return "MEM_PRIVATE"
	default:
		return "other_or_unavailable"
	}
}

type diskSpec struct {
	Stamp, Size uint32
	Pages       map[uint32][]byte
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}
func baseName(p string) string {
	s := strings.ReplaceAll(p, "\\", "/")
	return s[strings.LastIndex(s, "/")+1:]
}
func samePath(a, b string) bool {
	return strings.EqualFold(strings.ReplaceAll(a, "/", "\\"), strings.ReplaceAll(b, "/", "\\"))
}
func loadDisk(path string) (diskSpec, error) {
	s := diskSpec{Pages: map[uint32][]byte{}}
	f, e := os.Open(path)
	if e != nil {
		return s, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 256*1024*1024+1))
	if e != nil {
		return s, e
	}
	if len(b) > 256*1024*1024 {
		return s, fmt.Errorf("disk image exceeds read limit")
	}
	if digest(b) != wowHash {
		return s, fmt.Errorf("disk Wow.exe SHA256 differs from pinned build 12.1.5.70448")
	}
	p, e := pe.NewFile(bytes.NewReader(b))
	if e != nil {
		return s, e
	}
	defer p.Close()
	opt, ok := p.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || p.Machine != 0x8664 {
		return s, fmt.Errorf("disk PE is not AMD64")
	}
	s.Stamp = p.TimeDateStamp
	s.Size = opt.SizeOfImage
	for _, rva := range pagePlan {
		for _, sec := range p.Sections {
			if rva >= sec.VirtualAddress {
				d := uint64(rva - sec.VirtualAddress)
				off := uint64(sec.Offset) + d
				if d+4096 <= uint64(sec.Size) && off+4096 <= uint64(len(b)) {
					s.Pages[rva] = append([]byte{}, b[off:off+4096]...)
					break
				}
			}
		}
		if len(s.Pages[rva]) != 4096 {
			return s, fmt.Errorf("planned page 0x%x not file-backed", rva)
		}
	}
	return s, nil
}
func validRegion(r region, base, addr uint64, n uint32) error {
	if r.Base > addr || r.Size == 0 || r.Base > ^uint64(0)-r.Size || addr > ^uint64(0)-uint64(n) || addr+uint64(n) > r.Base+r.Size {
		return fmt.Errorf("planned read crosses returned region bounds")
	}
	if r.AllocationBase != base || r.State != 0x1000 || (r.Type != 0x1000000 && r.Type != 0x40000) {
		return fmt.Errorf("not a committed MEM_IMAGE or MEM_MAPPED region at the expected module allocation")
	}
	if r.Protect&0x100 != 0 || r.Protect&0xff == 0x01 {
		return fmt.Errorf("guard or no-access page; no protection change or retry")
	}
	switch r.Protect & 0xff {
	case 0x02, 0x04, 0x08, 0x20, 0x40, 0x80:
		return nil
	}
	return fmt.Errorf("page protection 0x%x is not accepted readable memory", r.Protect)
}
func readChecked(t targetReader, base, addr uint64, n uint32, row map[string]any) ([]byte, error) {
	r, e := t.Region(addr)
	if e != nil {
		row["query_error"] = e.Error()
		return nil, e
	}
	row["region"] = r
	if e = validRegion(r, base, addr, n); e != nil {
		row["protection_or_bounds_error"] = e.Error()
		return nil, e
	}
	b, e := t.Read(addr, n)
	row["bytes_returned"] = len(b)
	if e != nil {
		row["read_error"] = e.Error()
		return nil, e
	}
	if len(b) != int(n) {
		e = fmt.Errorf("partial read: %d of %d bytes; partial data not exported", len(b), n)
		row["read_error"] = e.Error()
		return nil, e
	}
	return b, nil
}
func checkHeader(b []byte, d diskSpec) error {
	if len(b) != 4096 || string(b[:2]) != "MZ" {
		return fmt.Errorf("memory PE header missing or short")
	}
	nt := uint64(le.Uint32(b[0x3c:]))
	if nt > 4096-264 || string(b[nt:nt+4]) != "PE\x00\x00" || le.Uint16(b[nt+4:]) != 0x8664 || le.Uint32(b[nt+8:]) != d.Stamp || le.Uint16(b[nt+24:]) != 0x20b || le.Uint32(b[nt+24+56:]) != d.Size {
		return fmt.Errorf("loaded PE header does not match pinned disk timestamp/size/AMD64")
	}
	return nil
}
func sameIdentity(a, b identity) bool {
	return a.PID == b.PID && a.Start == b.Start && samePath(a.Path, b.Path) && a.Base == b.Base && a.ImageSize == b.ImageSize && samePath(a.ModulePath, b.ModulePath)
}
func collect(t targetReader, pid uint32, start uint64, initial identity, d diskSpec, report map[string]any) (map[string][]byte, error) {
	files := map[string][]byte{}
	rows := []map[string]any{}
	report["page_reads"] = &rows
	before, e := t.Identity()
	if e != nil {
		return nil, e
	}
	report["identity_before"] = before
	if !sameIdentity(initial, before) || before.PID != pid || before.Start != start || before.Base == 0 || before.ImageSize != d.Size || !strings.EqualFold(baseName(before.Path), "Wow.exe") || !samePath(before.Path, before.ModulePath) {
		return nil, fmt.Errorf("process/module identity changed or does not match selected pinned image")
	}
	// Metadata-only census of the header and three fixed ranges. No process memory
	// is read here. Query errors are recorded and stop all reads (not retried).
	census := []map[string]any{}
	var censusError error
	for _, rva := range append([]uint32{0}, pagePlan...) {
		row := map[string]any{"rva": fmt.Sprintf("0x%x", rva), "requested_bytes": 4096, "query_only": true}
		if before.Base > ^uint64(0)-uint64(rva) || uint64(rva)+4096 > uint64(d.Size) {
			row["query_error"] = "planned range outside module or overflow"
			if censusError == nil {
				censusError = fmt.Errorf("invalid census range")
			}
		} else {
			row["address"] = before.Base + uint64(rva)
			region, e := t.Region(before.Base + uint64(rva))
			if e != nil {
				row["query_error"] = e.Error()
				if censusError == nil {
					censusError = e
				}
			} else {
				row["region"] = region
				row["region_type_name"] = regionTypeName(region.Type)
				if e = validRegion(region, before.Base, before.Base+uint64(rva), 4096); e != nil {
					row["policy_gate_note"] = e.Error()
				}
			}
		}
		census = append(census, row)
	}
	report["planned_region_census"] = census
	if censusError != nil {
		return nil, fmt.Errorf("fixed-range metadata query failed; no read started: %w", censusError)
	}
	headRow := map[string]any{"purpose": "loaded PE identity before; not exported"}
	report["header_before"] = headRow
	h, e := readChecked(t, before.Base, before.Base, 4096, headRow)
	if e != nil {
		return nil, e
	}
	if e = checkHeader(h, d); e != nil {
		return nil, e
	}
	for _, rva := range pagePlan {
		row := map[string]any{"rva": fmt.Sprintf("0x%x", rva), "requested_bytes": 4096, "status": "not_read"}
		rows = append(rows, row)
		if uint64(rva)+4096 > uint64(d.Size) || before.Base > ^uint64(0)-uint64(rva) {
			return nil, fmt.Errorf("page outside module/VA overflow")
		}
		b, e := readChecked(t, before.Base, before.Base+uint64(rva), 4096, row)
		if e != nil {
			row["status"] = "stopped"
			return nil, fmt.Errorf("page 0x%x: %w", rva, e)
		}
		if len(d.Pages[rva]) != 4096 {
			return nil, fmt.Errorf("missing validated baseline")
		}
		row["status"] = "read_staged"
		row["memory_sha256"] = digest(b)
		row["disk_sha256"] = digest(d.Pages[rva])
		row["raw_bytes_equal_disk"] = bytes.Equal(b, d.Pages[rva])
		files[fmt.Sprintf("page-%08x.bin", rva)] = b
	}
	after, e := t.Identity()
	if e != nil {
		return nil, e
	}
	report["identity_after"] = after
	if !sameIdentity(before, after) {
		return nil, fmt.Errorf("identity changed after read; staged bytes discarded")
	}
	headAfterRow := map[string]any{"purpose": "loaded PE identity after; not exported"}
	report["header_after"] = headAfterRow
	h2, e := readChecked(t, after.Base, after.Base, 4096, headAfterRow)
	if e != nil {
		return nil, e
	}
	if e = checkHeader(h2, d); e != nil {
		return nil, e
	}
	if !bytes.Equal(h, h2) {
		return nil, fmt.Errorf("PE identity page changed; staged bytes discarded")
	}
	targets := []map[string]any{}
	for _, c := range candidatePlan {
		page := c.RVA &^ uint32(4095)
		offset := c.RVA - page
		b := files[fmt.Sprintf("page-%08x.bin", page)]
		baseline := d.Pages[page]
		if uint64(offset)+uint64(c.Size) > uint64(len(b)) {
			return nil, fmt.Errorf("candidate exceeds planned page")
		}
		slice := append([]byte{}, b[offset:offset+c.Size]...)
		files[c.Name+".bin"] = slice
		targets = append(targets, map[string]any{"role_candidate": c.Name, "rva": fmt.Sprintf("0x%x", c.RVA), "size": c.Size, "memory_sha256": digest(slice), "raw_bytes_equal_disk": bytes.Equal(slice, baseline[offset:offset+c.Size]), "first_24_bytes": hex.EncodeToString(slice[:24])})
	}
	for _, row := range rows {
		row["status"] = "read_and_identity_checks_passed"
	}
	report["targets"] = targets
	report["identity_scope"] = "pinned disk SHA256 plus loaded module path/base/size and PE timestamp/size/header before and after; not a full memory image hash"
	report["bytes_exported"] = 4096*3 + 24 + 110 + 244
	return files, nil
}
func runRead(pid uint32, start uint64, out string) (err error) {
	if e := os.MkdirAll(out, 0700); e != nil {
		return e
	}
	marker, e := os.OpenFile(filepath.Join(out, ".read-attempt"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return fmt.Errorf("report directory already used or unavailable; no read started: %w", e)
	}
	marker.Close()
	report := map[string]any{"tool": "WLab CodeRead 0.1.1", "status": "read_failed", "started_utc": time.Now().UTC().Format(time.RFC3339Nano), "expected_pid": pid, "expected_creation_filetime": start, "pinned_wow_sha256": wowHash, "maximum_target_memory_requested_bytes": 20480, "sending_on_3724": "unresolved", "method": "query metadata + ReadProcessMemory only; no clone/debugger/injection/target writes/protection changes", "consistency_limit": "live sequential reads, not an atomic snapshot; same identities and PE headers do not prove code never changed between reads", "comparison_limit": "raw byte differences are not proof of decryption, execution, serialization or sending; relocations not normalized"}
	defer func() {
		if err != nil {
			report["error"] = err.Error()
			var api *apiFailure
			if errors.As(err, &api) {
				report["native_failure"] = api
			}
		}
		report["finished_utc"] = time.Now().UTC().Format(time.RFC3339Nano)
		if e := writeJSON(filepath.Join(out, "analysis.json"), report); err == nil {
			err = e
		}
	}()
	t, e := openTarget(pid)
	if e != nil {
		return e
	}
	defer t.Close()
	id, e := t.Identity()
	if e != nil {
		return e
	}
	report["identity_initial"] = id
	if id.PID != pid || id.Start != start || !strings.EqualFold(baseName(id.Path), "Wow.exe") || !samePath(id.Path, id.ModulePath) {
		return fmt.Errorf("selected process identity no longer matches")
	}
	d, e := loadDisk(id.Path)
	if e != nil {
		return e
	}
	report["disk_sha256"] = wowHash
	files, e := collect(t, pid, start, id, d, report)
	if e != nil {
		return e
	}
	// No partial or staged bytes are exported if any identity/access/read gate failed.
	for name, b := range files {
		if e = os.WriteFile(filepath.Join(out, name), b, 0600); e != nil {
			return e
		}
	}
	report["region_policy"] = "committed readable MEM_IMAGE or MEM_MAPPED; allocation base must match verified module; MEM_PRIVATE, guard, no-access and invalid bounds rejected"
	report["status"] = "bounded_read_complete"
	return nil
}
