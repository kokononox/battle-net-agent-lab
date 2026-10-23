package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const wowHash = "1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a"
const procHash = "22c2a2b09ade73a342a18dab838354385f73fc98e324b9903fd61fff949c5124"

var le = binary.LittleEndian

func hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

type span struct{ VA, Size, Off uint64 }
type module struct {
	Name        string
	Base        uint64
	Size, Stamp uint32
}
type dump struct {
	f       io.ReaderAt
	size    uint64
	spans   []span
	modules []module
}

func readAt(f io.ReaderAt, total, off, n uint64) ([]byte, error) {
	if n > 16*1024*1024 || off > total || n > total-off {
		return nil, fmt.Errorf("out-of-bounds read: offset=%x length=%x", off, n)
	}
	b := make([]byte, int(n))
	_, e := f.ReadAt(b, int64(off))
	if e != nil {
		return nil, e
	}
	return b, nil
}
func parseDump(f io.ReaderAt, total uint64) (*dump, error) {
	rd := func(o, n uint64) ([]byte, error) { return readAt(f, total, o, n) }
	h, e := rd(0, 32)
	if e != nil {
		return nil, e
	}
	if string(h[:4]) != "MDMP" || le.Uint32(h[4:])&0xffff != 0xa793 {
		return nil, fmt.Errorf("unsupported minidump header")
	}
	count, dir := le.Uint32(h[8:]), uint64(le.Uint32(h[12:]))
	if count == 0 || count > 4096 {
		return nil, fmt.Errorf("invalid directory count")
	}
	entries, e := rd(dir, uint64(count)*12)
	if e != nil {
		return nil, e
	}
	d := &dump{f: f, size: total}
	seen := map[uint32]bool{}
	archOK := false
	for i := uint32(0); i < count; i++ {
		row := entries[i*12 : i*12+12]
		typ := le.Uint32(row)
		if typ != 4 && typ != 5 && typ != 7 && typ != 9 {
			continue
		}
		if seen[typ] {
			return nil, fmt.Errorf("duplicate supported stream %d", typ)
		}
		seen[typ] = true
		n, off := uint64(le.Uint32(row[4:])), uint64(le.Uint32(row[8:]))
		b, e := rd(off, n)
		if e != nil {
			return nil, e
		}
		switch typ {
		case 7:
			if len(b) < 2 || le.Uint16(b) != 9 {
				return nil, fmt.Errorf("dump is not AMD64")
			}
			archOK = true
		case 4:
			if len(b) < 4 {
				return nil, fmt.Errorf("short module stream")
			}
			num := uint64(le.Uint32(b))
			if num > 65536 || 4+num*108 != n {
				return nil, fmt.Errorf("bad module stream size")
			}
			for j := uint64(0); j < num; j++ {
				v := b[4+j*108 : 4+(j+1)*108]
				nr := uint64(le.Uint32(v[20:]))
				ns, e := rd(nr, 4)
				if e != nil {
					return nil, e
				}
				nb := uint64(le.Uint32(ns))
				if nb > 32768 || nb%2 != 0 {
					return nil, fmt.Errorf("bad module name length")
				}
				raw, e := rd(nr+4, nb)
				if e != nil {
					return nil, e
				}
				name := decodeUTF16(raw)
				base := le.Uint64(v)
				size := le.Uint32(v[8:])
				if uint64(size) > ^uint64(0)-base {
					return nil, fmt.Errorf("module overflow")
				}
				d.modules = append(d.modules, module{name, base, size, le.Uint32(v[16:])})
			}
		case 5:
			if len(b) < 4 {
				return nil, fmt.Errorf("short memory stream")
			}
			num := uint64(le.Uint32(b))
			if num > 1000000 || 4+num*16 != n {
				return nil, fmt.Errorf("bad memory stream size")
			}
			for j := uint64(0); j < num; j++ {
				v := b[4+j*16:]
				s := span{le.Uint64(v), uint64(le.Uint32(v[8:])), uint64(le.Uint32(v[12:]))}
				if e := d.add(s); e != nil {
					return nil, e
				}
			}
		case 9:
			if len(b) < 16 {
				return nil, fmt.Errorf("short memory64 stream")
			}
			num, at := le.Uint64(b), le.Uint64(b[8:])
			if num > 1000000 || 16+num*16 != n {
				return nil, fmt.Errorf("bad memory64 stream size")
			}
			for j := uint64(0); j < num; j++ {
				v := b[16+j*16:]
				s := span{le.Uint64(v), le.Uint64(v[8:]), at}
				if e := d.add(s); e != nil {
					return nil, e
				}
				at += s.Size
			}
		}
	}
	if !archOK || len(d.modules) == 0 || len(d.spans) == 0 {
		return nil, fmt.Errorf("required streams missing")
	}
	// Full and mini streams can coexist. Only exact duplicate mappings are accepted.
	sort.Slice(d.spans, func(i, j int) bool { return d.spans[i].VA < d.spans[j].VA })
	unique := []span{}
	for _, s := range d.spans {
		if len(unique) > 0 {
			p := unique[len(unique)-1]
			if s == p {
				continue
			}
			if s.VA < p.VA+p.Size {
				return nil, fmt.Errorf("overlapping memory mappings")
			}
		}
		unique = append(unique, s)
	}
	d.spans = unique
	return d, nil
}
func (d *dump) add(s span) error {
	if s.Size == 0 {
		return nil
	}
	if s.VA > ^uint64(0)-s.Size || s.Off > d.size || s.Size > d.size-s.Off {
		return fmt.Errorf("invalid memory mapping")
	}
	d.spans = append(d.spans, s)
	return nil
}
func (d *dump) memory(va, n uint64) ([]byte, error) {
	if n > 1024*1024 || va > ^uint64(0)-n {
		return nil, fmt.Errorf("invalid requested range")
	}
	out := []byte{}
	for uint64(len(out)) < n {
		at := va + uint64(len(out))
		i := sort.Search(len(d.spans), func(i int) bool { return d.spans[i].VA+d.spans[i].Size > at })
		if i == len(d.spans) || d.spans[i].VA > at {
			return nil, fmt.Errorf("missing memory at %x", at)
		}
		s := d.spans[i]
		take := n - uint64(len(out))
		if take > s.VA+s.Size-at {
			take = s.VA + s.Size - at
		}
		b, e := readAt(d.f, d.size, s.Off+at-s.VA, take)
		if e != nil {
			return nil, e
		}
		out = append(out, b...)
	}
	return out, nil
}
func baseName(s string) string {
	s = strings.ReplaceAll(s, "\\", "/")
	return s[strings.LastIndex(s, "/")+1:]
}
func decodeUTF16(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = le.Uint16(b[i*2:])
	}
	return string(utf16Decode(u))
}
func (d *dump) wow() (module, error) {
	found := []module{}
	for _, m := range d.modules {
		if strings.EqualFold(baseName(m.Name), "Wow.exe") {
			found = append(found, m)
		}
	}
	if len(found) != 1 {
		return module{}, fmt.Errorf("expected one Wow.exe module, got %d", len(found))
	}
	return found[0], nil
}
func diskRange(p *pe.File, file []byte, rva, n uint32) ([]byte, error) {
	for _, s := range p.Sections {
		if rva >= s.VirtualAddress {
			delta := uint64(rva - s.VirtualAddress)
			if delta+uint64(n) <= uint64(s.Size) {
				off := uint64(s.Offset) + delta
				return readAt(bytes.NewReader(file), uint64(len(file)), off, uint64(n))
			}
		}
	}
	return nil, fmt.Errorf("disk range not file-backed")
}
func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}

// Extraction is deliberately bounded. It neither scans heap/account data nor decrypts network traffic.
func extract(dumpPath, diskPath, out string) (err error) {
	if e := os.MkdirAll(out, 0700); e != nil {
		return e
	}
	report := map[string]any{"tool": "WLab Snapshot 0.1.0", "status": "extraction_failed", "sending_on_3724": "unresolved", "note": "raw byte differences are not proof of decryption, execution, serialization or sending; ASLR/relocations may differ"}
	defer func() {
		if err != nil {
			report["error"] = err.Error()
		}
		if e := writeJSON(filepath.Join(out, "analysis.json"), report); err == nil {
			err = e
		}
	}()
	disk, e := os.ReadFile(diskPath)
	if e != nil {
		return e
	}
	if hash(disk) != wowHash {
		return fmt.Errorf("wrong Wow.exe SHA256")
	}
	p, e := pe.Open(diskPath)
	if e != nil {
		return e
	}
	defer p.Close()
	opt, ok := p.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || p.Machine != 0x8664 {
		return fmt.Errorf("disk PE is not AMD64")
	}
	f, e := os.Open(dumpPath)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	d, e := parseDump(f, uint64(st.Size()))
	if e != nil {
		return e
	}
	m, e := d.wow()
	if e != nil {
		return e
	}
	if m.Stamp != p.TimeDateStamp || m.Size != opt.SizeOfImage {
		return fmt.Errorf("module timestamp/image-size mismatch")
	}
	hdr, e := d.memory(m.Base, 4096)
	if e != nil {
		return e
	}
	if string(hdr[:2]) != "MZ" {
		return fmt.Errorf("memory PE missing MZ")
	}
	nt := uint64(le.Uint32(hdr[0x3c:]))
	if nt > 4096-264 || string(hdr[nt:nt+4]) != "PE\x00\x00" || le.Uint16(hdr[nt+4:]) != 0x8664 || le.Uint32(hdr[nt+8:]) != m.Stamp || le.Uint32(hdr[nt+24+56:]) != m.Size {
		return fmt.Errorf("memory PE header mismatch")
	}
	report["disk_sha256"] = wowHash
	report["module_base"] = fmt.Sprintf("0x%x", m.Base)
	report["module_timestamp"] = m.Stamp
	report["module_size"] = m.Size
	report["dump_size_bytes"] = st.Size()
	report["module_identity_scope"] = "disk hash pinned; dump module timestamp/image-size and memory PE header matched, not a hash of all loaded code"
	targets := []struct {
		Name      string
		RVA, Size uint32
	}{{"merge_candidate", 0x1b14120, 24}, {"creator_candidate", 0x1b11190, 110}, {"parse_fallback_candidate", 0x33068c0, 244}}
	rows := []map[string]any{}
	pages := map[uint32]bool{}
	missing := 0
	for _, t := range targets {
		row := map[string]any{"role_candidate": t.Name, "rva": fmt.Sprintf("0x%x", t.RVA), "size": t.Size}
		b, e := d.memory(m.Base+uint64(t.RVA), uint64(t.Size))
		if e != nil {
			row["status"] = "missing"
			row["error"] = e.Error()
			missing++
		} else {
			baseline, e := diskRange(p, disk, t.RVA, t.Size)
			if e != nil {
				return e
			}
			row["status"] = "present"
			row["memory_sha256"] = hash(b)
			row["disk_sha256"] = hash(baseline)
			row["raw_bytes_equal_disk"] = hash(b) == hash(baseline)
			row["first_24_bytes"] = hex.EncodeToString(b[:24])
			if e = os.WriteFile(filepath.Join(out, t.Name+".bin"), b, 0600); e != nil {
				return e
			}
		}
		rows = append(rows, row)
		page := t.RVA &^ uint32(4095)
		if !pages[page] {
			pages[page] = true
			b, e := d.memory(m.Base+uint64(page), 4096)
			if e == nil {
				if e = os.WriteFile(filepath.Join(out, fmt.Sprintf("page-%08x.bin", page)), b, 0600); e != nil {
					return e
				}
			}
		}
	}
	report["targets"] = rows
	report["status"] = "snapshot_valid_targets_present"
	if missing > 0 {
		report["status"] = "snapshot_valid_targets_missing"
	}
	report["target_missing_count"] = missing
	return nil
}
func bundle(dir, dest string) error {
	out, e := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	z := zip.NewWriter(out)
	err := filepath.WalkDir(dir, func(path string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.IsDir() {
			return nil
		}
		name := de.Name()
		if name != "analysis.json" && name != "run.json" && name != "procdump.stdout.txt" && name != "procdump.stderr.txt" && !strings.HasSuffix(name, ".bin") {
			return nil
		}
		s, e := os.Stat(path)
		if e != nil {
			return e
		}
		if s.Size() > 4*1024*1024 {
			return fmt.Errorf("unexpected large report member")
		}
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		defer f.Close()
		rel, e := filepath.Rel(dir, path)
		if e != nil {
			return e
		}
		w, e := z.Create(filepath.ToSlash(rel))
		if e != nil {
			return e
		}
		_, e = io.Copy(w, f)
		return e
	})
	ze := z.Close()
	fe := out.Close()
	if err != nil {
		return err
	}
	if ze != nil {
		return ze
	}
	return fe
}
