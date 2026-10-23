package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

func reportAllowed(n string) bool {
	if n == "analysis.json" || n == "run.json" || n == "trust.json" {
		return true
	}
	for _, p := range []string{"read", "bundle", "probe-zero", "probe-seven"} {
		for _, s := range []string{".stdout.txt", ".stderr.txt", ".result.json"} {
			if n == p+s {
				return true
			}
		}
	}
	return false
}
func bundle(dir, dest string) error {
	out, e := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	z := zip.NewWriter(out)
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			if path != dir {
				return filepath.SkipDir
			}
			return nil
		}
		if !reportAllowed(d.Name()) {
			return nil
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || info.Size() > 256*1024 {
			return fmt.Errorf("report member rejected")
		}
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		defer f.Close()
		w, e := z.Create(d.Name())
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
func runRead(pid uint32, start uint64, dir string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	marker, e := os.OpenFile(filepath.Join(dir, ".api-slot-attempt"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return fmt.Errorf("attempt marker exists or cannot be created; no retry: %w", e)
	}
	marker.Close()
	var r report
	var tm trustManifest
	runErr := func() error {
		info, e := os.Stat(filepath.Join(dir, "trust.json"))
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || info.Size() > 65536 {
			return fmt.Errorf("signature manifest rejected")
		}
		b, e := os.ReadFile(filepath.Join(dir, "trust.json"))
		if e != nil {
			return e
		}
		if e = json.Unmarshal(b, &tm); e != nil {
			return e
		}
		sysdir, e := systemDirectory()
		if e != nil {
			return e
		}
		t, e := openTarget(pid)
		if e != nil {
			return e
		}
		defer t.Close()
		r = probe(t, readDiskFile, tm, pid, start, sysdir)
		if r.Status != "api_slot_sample_complete" {
			return fmt.Errorf("%s", r.Error)
		}
		return nil
	}()
	if r.Tool == "" {
		r = report{Tool: "WLab APIProbe 0.1.1", Status: "read_stopped", Error: fmt.Sprint(runErr), Resolution: resolution{Status: "unresolved", Detail: "No validated sample."}}
	}
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "analysis.json"), b, 0600); e != nil {
		return e
	}
	return runErr
}
func runCLI() {
	var e error
	switch {
	case len(os.Args) == 3 && os.Args[1] == "--child-probe":
		n, er := strconv.Atoi(os.Args[2])
		if er != nil || (n != 0 && n != 7) {
			e = fmt.Errorf("invalid probe")
			break
		}
		fmt.Printf("WLAB-CHILD-PROBE %d\n", n)
		fmt.Fprintf(os.Stderr, "WLAB-CHILD-STDERR %d\n", n)
		os.Exit(n)
	case len(os.Args) == 5 && os.Args[1] == "--read-once":
		pid, er := strconv.ParseUint(os.Args[2], 10, 32)
		if er != nil || pid == 0 {
			e = fmt.Errorf("invalid PID")
			break
		}
		start, er := strconv.ParseUint(os.Args[3], 10, 64)
		if er != nil || start == 0 {
			e = fmt.Errorf("invalid creation time")
			break
		}
		e = runRead(uint32(pid), start, os.Args[4])
	case len(os.Args) == 4 && os.Args[1] == "--bundle":
		e = bundle(os.Args[2], os.Args[3])
	default:
		e = fmt.Errorf("internal modes: --read-once PID FILETIME REPORT | --bundle REPORT ZIP | --child-probe 0|7")
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}
