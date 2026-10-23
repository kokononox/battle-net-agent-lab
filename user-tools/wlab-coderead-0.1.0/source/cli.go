package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

func reportAllowed(n string) bool {
	if n == "analysis.json" || n == "run.json" {
		return true
	}
	for _, c := range candidatePlan {
		if n == c.Name+".bin" {
			return true
		}
	}
	for _, rva := range pagePlan {
		if n == fmt.Sprintf("page-%08x.bin", rva) {
			return true
		}
	}
	for _, prefix := range []string{"read", "bundle", "probe-zero", "probe-seven"} {
		for _, suffix := range []string{".stdout.txt", ".stderr.txt", ".result.json"} {
			if n == prefix+suffix {
				return true
			}
		}
	}
	return false
}
func bundle(dir, dest string) error {
	out, e := os.Create(dest)
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
		if !info.Mode().IsRegular() || info.Size() > 4*1024*1024 {
			return fmt.Errorf("unexpected report member")
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
func runCLI() {
	var e error
	switch {
	case len(os.Args) == 3 && os.Args[1] == "--child-probe":
		n, er := strconv.Atoi(os.Args[2])
		if er != nil || (n != 0 && n != 7) {
			fmt.Fprintln(os.Stderr, "invalid probe")
			os.Exit(2)
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
		e = fmt.Errorf("internal modes: --read-once PID CREATION_FILETIME REPORT | --bundle REPORT ZIP | --child-probe 0|7")
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
