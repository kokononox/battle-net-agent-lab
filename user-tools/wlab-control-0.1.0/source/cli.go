package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const procHash = "22c2a2b09ade73a342a18dab838354385f73fc98e324b9903fd61fff949c5124"

func hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func controlWorker(ready string, hold time.Duration) error {
	memory := make([]byte, 2*1024*1024)
	for i := range memory {
		memory[i] = byte(i % 251)
	}
	b, _ := json.Marshal(map[string]any{"purpose": "owned WLab diagnostic worker; not Wow", "pid": os.Getpid(), "ready_utc": time.Now().UTC().Format(time.RFC3339Nano), "allocated_test_bytes": len(memory)})
	f, e := os.OpenFile(ready, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	fmt.Println("WLAB-CONTROL-WORKER-READY")
	time.Sleep(hold)
	runtime.KeepAlive(memory)
	return nil
}
func reportAllowed(n string) bool {
	if n == "run.json" || n == "control-worker-ready.json" {
		return true
	}
	for _, prefix := range []string{"preparation", "bundle", "probe-zero", "probe-seven", "control-worker", "control-clone", "control-direct", "cancel-clone", "cancel-direct"} {
		for _, suffix := range []string{".stdout.txt", ".stderr.txt", ".result.json", ".decoded.txt"} {
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
		if !info.Mode().IsRegular() {
			return fmt.Errorf("not a regular report member")
		}
		if info.Size() > 4*1024*1024 {
			return fmt.Errorf("oversized report member")
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
	case len(os.Args) == 3 && os.Args[1] == "--control-worker":
		e = controlWorker(os.Args[2], 150*time.Second)
	case len(os.Args) == 3 && os.Args[1] == "--prepare":
		e = prepare(os.Args[2])
	case len(os.Args) == 4 && os.Args[1] == "--bundle":
		e = bundle(os.Args[2], os.Args[3])
	default:
		e = fmt.Errorf("internal modes: --control-worker READY | --prepare DIR | --bundle REPORT ZIP | --child-probe 0|7")
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, strings.TrimSpace(e.Error()))
		os.Exit(1)
	}
}

func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, byte(10)), 0600)
}
