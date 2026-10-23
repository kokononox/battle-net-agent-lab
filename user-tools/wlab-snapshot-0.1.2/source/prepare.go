package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const packageURL = "https://download.sysinternals.com/files/Procdump.zip"
const packageHash = "5fe68e81632f13188930affff20a9a9910170bae654360850d3108cead708a2d"

func prepare(dir string) error {
	if b, e := os.ReadFile(filepath.Join(dir, "procdump64.exe")); e == nil && hash(b) == procHash {
		return nil
	}
	client := &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || req.URL.Scheme != "https" || req.URL.Hostname() != "download.sysinternals.com" {
			return fmt.Errorf("unapproved download redirect")
		}
		return nil
	}}
	resp, e := client.Get(packageURL)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download HTTP %d", resp.StatusCode)
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 3*1024*1024+1))
	if e != nil {
		return e
	}
	if len(raw) > 3*1024*1024 || hash(raw) != packageHash {
		return fmt.Errorf("official package changed or download incomplete; no execution")
	}
	z, e := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		return e
	}
	files := map[string][]byte{}
	for _, f := range z.File {
		if f.Name != "procdump64.exe" && f.Name != "Eula.txt" {
			continue
		}
		if _, ok := files[f.Name]; ok {
			return fmt.Errorf("duplicate package member")
		}
		r, e := f.Open()
		if e != nil {
			return e
		}
		b, e := io.ReadAll(io.LimitReader(r, 4*1024*1024+1))
		r.Close()
		if e != nil {
			return e
		}
		if len(b) > 4*1024*1024 {
			return fmt.Errorf("oversized package member")
		}
		files[f.Name] = b
	}
	if hash(files["procdump64.exe"]) != procHash || len(files["Eula.txt"]) == 0 {
		return fmt.Errorf("required official member mismatch")
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	for name, b := range files {
		temp, e := os.CreateTemp(dir, "prepare-*.tmp")
		if e != nil {
			return e
		}
		tmp := temp.Name()
		if _, e = temp.Write(b); e != nil {
			temp.Close()
			os.Remove(tmp)
			return e
		}
		if e = temp.Close(); e != nil {
			os.Remove(tmp)
			return e
		}
		dest := filepath.Join(dir, name)
		if e = os.Rename(tmp, dest); e != nil {
			os.Remove(tmp)
			return e
		}
	}
	return nil
}
