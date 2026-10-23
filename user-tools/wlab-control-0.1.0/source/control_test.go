package main

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOwnedWorkerWritesIdentity(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ready.json")
	if e := controlWorker(p, time.Millisecond); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(p)
	var j map[string]any
	if e := json.Unmarshal(b, &j); e != nil {
		t.Fatal(e)
	}
	if int(j["pid"].(float64)) != os.Getpid() || j["purpose"] != "owned WLab diagnostic worker; not Wow" {
		t.Fatal(j)
	}
}
func TestOwnedWorkerDoesNotOverwriteReady(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ready.json")
	os.WriteFile(p, []byte("existing"), 0600)
	if e := controlWorker(p, time.Millisecond); e == nil {
		t.Fatal("overwrote ready")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "existing" {
		t.Fatal("changed ready")
	}
}
func TestBundleExcludesDumpsAndUnknownFiles(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(t.TempDir(), "ready.zip")
	for _, n := range []string{"run.json", "control-worker-ready.json", "control-clone.stdout.txt", "control-direct.decoded.txt", "control-clone.dmp", "unrelated.txt"} {
		os.WriteFile(filepath.Join(dir, n), []byte("x"), 0600)
	}
	if e := bundle(dir, dest); e != nil {
		t.Fatal(e)
	}
	z, e := zip.OpenReader(dest)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	if len(z.File) != 4 {
		t.Fatalf("members=%d", len(z.File))
	}
	for _, f := range z.File {
		if strings.HasSuffix(f.Name, ".dmp") || f.Name == "unrelated.txt" {
			t.Fatal(f.Name)
		}
	}
}
func TestBundleRejectsLargeAllowedMember(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "run.json"), make([]byte, 4*1024*1024+1), 0600)
	if e := bundle(dir, filepath.Join(t.TempDir(), "r.zip")); e == nil {
		t.Fatal("accepted oversized report")
	}
}
func TestControlTargetComesOnlyFromOwnedWorker(t *testing.T) {
	b, e := os.ReadFile("control.ps1")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	for _, v := range []string{"$pidText=[string]$script:worker.Pid", "target_pid=$script:worker.Pid", "Start-WLabChild $WLabExe @('--control-worker'", "RunCase 'control-clone' $true", "RunCase 'control-direct' $false", "game_capture_requested=$false", "Acquire-WLabCaptureLock $cache"} {
		if !strings.Contains(s, v) {
			t.Fatal("missing guard", v)
		}
	}
	for _, bad := range []string{"Get-Process -Name Wow", "--extract", "-e 1", "-k'", "WLab-Snapshot"} {
		if strings.Contains(s, bad) {
			t.Fatal("unexpected game/capture path", bad)
		}
	}
}
