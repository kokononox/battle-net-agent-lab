package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestPhaseLogsAndResultsBundledWithoutDump(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(t.TempDir(), "report.zip")
	for _, name := range []string{"run.json", "preparation.stdout.txt", "preparation.stderr.txt", "preparation.result.json", "extract.stderr.txt", "probe-zero.result.json", "probe-seven.result.json", "snapshot.dmp", "not-allowlisted.txt"} {
		if e := os.WriteFile(filepath.Join(dir, name), []byte("test"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := bundle(dir, dest); e != nil {
		t.Fatal(e)
	}
	z, e := zip.OpenReader(dest)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	names := map[string]bool{}
	for _, f := range z.File {
		names[f.Name] = true
	}
	for _, n := range []string{"preparation.stderr.txt", "preparation.stdout.txt", "preparation.result.json", "probe-zero.result.json", "probe-seven.result.json", "extract.stderr.txt"} {
		if !names[n] {
			t.Fatal("diagnostic omitted", n)
		}
	}
	if names["snapshot.dmp"] || names["not-allowlisted.txt"] {
		t.Fatal("unexpected member included")
	}
}
