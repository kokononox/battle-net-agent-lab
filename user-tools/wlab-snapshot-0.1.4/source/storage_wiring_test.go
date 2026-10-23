package main

import (
	"os"
	"strings"
	"testing"
)

func TestGameDriveStorageWiring(t *testing.T) {
	b, e := os.ReadFile("capture.ps1")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	for _, want := range []string{"$outputRoot=Get-WLabGameOutputRoot $script:t.Path", "$script:run=Join-Path $outputRoot", "Acquire-WLabCaptureLock $root", "$script:tools=Join-Path $root", "Get-WLabOutputFreeBytes $script:run", "output_free_bytes_before_capture -lt 8GB", "-lt 1GB"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing storage guard %q", want)
		}
	}
	if strings.Contains(s, "$script:run=Join-Path $root ") {
		t.Fatal("run output still follows cache drive")
	}
	b, e = os.ReadFile("main_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(b), `storageScript + "\n" + guiScript`) {
		t.Fatal("storage helper not embedded before GUI")
	}
}
