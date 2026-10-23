package main

import (
	"os"
	"strings"
	"testing"
)

func TestCenterNormalWindow(t *testing.T) {
	x, y, ok := centerOwnWindow(windowRect{0, 0, 800, 500}, windowRect{0, 0, 1920, 1040})
	if !ok || x != 560 || y != 270 {
		t.Fatal(x, y, ok)
	}
}
func TestCenterNegativeMonitorOrigin(t *testing.T) {
	x, y, ok := centerOwnWindow(windowRect{5000, 5000, 5800, 5500}, windowRect{-1920, 0, 0, 1040})
	if !ok || x != -1360 || y != 270 {
		t.Fatal(x, y, ok)
	}
}
func TestOversizedOwnWindowAnchorsAtWorkArea(t *testing.T) {
	x, y, ok := centerOwnWindow(windowRect{0, 0, 2000, 1200}, windowRect{10, 20, 810, 620})
	if !ok || x != 10 || y != 20 {
		t.Fatal(x, y, ok)
	}
}
func TestBadWindowRectangleNotMoved(t *testing.T) {
	if _, _, ok := centerOwnWindow(windowRect{}, windowRect{0, 0, 1920, 1080}); ok {
		t.Fatal("invalid rectangle accepted")
	}
}
func TestGUIWorkerDoesNotRequestHiddenStartup(t *testing.T) {
	b, e := os.ReadFile("main_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	if strings.Contains(s, "HideWindow: true") || !strings.Contains(s, "CreationFlags: 0x08000000") {
		t.Fatal("GUI worker startup flags regressed")
	}
}
