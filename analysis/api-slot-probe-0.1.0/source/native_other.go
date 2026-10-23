//go:build !windows

package main

import "fmt"

func openTarget(pid uint32) (targetReader, error) {
	return nil, fmt.Errorf("Windows AMD64 required; no memory read attempted")
}
func systemDirectory() (string, error) { return "", fmt.Errorf("Windows AMD64 required") }
