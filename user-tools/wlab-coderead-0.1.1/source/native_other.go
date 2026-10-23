//go:build !windows

package main

import "fmt"

func openTarget(pid uint32) (targetReader, error) {
	return nil, fmt.Errorf("real process memory reads require Windows amd64; Linux tests use fake readers only")
}
