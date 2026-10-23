//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var getTimes = kernel.NewProc("GetProcessTimes")
var queryImage = kernel.NewProc("QueryFullProcessImageNameW")
var moduleSnapshot = kernel.NewProc("CreateToolhelp32Snapshot")
var moduleFirst = kernel.NewProc("Module32FirstW")
var moduleNext = kernel.NewProc("Module32NextW")
var queryMemory = kernel.NewProc("VirtualQueryEx")
var readMemory = kernel.NewProc("ReadProcessMemory")

type nativeTarget struct {
	handle syscall.Handle
	pid    uint32
}
type moduleEntry struct {
	Size, ModuleID, PID, GlobalUsage, ProcessUsage uint32
	Base                                           uintptr
	ImageSize                                      uint32
	Module                                         syscall.Handle
	Name                                           [256]uint16
	Path                                           [260]uint16
}
type memoryInfo struct {
	Base, AllocationBase           uintptr
	AllocationProtect              uint32
	Partition                      uint16
	Padding                        uint16
	Size                           uintptr
	State, Protect, Type, Padding2 uint32
}

func nativeError(api string, e error) error {
	var code uint32
	if n, ok := e.(syscall.Errno); ok {
		code = uint32(n)
	}
	return &apiFailure{API: api, Code: code, Message: fmt.Sprint(e)}
}
func openTarget(pid uint32) (targetReader, error) {
	// PROCESS_QUERY_INFORMATION | PROCESS_VM_READ only. No debug-privilege manipulation.
	h, e := syscall.OpenProcess(0x0400|0x0010, false, pid)
	if e != nil {
		return nil, nativeError("OpenProcess(read/query only)", e)
	}
	return &nativeTarget{handle: h, pid: pid}, nil
}
func (t *nativeTarget) Close() error { return syscall.CloseHandle(t.handle) }
func (t *nativeTarget) Identity() (identity, error) {
	id := identity{PID: t.pid}
	var created, exited, kernelTime, userTime syscall.Filetime
	r, _, e := getTimes.Call(uintptr(t.handle), uintptr(unsafe.Pointer(&created)), uintptr(unsafe.Pointer(&exited)), uintptr(unsafe.Pointer(&kernelTime)), uintptr(unsafe.Pointer(&userTime)))
	if r == 0 {
		return id, nativeError("GetProcessTimes", e)
	}
	if exited.HighDateTime != 0 || exited.LowDateTime != 0 {
		return id, fmt.Errorf("selected process exited")
	}
	id.Start = uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	r, _, e = queryImage.Call(uintptr(t.handle), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return id, nativeError("QueryFullProcessImageNameW", e)
	}
	id.Path = syscall.UTF16ToString(buf[:n])
	// Module-list metadata only (TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32), NOT a PSS/process clone.
	snap, _, e := moduleSnapshot.Call(0x00000008|0x00000010, uintptr(t.pid))
	if snap == ^uintptr(0) {
		return id, nativeError("CreateToolhelp32Snapshot(module metadata)", e)
	}
	defer syscall.CloseHandle(syscall.Handle(snap))
	entry := moduleEntry{}
	entry.Size = uint32(unsafe.Sizeof(entry))
	r, _, e = moduleFirst.Call(snap, uintptr(unsafe.Pointer(&entry)))
	count := 0
	for r != 0 {
		if samePath(syscall.UTF16ToString(entry.Path[:]), id.Path) {
			id.Base = uint64(entry.Base)
			id.ImageSize = entry.ImageSize
			id.ModulePath = syscall.UTF16ToString(entry.Path[:])
			return id, nil
		}
		count++
		if count > 4096 {
			return id, fmt.Errorf("module metadata enumeration cap reached")
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		r, _, e = moduleNext.Call(snap, uintptr(unsafe.Pointer(&entry)))
	}
	return id, fmt.Errorf("main image not found in module metadata: %v", e)
}
func (t *nativeTarget) Region(addr uint64) (region, error) {
	var m memoryInfo
	r, _, e := queryMemory.Call(uintptr(t.handle), uintptr(addr), uintptr(unsafe.Pointer(&m)), unsafe.Sizeof(m))
	if r != unsafe.Sizeof(m) {
		return region{}, nativeError("VirtualQueryEx", e)
	}
	return region{Base: uint64(m.Base), AllocationBase: uint64(m.AllocationBase), Size: uint64(m.Size), State: m.State, Protect: m.Protect, Type: m.Type}, nil
}
func (t *nativeTarget) Read(addr uint64, n uint32) ([]byte, error) {
	if n == 0 || n > 4096 || addr > ^uint64(0)-uint64(n) {
		return nil, fmt.Errorf("read exceeds bounded page limit")
	}
	b := make([]byte, n)
	var got uintptr
	r, _, e := readMemory.Call(uintptr(t.handle), uintptr(addr), uintptr(unsafe.Pointer(&b[0])), uintptr(n), uintptr(unsafe.Pointer(&got)))
	if got > uintptr(n) {
		return nil, fmt.Errorf("native read returned invalid byte count")
	}
	if r == 0 {
		return b[:int(got)], nativeError("ReadProcessMemory", e)
	}
	return b[:int(got)], nil
}

// Compile-time AMD64 Windows ABI layout checks; runtime APIs still need a Windows test.
var _ [1080 - unsafe.Sizeof(moduleEntry{})]byte
var _ [unsafe.Sizeof(moduleEntry{}) - 1080]byte
var _ [48 - unsafe.Sizeof(memoryInfo{})]byte
var _ [unsafe.Sizeof(memoryInfo{}) - 48]byte
