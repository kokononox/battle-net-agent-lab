//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
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
	handle    syscall.Handle
	pid       uint32
	readCalls int
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
	Partition, Padding             uint16
	Size                           uintptr
	State, Protect, Type, Padding2 uint32
}

func nativeError(api string, e error) error {
	var c uint32
	if n, ok := e.(syscall.Errno); ok {
		c = uint32(n)
	}
	return &apiFailure{api, c, fmt.Sprint(e)}
}
func openTarget(pid uint32) (targetReader, error) {
	h, e := syscall.OpenProcess(0x0400|0x0010, false, pid)
	if e != nil {
		return nil, nativeError("OpenProcess(read/query only)", e)
	}
	return &nativeTarget{handle: h, pid: pid}, nil
}
func (t *nativeTarget) Close() error { return syscall.CloseHandle(t.handle) }
func (t *nativeTarget) Identity() (identity, error) {
	id := identity{PID: t.pid}
	var c, x, k, u syscall.Filetime
	r, _, e := getTimes.Call(uintptr(t.handle), uintptr(unsafe.Pointer(&c)), uintptr(unsafe.Pointer(&x)), uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u)))
	if r == 0 {
		return id, nativeError("GetProcessTimes", e)
	}
	if x.HighDateTime != 0 || x.LowDateTime != 0 {
		return id, fmt.Errorf("selected process exited")
	}
	id.Start = uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime)
	b := make([]uint16, 32768)
	n := uint32(len(b))
	r, _, e = queryImage.Call(uintptr(t.handle), 0, uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return id, nativeError("QueryFullProcessImageNameW", e)
	}
	if n == 0 || int(n) > len(b) {
		return id, fmt.Errorf("invalid image path length")
	}
	id.Path = syscall.UTF16ToString(b[:n])
	return id, nil
}
func (t *nativeTarget) Modules() ([]moduleInfo, error) {
	snap, _, e := moduleSnapshot.Call(0x8|0x10, uintptr(t.pid))
	if snap == ^uintptr(0) {
		return nil, nativeError("CreateToolhelp32Snapshot(module metadata)", e)
	}
	defer syscall.CloseHandle(syscall.Handle(snap))
	entry := moduleEntry{}
	entry.Size = uint32(unsafe.Sizeof(entry))
	r, _, e := moduleFirst.Call(snap, uintptr(unsafe.Pointer(&entry)))
	if r == 0 {
		return nil, nativeError("Module32FirstW", e)
	}
	var out []moduleInfo
	for {
		if len(out) >= 4096 {
			return nil, fmt.Errorf("module enumeration cap")
		}
		out = append(out, moduleInfo{syscall.UTF16ToString(entry.Name[:]), syscall.UTF16ToString(entry.Path[:]), uint64(entry.Base), entry.ImageSize})
		entry.Size = uint32(unsafe.Sizeof(entry))
		r, _, e = moduleNext.Call(snap, uintptr(unsafe.Pointer(&entry)))
		if r == 0 {
			if code, ok := e.(syscall.Errno); ok && code == 18 {
				break
			}
			return nil, nativeError("Module32NextW", e)
		}
	}
	return out, nil
}
func (t *nativeTarget) Region(addr uint64) (region, error) {
	var m memoryInfo
	r, _, e := queryMemory.Call(uintptr(t.handle), uintptr(addr), uintptr(unsafe.Pointer(&m)), unsafe.Sizeof(m))
	if r != unsafe.Sizeof(m) {
		return region{}, nativeError("VirtualQueryEx", e)
	}
	return region{uint64(m.Base), uint64(m.AllocationBase), uint64(m.Size), m.State, m.Protect, m.Type}, nil
}
func (t *nativeTarget) Read(addr uint64, n uint32) ([]byte, error) {
	if t.readCalls != 0 || n != 8 || addr > ^uint64(0)-8 {
		return nil, fmt.Errorf("native one-read/exact-eight-byte cap rejected")
	}
	t.readCalls++
	b := make([]byte, 8)
	var got uintptr
	r, _, e := readMemory.Call(uintptr(t.handle), uintptr(addr), uintptr(unsafe.Pointer(&b[0])), 8, uintptr(unsafe.Pointer(&got)))
	if got > 8 {
		return nil, fmt.Errorf("invalid native read count")
	}
	if r == 0 {
		return b[:int(got)], nativeError("ReadProcessMemory", e)
	}
	return b[:int(got)], nil
}
func systemDirectory() (string, error) {
	b := make([]uint16, 32768)
	r, _, e := kernel.NewProc("GetSystemDirectoryW").Call(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if r == 0 || r >= uintptr(len(b)) {
		return "", nativeError("GetSystemDirectoryW", e)
	}
	return syscall.UTF16ToString(b[:int(r)]), nil
}

var _ [1080 - unsafe.Sizeof(moduleEntry{})]byte
var _ [unsafe.Sizeof(moduleEntry{}) - 1080]byte
var _ [48 - unsafe.Sizeof(memoryInfo{})]byte
var _ [unsafe.Sizeof(memoryInfo{}) - 48]byte

// Mapping metadata only: no process-memory reads, privilege changes or fallback APIs.
func (t *nativeTarget) Backing(addr, allocation uint64, expectedPath string) (backingProof, error) {
	p := backingProof{Method: "K32GetMappedFileNameW + GetFinalPathNameByHandleW(VOLUME_NAME_NT) + same-handle SHA256"}
	getMapped := kernel.NewProc("K32GetMappedFileNameW")
	getFinal := kernel.NewProc("GetFinalPathNameByHandleW")
	if e := getMapped.Find(); e != nil {
		return p, nativeError("Find K32GetMappedFileNameW", e)
	}
	if e := getFinal.Find(); e != nil {
		return p, nativeError("Find GetFinalPathNameByHandleW", e)
	}
	mappedName := func(a uint64) (string, error) {
		b := make([]uint16, 32768)
		n, _, e := getMapped.Call(uintptr(t.handle), uintptr(a), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
		if n == 0 {
			return "", nativeError("K32GetMappedFileNameW", e)
		}
		if n >= uintptr(len(b)) {
			return "", fmt.Errorf("mapped-file path truncated; no retry")
		}
		return syscall.UTF16ToString(b[:int(n)]), nil
	}
	var e error
	p.MappedPath, e = mappedName(addr)
	if e != nil {
		return p, e
	}
	p.AllocationPath, e = mappedName(allocation)
	if e != nil {
		return p, e
	}
	f, e := os.Open(expectedPath)
	if e != nil {
		return p, e
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil {
		return p, e
	}
	if !before.Mode().IsRegular() || before.Size() < 64 || before.Size() > 160*1024*1024 {
		return p, fmt.Errorf("opened backing file type/size rejected")
	}
	b := make([]uint16, 32768)
	n, _, ne := getFinal.Call(f.Fd(), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 2) // normalized VOLUME_NAME_NT
	if n == 0 {
		return p, nativeError("GetFinalPathNameByHandleW(NT)", ne)
	}
	if n >= uintptr(len(b)) {
		return p, fmt.Errorf("final NT path too long; no retry")
	}
	p.DiskPath = syscall.UTF16ToString(b[:int(n)])
	h := sha256.New()
	count, e := io.Copy(h, io.LimitReader(f, 160*1024*1024+1))
	if e != nil {
		return p, e
	}
	after, e := f.Stat()
	if e != nil {
		return p, e
	}
	if count != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return p, fmt.Errorf("opened backing file changed during hash")
	}
	p.DiskSHA256 = hex.EncodeToString(h.Sum(nil))
	return p, nil
}
