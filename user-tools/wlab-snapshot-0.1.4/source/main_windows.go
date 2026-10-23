//go:build windows

package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

//go:embed capture.ps1
var guiScript string

//go:embed capture-lock.ps1
var captureLockScript string

//go:embed child-process.ps1
var childProcessScript string

//go:embed storage.ps1
var storageScript string

func message(s string) {
	p, _ := syscall.UTF16PtrFromString(s)
	t, _ := syscall.UTF16PtrFromString("WLab Snapshot 0.1.4")
	syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafePointer(p)), uintptr(unsafePointer(t)), 0x10)
}
func main() {
	if len(os.Args) > 1 {
		runCLI()
		return
	}
	exe, e := os.Executable()
	if e != nil {
		message(e.Error())
		return
	}
	base, e := os.UserCacheDir()
	if e != nil {
		base = os.TempDir()
	}
	parent := filepath.Join(base, "WLabSnapshot", "launcher")
	if e = os.MkdirAll(parent, 0700); e != nil {
		message("Cannot create startup log folder: " + e.Error())
		return
	}
	logs, e := os.MkdirTemp(parent, "startup-")
	if e != nil {
		message(e.Error())
		return
	}
	log, e := os.OpenFile(filepath.Join(logs, "launcher.log"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if e != nil {
		message(e.Error())
		return
	}
	fmt.Fprintf(log, "WLab Snapshot 0.1.4 launcher\nUTC: %s\nPID: %d\n", time.Now().UTC().Format(time.RFC3339), os.Getpid())
	script := "$WLabExe='" + psQuote(exe) + "';$WLabRoot='" + psQuote(filepath.Dir(exe)) + "';$WLabLogDir='" + psQuote(logs) + "';" + captureLockScript + "\n" + childProcessScript + "\n" + storageScript + "\n" + guiScript
	loader := "$b=New-Object IO.MemoryStream;[Console]::OpenStandardInput().CopyTo($b); & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString($b.ToArray())))"
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoLogo", "-NoProfile", "-NonInteractive", "-STA", "-Command", loader)
	cmd.Stdin = strings.NewReader(script)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW: suppress console, not the GUI show state
	cmd.Dir = filepath.Dir(exe)
	cmd.Stdout = log
	cmd.Stderr = log
	if e = cmd.Start(); e == nil {
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() { defer close(done); monitorOwnUI(uint32(cmd.Process.Pid), logs, stop) }()
		e = cmd.Wait()
		close(stop)
		<-done
	}
	if e != nil {
		fmt.Fprintf(log, "\nLauncher error: %v\n", e)
	}
	log.Close()
	_, ready := os.Stat(filepath.Join(logs, "ui-ready.txt"))
	_, handoff := os.Stat(filepath.Join(logs, "elevation-handoff.txt"))
	if e != nil || (ready != nil && handoff != nil) {
		message("The interface could not be confirmed open. Send launcher.log from this folder:\n" + logs)
		exec.Command(filepath.Join(os.Getenv("SystemRoot"), "explorer.exe"), logs).Start()
	}
}
func psQuote(s string) string { return strings.ReplaceAll(s, "'", "''") }
