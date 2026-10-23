//go:build windows

package main

import (
	_ "embed"
	"strings"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

//go:embed capture.ps1
var guiScript string

func main() {
	if len(os.Args) > 1 {
		runCLI()
		return
	}
	exe, e := os.Executable()
	if e != nil {
		panic(e)
	}
	script := "$WLabExe='" + psQuote(exe) + "';$WLabRoot='" + psQuote(filepath.Dir(exe)) + "';" + guiScript
 loader := "$b=New-Object IO.MemoryStream;[Console]::OpenStandardInput().CopyTo($b); & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString($b.ToArray())))"
 cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoLogo", "-NoProfile", "-NonInteractive", "-STA", "-Command", loader)
 cmd.Stdin = strings.NewReader(script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Dir = filepath.Dir(exe)
	log, e := os.OpenFile(filepath.Join(os.TempDir(), "WLab-Snapshot-launcher.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if e == nil {
		defer log.Close()
		cmd.Stdout = log
		cmd.Stderr = log
	}
	if e = cmd.Run(); e != nil {
		msg := fmt.Sprintf("WLab UI did not start. See %%TEMP%%\\WLab-Snapshot-launcher.log. Error: %v", e)
		p, _ := syscall.UTF16PtrFromString(msg)
		title, _ := syscall.UTF16PtrFromString("WLab Snapshot")
		syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafePointer(p)), uintptr(unsafePointer(title)), 0x10)
	}
}
func psQuote(s string) string {
	out := ""
	for _, r := range s {
		if r == '\'' {
			out += "''"
		} else {
			out += string(r)
		}
	}
	return out
}
