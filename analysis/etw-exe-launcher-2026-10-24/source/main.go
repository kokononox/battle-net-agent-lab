// Windows x64 launcher for the unchanged ETW loopback control.
// Uses built-in PowerShell, visible console, normal UAC, no policy modification.
package main

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

//go:embed Run-Control.ps1 Control.wprp
var payload embed.FS
var user32 = syscall.NewLazyDLL("user32.dll")
var shell32 = syscall.NewLazyDLL("shell32.dll")
var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var messageBox = user32.NewProc("MessageBoxW")
var shellExecute = shell32.NewProc("ShellExecuteW")
var isAdmin = shell32.NewProc("IsUserAnAdmin")
var createMutex = kernel32.NewProc("CreateMutexW")
var closeHandle = kernel32.NewProc("CloseHandle")
var getSystemDirectory = kernel32.NewProc("GetSystemDirectoryW")

func wide(s string) *uint16 {
	p, e := syscall.UTF16PtrFromString(s)
	if e != nil {
		panic(e)
	}
	return p
}
func dialog(text string, flags uintptr) uintptr {
	r, _, _ := messageBox.Call(0, uintptr(unsafe.Pointer(wide(text))), uintptr(unsafe.Pointer(wide("WLab ETW Control 0.1.1"))), flags)
	return r
}
func fail(err error) { dialog(err.Error(), 0x10) }
func encodedCommand(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	return base64.StdEncoding.EncodeToString(b)
}
func run() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(exe)
	if strings.HasPrefix(dir, `\\`) {
		return fmt.Errorf("Extract this package to a local drive first, not a network share.")
	}
	admin, _, _ := isAdmin.Call()
	if admin == 0 {
		r, _, _ := shellExecute.Call(0, uintptr(unsafe.Pointer(wide("runas"))), uintptr(unsafe.Pointer(wide(exe))), 0, uintptr(unsafe.Pointer(wide(dir))), 1)
		if r <= 32 {
			return fmt.Errorf("Administrator approval was cancelled or launch failed (ShellExecute code %d). No tracing was started.", r)
		}
		return nil
	}
	h, _, last := createMutex.Call(0, 0, uintptr(unsafe.Pointer(wide(`Local\WLab_ETW_Control_011_Launcher`))))
	if h == 0 {
		return fmt.Errorf("Cannot create launcher lock: %v", last)
	}
	defer closeHandle.Call(h)
	if last == syscall.Errno(183) {
		dialog("A control window is already running. Check its visible PowerShell window and finish it before starting another test.", 0x40)
		return nil
	}
	if dialog("Close the game before continuing.\n\nThis test uses built-in Windows tracing and sends 448 test bytes only to 127.0.0.1. No Internet, installation, game attachment, or upload. Background network metadata may be recorded.\n\nA visible PowerShell window will show progress. Continue?", 0x4|0x40) != 6 {
		return nil
	}
	work, err := os.MkdirTemp(dir, "WLab-Control-")
	if err != nil {
		return fmt.Errorf("Cannot create output beside the EXE. Extract it to a writable local drive.\n%v", err)
	}
	profile, err := payload.ReadFile("Control.wprp")
	if err != nil {
		return err
	}
	script, err := payload.ReadFile("Run-Control.ps1")
	if err != nil {
		return err
	}
	// Audit copies; execution uses the same embedded script inline, with only its base path binding changed.
	if err = os.WriteFile(filepath.Join(work, "Control.wprp"), profile, 0600); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(work, "Run-Control.ps1"), script, 0600); err != nil {
		return err
	}
	b := make([]uint16, 32768)
	n, _, _ := getSystemDirectory.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if n == 0 || n >= uintptr(len(b)) {
		return fmt.Errorf("Cannot resolve the Windows system directory.")
	}
	system := syscall.UTF16ToString(b[:int(n)])
	ps := filepath.Join(system, `WindowsPowerShell\v1.0\powershell.exe`)
	if _, err = os.Stat(ps); err != nil {
		return fmt.Errorf("Built-in Windows PowerShell not found: %v", err)
	}
	original := string(script)
	if strings.Count(original, "$base = $PSScriptRoot") != 1 {
		return fmt.Errorf("Embedded script base-path invariant failed.")
	}
	inline := strings.Replace(original, "$base = $PSScriptRoot", "$base = $env:WLAB_CONTROL_DIR", 1)
	command := "try { & {\n" + inline + "\n} } catch { Write-Host $_.Exception.Message -ForegroundColor Red } finally { Write-Host ('Working folder: ' + $env:WLAB_CONTROL_DIR); [void](Read-Host 'Press Enter to close this window') }"
	encoded := encodedCommand(command)
	if len(encoded)+len(ps)+200 >= 32000 {
		return fmt.Errorf("Embedded command exceeds the safe Windows command-line budget.")
	}
	hash := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	info := map[string]interface{}{"launcher_version": "0.1.1", "script_sha256": hash(script), "profile_sha256": hash(profile), "policy_changed": false, "execution": "Visible built-in PowerShell, UTF-16LE EncodedCommand; base64 is transport encoding, not encryption.", "windows_runtime_tested": false}
	data, _ := json.MarshalIndent(info, "", "  ")
	if err = os.WriteFile(filepath.Join(work, "launcher-info.json"), data, 0600); err != nil {
		return err
	}
	// CreateProcess directly, WITHOUT STARTF_USESTDHANDLES: the child receives
	// its own console handles, not os/exec's default NUL streams in a GUI parent.
	if err = os.Setenv("WLAB_CONTROL_DIR", work); err != nil {
		return err
	}
	if err = os.Setenv("WINDIR", filepath.Dir(system)); err != nil {
		return err
	}
	line, err := syscall.UTF16FromString(`"` + ps + `" -NoLogo -NoProfile -EncodedCommand ` + encoded)
	if err != nil {
		return err
	}
	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation
	ok, _, callErr := kernel32.NewProc("CreateProcessW").Call(
		uintptr(unsafe.Pointer(wide(ps))), uintptr(unsafe.Pointer(&line[0])), 0, 0, 0,
		0x00000010, 0, uintptr(unsafe.Pointer(wide(work))), uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if ok == 0 {
		return fmt.Errorf("Cannot open visible control console. Files remain in %s.\n%v", work, callErr)
	}
	closeHandle.Call(uintptr(pi.Thread))
	defer closeHandle.Call(uintptr(pi.Process))
	wait, _, waitErr := kernel32.NewProc("WaitForSingleObject").Call(uintptr(pi.Process), 0xffffffff)
	if wait != 0 {
		return fmt.Errorf("Cannot wait for the control window. Folder: %s\n%v", work, waitErr)
	}
	var exitCode uint32
	ok, _, callErr = kernel32.NewProc("GetExitCodeProcess").Call(uintptr(pi.Process), uintptr(unsafe.Pointer(&exitCode)))
	if ok == 0 {
		return fmt.Errorf("Cannot read control exit code: %v", callErr)
	}
	if exitCode != 0 {
		return fmt.Errorf("Control console ended with code %d. Keep results in:\n%s", exitCode, work)
	}

	return nil
}
func main() {
	if err := run(); err != nil {
		fail(err)
	}
}
