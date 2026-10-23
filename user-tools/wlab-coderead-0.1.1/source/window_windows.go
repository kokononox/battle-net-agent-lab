//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

const ownUITitle = "WLab CodeRead 0.1.1 - One bounded read only"

var u32 = syscall.NewLazyDLL("user32.dll")
var enumWindows = u32.NewProc("EnumWindows")
var windowPID = u32.NewProc("GetWindowThreadProcessId")
var windowText = u32.NewProc("GetWindowTextW")
var windowRectProc = u32.NewProc("GetWindowRect")
var visibleProc = u32.NewProc("IsWindowVisible")
var iconicProc = u32.NewProc("IsIconic")
var foregroundProc = u32.NewProc("GetForegroundWindow")
var showAsyncProc = u32.NewProc("ShowWindowAsync")
var setPosProc = u32.NewProc("SetWindowPos")
var foregroundSetProc = u32.NewProc("SetForegroundWindow")
var workAreaProc = u32.NewProc("SystemParametersInfoW")
var sessionProc = syscall.NewLazyDLL("kernel32.dll").NewProc("ProcessIdToSessionId")

func findOwnWindow(pid uint32) uintptr {
	var found uintptr
	cb := syscall.NewCallback(func(h, l uintptr) uintptr {
		var owner uint32
		windowPID.Call(h, uintptr(unsafe.Pointer(&owner)))
		if owner != pid {
			return 1
		}
		text := make([]uint16, 256)
		windowText.Call(h, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)))
		if syscall.UTF16ToString(text) == ownUITitle {
			found = h
			return 0
		}
		return 1
	})
	enumWindows.Call(cb, 0)
	return found
}
func stillOwnWindow(h uintptr, pid uint32) bool {
	var owner uint32
	windowPID.Call(h, uintptr(unsafe.Pointer(&owner)))
	return owner == pid
}
func ownWindowState(h uintptr, pid uint32) map[string]any {
	var owner uint32
	windowPID.Call(h, uintptr(unsafe.Pointer(&owner)))
	if owner != pid {
		return map[string]any{"hwnd": fmt.Sprintf("0x%x", h), "owner_matches_launched_worker": false}
	}
	var r windowRect
	valid, _, _ := windowRectProc.Call(h, uintptr(unsafe.Pointer(&r)))
	v, _, _ := visibleProc.Call(h)
	iconic, _, _ := iconicProc.Call(h)
	fg, _, _ := foregroundProc.Call()
	return map[string]any{"hwnd": fmt.Sprintf("0x%x", h), "window_owner_pid": owner, "owner_matches_launched_worker": true, "is_window_visible": v != 0, "is_minimized": iconic != 0, "is_foreground_window": fg == h, "rectangle_valid": valid != 0, "rectangle": r}
}
func monitorOwnUI(pid uint32, logs string, stop <-chan struct{}) {
	report := map[string]any{"tool": "WLab CodeRead 0.1.1", "ui_worker_pid": pid, "launcher_pid": os.Getpid(), "requested_worker_creation_flag": "CREATE_NO_WINDOW (0x08000000), no HideWindow/SW_HIDE startup flag", "visibility_limit": "native visible/foreground/rectangle state does not prove the human can see or interact with the window"}
	defer func() {
		report["updated_utc"] = time.Now().UTC().Format(time.RFC3339)
		writeJSON(filepath.Join(logs, "window-state.json"), report)
		needsHelp := report["status"] == "own_ui_window_not_found_within_30_seconds"
		if report["status"] == "own_window_found_restore_and_position_attempted" {
			if after, ok := report["after"].(map[string]any); ok {
				needsHelp = after["is_window_visible"] != true || after["is_minimized"] == true
			}
		}
		if needsHelp {
			exec.Command(filepath.Join(os.Getenv("SystemRoot"), "explorer.exe"), logs).Start()
			message("WLab could not verify a normal visible interface. Send window-state.json and launcher.log from this folder:\n" + logs)
		}
	}()
	var selfSession, childSession uint32
	a, _, _ := sessionProc.Call(uintptr(os.Getpid()), uintptr(unsafe.Pointer(&selfSession)))
	b, _, _ := sessionProc.Call(uintptr(pid), uintptr(unsafe.Pointer(&childSession)))
	report["launcher_session_lookup_ok"] = a != 0
	report["worker_session_lookup_ok"] = b != 0
	if a != 0 {
		report["launcher_session_id"] = selfSession
	}
	if b != 0 {
		report["worker_session_id"] = childSession
	}
	limit := time.NewTimer(30 * time.Second)
	defer limit.Stop()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			report["status"] = "worker_exited_before_window_check"
			return
		case <-limit.C:
			report["status"] = "own_ui_window_not_found_within_30_seconds"
			return
		case <-tick.C:
			if _, e := os.Stat(filepath.Join(logs, "elevation-handoff.txt")); e == nil {
				report["status"] = "elevation_handoff_only"
				return
			}
			if _, e := os.Stat(filepath.Join(logs, "ui-ready.txt")); e != nil {
				continue
			}
			report["shown_event_marker_present"] = true
			h := findOwnWindow(pid)
			if h == 0 {
				continue
			}
			before := ownWindowState(h, pid)
			// Validate process ownership immediately before touching this HWND.
			if before["owner_matches_launched_worker"] != true {
				continue
			}
			report["before"] = before
			show, _, _ := showAsyncProc.Call(h, 9) // SW_RESTORE; does not attach a debugger.
			report["restore_request_accepted"] = show != 0
			var work windowRect
			ok, _, _ := workAreaProc.Call(0x30, 0, uintptr(unsafe.Pointer(&work)), 0) // SPI_GETWORKAREA
			var bounds windowRect
			valid, _, _ := windowRectProc.Call(h, uintptr(unsafe.Pointer(&bounds)))
			if ok != 0 && valid != 0 && stillOwnWindow(h, pid) {
				if x, y, valid := centerOwnWindow(bounds, work); valid {
					positioned, _, _ := setPosProc.Call(h, 0, uintptr(int64(x)), uintptr(int64(y)), 0, 0, 0x4041) // SWP_ASYNCWINDOWPOS | SWP_NOSIZE | SWP_SHOWWINDOW
					report["center_on_primary_work_area_requested"] = true
					report["position_request_accepted"] = positioned != 0
					report["primary_work_area"] = work
				}
			}
			if !stillOwnWindow(h, pid) {
				report["status"] = "own_window_disappeared"
				return
			}
			fg, _, _ := foregroundSetProc.Call(h)
			report["foreground_request_succeeded"] = fg != 0
			select {
			case <-stop:
				report["status"] = "worker_exited_during_window_check"
				return
			case <-time.After(time.Second):
			}
			after := ownWindowState(h, pid)
			report["after"] = after
			if after["owner_matches_launched_worker"] != true {
				report["status"] = "own_window_disappeared"
				return
			}
			report["status"] = "own_window_found_restore_and_position_attempted"
			return
		}
	}
}
