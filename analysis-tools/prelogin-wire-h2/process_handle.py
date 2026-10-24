"""G1: native root+child fixture gate, then one verified startup from process birth."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

class Process:
    """Minimal Popen-compatible handle for observe_agent's one exact setup launch."""
    def __init__(self, manager, pid):
        self.manager, self.pid = manager, pid
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        self.api.OpenProcess.restype = ctypes.c_void_p
        self.api.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        self.api.CloseHandle.argtypes = [ctypes.c_void_p]
        self.handle = self.api.OpenProcess(0x1000, False, pid)
        if not self.handle:
            raise OSError("process_handle_unavailable")
    def poll(self):
        code = ctypes.c_uint32()
        if not self.api.GetExitCodeProcess(self.handle, ctypes.byref(code)):
            raise OSError("process_status_unavailable")
        return None if code.value == 259 else code.value
    def wait(self, timeout=None):
        deadline = time.monotonic() + (timeout if timeout is not None else 30)
        while time.monotonic() < deadline:
            code = self.poll()
            if code is not None:
                return code
            time.sleep(.05)
        raise subprocess.TimeoutExpired("verified_setup", timeout)
    def kill(self):
        from manager import bounded
        bounded(self.manager.frida, lambda: self.manager.device.kill(self.pid))
    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None
