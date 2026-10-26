import unittest,os,sys,subprocess
from process_exit_proof import termination_proven

class T(unittest.TestCase):
    def test_signalled_only(self):
        self.assertTrue(termination_proven(0))
        for x in (258,0xffffffff,1,128,None,False,0.0,'0'):
            self.assertFalse(termination_proven(x))

    @unittest.skipUnless(os.name=='nt','native Windows controlled-child check')
    def test_native_owned_child_active_and_terminated(self):
        import ctypes as C
        from ctypes import wintypes as W
        k=C.WinDLL('kernel32',use_last_error=True)
        k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE
        k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.WaitForSingleObject.restype=W.DWORD
        k.CloseHandle.argtypes=[W.HANDLE]
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)'])
        handle=k.OpenProcess(0x100000,False,child.pid)
        try:
            self.assertTrue(handle)
            self.assertFalse(termination_proven(k.WaitForSingleObject(handle,0)))
            child.terminate();child.wait(timeout=10)
            self.assertTrue(termination_proven(k.WaitForSingleObject(handle,0)))
        finally:
            if child.poll() is None:
                child.kill();child.wait()
            if handle:k.CloseHandle(handle)