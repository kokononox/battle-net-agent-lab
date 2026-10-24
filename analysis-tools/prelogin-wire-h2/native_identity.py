"""Live PID image and module paths, kept private except selected classifications."""
import ctypes
from ctypes import wintypes as w
import sys

def identity(pid):
 if sys.platform!='win32':raise OSError('windows_required')
 k=ctypes.WinDLL('kernel32',use_last_error=True);p=ctypes.WinDLL('psapi',use_last_error=True)
 k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];k.OpenProcess.restype=w.HANDLE
 k.CloseHandle.argtypes=[w.HANDLE];k.CloseHandle.restype=w.BOOL
 k.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,ctypes.POINTER(w.DWORD)];k.QueryFullProcessImageNameW.restype=w.BOOL
 class FT(ctypes.Structure):_fields_=[('low',w.DWORD),('high',w.DWORD)]
 k.GetProcessTimes.argtypes=[w.HANDLE,*([ctypes.POINTER(FT)]*4)];k.GetProcessTimes.restype=w.BOOL
 p.EnumProcessModulesEx.argtypes=[w.HANDLE,ctypes.c_void_p,w.DWORD,ctypes.POINTER(w.DWORD),w.DWORD];p.EnumProcessModulesEx.restype=w.BOOL
 p.GetModuleFileNameExW.argtypes=[w.HANDLE,ctypes.c_void_p,w.LPWSTR,w.DWORD];p.GetModuleFileNameExW.restype=w.DWORD
 h=k.OpenProcess(0x410,False,pid)
 if not h:raise ctypes.WinError(ctypes.get_last_error())
 try:
  path=ctypes.create_unicode_buffer(32768);size=w.DWORD(len(path))
  if not k.QueryFullProcessImageNameW(h,0,path,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
  creation,exit,kernel,user=FT(),FT(),FT(),FT()
  if not k.GetProcessTimes(h,ctypes.byref(creation),ctypes.byref(exit),ctypes.byref(kernel),ctypes.byref(user)):raise ctypes.WinError(ctypes.get_last_error())
  arr=(ctypes.c_void_p*1024)();needed=w.DWORD()
  modules=[];module_status='ok'
  if not p.EnumProcessModulesEx(h,arr,ctypes.sizeof(arr),ctypes.byref(needed),3):module_status='unavailable'
  elif needed.value>ctypes.sizeof(arr):module_status='limit'
  else:
   for module in arr[:needed.value//ctypes.sizeof(ctypes.c_void_p)]:
    buf=ctypes.create_unicode_buffer(32768)
    if p.GetModuleFileNameExW(h,module,buf,len(buf)):modules.append(buf.value)
  return {'path':path.value,'creation':(creation.high<<32)|creation.low,'modules':modules,'module_status':module_status}
 finally:k.CloseHandle(h)
