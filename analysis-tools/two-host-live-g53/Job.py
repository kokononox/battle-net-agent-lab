import ctypes as C
from ctypes import wintypes as W
K=C.WinDLL('kernel32',use_last_error=True)
K.CreateJobObjectW.argtypes=[C.c_void_p,W.LPCWSTR];K.CreateJobObjectW.restype=W.HANDLE
K.SetInformationJobObject.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD];K.SetInformationJobObject.restype=W.BOOL
K.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];K.OpenProcess.restype=W.HANDLE
K.AssignProcessToJobObject.argtypes=[W.HANDLE,W.HANDLE];K.AssignProcessToJobObject.restype=W.BOOL
K.TerminateJobObject.argtypes=[W.HANDLE,W.UINT];K.TerminateJobObject.restype=W.BOOL
K.CloseHandle.argtypes=[W.HANDLE]
class Limit(C.Structure):_fields_=[('a',C.c_int64),('b',C.c_int64),('flags',W.DWORD),('min',C.c_size_t),('max',C.c_size_t),('active',W.DWORD),('affinity',C.c_size_t),('priority',W.DWORD),('scheduling',W.DWORD)]
class Extended(C.Structure):_fields_=[('basic',Limit),('io',C.c_uint64*6),('a',C.c_size_t),('b',C.c_size_t),('c',C.c_size_t),('d',C.c_size_t)]
class Job:
 def __init__(self):
  self.h=K.CreateJobObjectW(None,None)
  if not self.h:raise RuntimeError('job_create_failed')
  l=Extended();l.basic.flags=0x2000
  if not K.SetInformationJobObject(self.h,9,C.byref(l),C.sizeof(l)):raise RuntimeError('job_config_failed')
 def assign(self,pid):
  p=K.OpenProcess(0x100|0x1|0x1000,False,pid)
  if not p:raise RuntimeError('job_open_failed')
  try:
   if not K.AssignProcessToJobObject(self.h,p):raise RuntimeError('job_assign_failed')
  finally:K.CloseHandle(p)
 def close(self):
  if self.h:
   ok=K.TerminateJobObject(self.h,17);K.CloseHandle(self.h);self.h=None
   if not ok:raise RuntimeError('job_terminate_failed')
