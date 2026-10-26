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
   inside=W.BOOL()
   if not K.IsProcessInJob(p,self.h,C.byref(inside)):raise RuntimeError('job_membership_failed')
   if not inside.value and not K.AssignProcessToJobObject(self.h,p):raise RuntimeError('job_assign_failed')
  finally:K.CloseHandle(p)
 def close(self):
  if self.h:
   ok=K.TerminateJobObject(self.h,17);K.CloseHandle(self.h);self.h=None
   if not ok:raise RuntimeError('job_terminate_failed')

K.GetProcessTimes.argtypes=[W.HANDLE,C.POINTER(W.FILETIME),C.POINTER(W.FILETIME),C.POINTER(W.FILETIME),C.POINTER(W.FILETIME)]
K.GetProcessTimes.restype=W.BOOL
def creation_time(pid):
 p=K.OpenProcess(0x1000,False,pid)
 if not p:raise RuntimeError('process_identity_open_failed')
 try:
  created=W.FILETIME();other=[W.FILETIME() for _ in range(3)]
  if not K.GetProcessTimes(p,C.byref(created),*[C.byref(x) for x in other]):raise RuntimeError('process_identity_time_failed')
  return (created.dwHighDateTime<<32)|created.dwLowDateTime
 finally:K.CloseHandle(p)

K.IsProcessInJob.argtypes=[W.HANDLE,W.HANDLE,C.POINTER(W.BOOL)];K.IsProcessInJob.restype=W.BOOL
K.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)];K.QueryFullProcessImageNameW.restype=W.BOOL
def guarded_process(row):
 import os,hashlib
 p=K.OpenProcess(0x1000|0x100|0x1,False,row['pid'])
 if not p:raise RuntimeError('late_process_open_failed')
 try:
  image=C.create_unicode_buffer(32768);n=W.DWORD(len(image))
  if not K.QueryFullProcessImageNameW(p,0,image,C.byref(n)):raise RuntimeError('late_process_image_failed')
  if os.path.normcase(image.value)!=os.path.normcase(row['image_path']):raise RuntimeError('late_process_path_changed')
  with open(image.value,'rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
  if digest!=row['sha256']:raise RuntimeError('late_process_hash_changed')
  return p,creation_time(row['pid'])
 except Exception:
  K.CloseHandle(p);raise
