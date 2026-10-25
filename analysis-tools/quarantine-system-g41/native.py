import ctypes as C
from ctypes import wintypes as W
import os,time
import peer_guard as peer
K=peer.K
K.CreateJobObjectW.argtypes=[C.c_void_p,W.LPCWSTR];K.CreateJobObjectW.restype=W.HANDLE
K.AssignProcessToJobObject.argtypes=[W.HANDLE,W.HANDLE];K.AssignProcessToJobObject.restype=W.BOOL
K.SetInformationJobObject.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD];K.SetInformationJobObject.restype=W.BOOL
class Limit(C.Structure):_fields_=[('a',C.c_int64),('b',C.c_int64),('flags',W.DWORD),('min',C.c_size_t),('max',C.c_size_t),('active',W.DWORD),('affinity',C.c_size_t),('priority',W.DWORD),('scheduling',W.DWORD)]
class IO(C.Structure):_fields_=[(x,C.c_uint64) for x in 'abcdef']
class Extended(C.Structure):_fields_=[('basic',Limit),('io',IO),('a',C.c_size_t),('b',C.c_size_t),('c',C.c_size_t),('d',C.c_size_t)]

def identity():
 h=K.OpenProcess(0x1000|0x100000,False,os.getpid())
 if not h:raise RuntimeError('controller_open_failed')
 try:
  created=W.FILETIME();other=[W.FILETIME() for _ in range(3)]
  if not K.GetProcessTimes(h,C.byref(created),*[C.byref(v) for v in other]):raise RuntimeError('controller_time_failed')
  image=C.create_unicode_buffer(32768);length=W.DWORD(len(image))
  if not K.QueryFullProcessImageNameW(h,0,image,C.byref(length)):raise RuntimeError('controller_image_failed')
  return {'pid':os.getpid(),'created':(created.dwHighDateTime<<32)|created.dwLowDateTime,'image':image.value}
 finally:K.CloseHandle(h)

K.OpenJobObjectW.argtypes=[W.DWORD,W.BOOL,W.LPCWSTR];K.OpenJobObjectW.restype=W.HANDLE
K.TerminateJobObject.argtypes=[W.HANDLE,W.UINT];K.TerminateJobObject.restype=W.BOOL
K.QueryInformationJobObject.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD,C.c_void_p];K.QueryInformationJobObject.restype=W.BOOL
class Accounting(C.Structure):
 _fields_=[('a',C.c_int64),('b',C.c_int64),('c',C.c_int64),('d',C.c_int64),('faults',W.DWORD),('total',W.DWORD),('active',W.DWORD),('terminated',W.DWORD)]
def create_job(name):
 handle=K.CreateJobObjectW(None,name)
 if not handle:raise RuntimeError('job_create_failed')
 limits=Extended();limits.basic.flags=0x2000
 if not K.SetInformationJobObject(handle,9,C.byref(limits),C.sizeof(limits)):
  K.CloseHandle(handle);raise RuntimeError('job_limits_failed')
 return handle
def assign(job,child):
 if not K.AssignProcessToJobObject(job,W.HANDLE(int(child._handle))):raise RuntimeError('job_assign_failed')
def active(job):
 info=Accounting()
 if not K.QueryInformationJobObject(job,1,C.byref(info),C.sizeof(info),None):raise RuntimeError('job_query_failed')
 return info.active
def end_job(job):
 if not K.TerminateJobObject(job,17):raise RuntimeError('job_terminate_failed')
 deadline=time.monotonic()+15
 while active(job) and time.monotonic()<deadline:time.sleep(.05)
 if active(job)!=0:raise RuntimeError('job_still_active')
 return True
