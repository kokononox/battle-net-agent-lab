"""Native Windows I/O for NEW owned scratch stages, never game directories.
Fixed local drive only. Reject reparse/offline/recall paths and hardlinked files.
Hold ancestor directory handles denying delete; readers deny write/delete.
No admin/ACL changes, scan, network or automatic lock removal. Not hostile-process
protection or power-loss qualification. File flush and write-through rename are
OS requests, not a claim about disk hardware durability.
"""
import os,ntpath,re
from pathlib import Path
from release_core import need

class WindowsStore:
 def __init__(self,path,*,create=False):
  need(os.name=='nt','native_windows_required')
  import ctypes,msvcrt
  from ctypes import wintypes as w
  self.ctypes=ctypes;self.msvcrt=msvcrt;self.handles=[];self.closed=False;self.path=Path(path);raw=os.fspath(self.path)
  need(type(raw)is str and not raw.startswith('\\\\')and ntpath.isabs(raw),'windows_owned_absolute_local_path')
  drive,tail=ntpath.splitdrive(raw);need(len(drive)==2 and drive[0].isalpha()and drive[1]==':'and tail.startswith('\\'),'windows_drive_path')
  components=tail.split('\\')[1:];need(all(p and p not in('.','..')and p[-1]not in' .'and not any(ord(c)<32 or c in ':<>"|?*'for c in p)for p in components),'windows_directory_component')
  self.kernel=ctypes.WinDLL('kernel32',use_last_error=True);k=self.kernel
  k.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,w.LPVOID,w.DWORD,w.DWORD,w.HANDLE];k.CreateFileW.restype=w.HANDLE
  k.CloseHandle.argtypes=[w.HANDLE];k.CloseHandle.restype=w.BOOL
  k.GetDriveTypeW.argtypes=[w.LPCWSTR];k.GetDriveTypeW.restype=w.UINT
  k.GetFileType.argtypes=[w.HANDLE];k.GetFileType.restype=w.DWORD
  k.FlushFileBuffers.argtypes=[w.HANDLE];k.FlushFileBuffers.restype=w.BOOL
  k.MoveFileExW.argtypes=[w.LPCWSTR,w.LPCWSTR,w.DWORD];k.MoveFileExW.restype=w.BOOL
  class FileInfo(ctypes.Structure):
   _fields_=[('attributes',w.DWORD),('creation',w.FILETIME),('access',w.FILETIME),('write',w.FILETIME),('volume',w.DWORD),('size_high',w.DWORD),('size_low',w.DWORD),('links',w.DWORD),('index_high',w.DWORD),('index_low',w.DWORD)]
  self.FileInfo=FileInfo;k.GetFileInformationByHandle.argtypes=[w.HANDLE,ctypes.POINTER(FileInfo)];k.GetFileInformationByHandle.restype=w.BOOL
  need(k.GetDriveTypeW(drive+'\\')==3,'windows_fixed_local_drive_required');self.root_handle=None
  try:
   current=drive+'\\';self._hold_directory(current)
   for part in components[:-1]:current=ntpath.join(current,part);self._hold_directory(current)
   if create:self.path.mkdir(exist_ok=False)
   self.root_handle=self._hold_directory(str(self.path));self.root_id=self._identity(self._info(self.root_handle))
  except BaseException:self.close();raise
 def _error(self):raise self.ctypes.WinError(self.ctypes.get_last_error())
 def _handle(self,path,access,share,disposition,flags):
  h=self.kernel.CreateFileW(str(path),access,share,None,disposition,flags,None)
  if h==self.ctypes.c_void_p(-1).value:self._error()
  return h
 def _info(self,h):
  i=self.FileInfo()
  if not self.kernel.GetFileInformationByHandle(h,self.ctypes.byref(i)):self._error()
  need(not i.attributes&(0x400|0x1000|0x40000|0x400000),'windows_reparse_offline_or_recall');need(self.kernel.GetFileType(h)==1,'windows_disk_handle_required');return i
 @staticmethod
 def _identity(i):return(i.volume,i.index_high,i.index_low)
 def _hold_directory(self,path):
  # FILE_READ_ATTRIBUTES alone does not participate in all share checks.
  # FILE_LIST_DIRECTORY requests data access without enumerating anything.
  h=self._handle(path,0x81,3,3,0x02000000|0x00200000)
  try:need(self._info(h).attributes&0x10,'windows_directory_required')
  except BaseException:self.kernel.CloseHandle(h);raise
  self.handles.append(h);return h
 def check(self):
  need(not self.closed and self.root_handle is not None,'windows_store_closed');need(self._identity(self._info(self.root_handle))==self.root_id,'windows_root_handle_identity')
 @staticmethod
 def _name(name):
  need(type(name)is str and re.fullmatch('[a-z0-9-]{1,64}\\.(?:seg|tmp|json|lock|bin)',name)is not None,'windows_owned_child_name');stem=name.split('.')[0].upper();need(re.fullmatch('CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]',stem)is None,'windows_reserved_child');return name
 def _child(self,name):self.check();return self.path/self._name(name)
 def open_read(self,name,*,size=None,cap=None):
  p=self._child(name);h=self._handle(p,0x80000000,1,3,0x00200000)
  try:
   i=self._info(h);n=(i.size_high<<32)|i.size_low;need(not i.attributes&0x10 and i.links==1,'windows_regular_single_link_file');need((size is None or n==size)and(cap is None or n<=cap),'windows_file_size_budget');fd=self.msvcrt.open_osfhandle(h,os.O_RDONLY|os.O_BINARY);h=None
   return os.fdopen(fd,'rb'),n
  finally:
   if h is not None:self.kernel.CloseHandle(h)
 def read(self,name,cap):
  f,n=self.open_read(name,cap=cap)
  with f:raw=f.read(cap+1);need(len(raw)==n,'windows_owned_file_changed');return raw
 def create_handle(self,name):
  p=self._child(name);h=self._handle(p,0x40000000,0,1,0x00200000|0x80)
  try:
   i=self._info(h);need(not i.attributes&0x10 and i.links==1,'windows_new_regular_file');fd=self.msvcrt.open_osfhandle(h,os.O_WRONLY|os.O_BINARY);h=None;return fd
  finally:
   if h is not None:self.kernel.CloseHandle(h)
 def write_new(self,name,raw):
  need(type(raw)is bytes and len(raw)<=1024**2,'windows_stage_write_budget');fd=self.create_handle(name)
  with os.fdopen(fd,'wb')as f:
   f.write(raw);f.flush()
   if not self.kernel.FlushFileBuffers(self.msvcrt.get_osfhandle(f.fileno())):self._error()
 def replace(self,source,dest):
  a,b=self._child(source),self._child(dest)
  # Both are fixed, owned child names. No cross-volume copy fallback.
  if not self.kernel.MoveFileExW(str(a),str(b),1|8):self._error()
 def remove_lock(self):self._child('writer.lock').unlink()
 def close(self):
  if not getattr(self,'closed',True):
   for h in reversed(self.handles):self.kernel.CloseHandle(h)
   self.handles=[];self.closed=True;self.root_handle=None
 def __del__(self):self.close()
