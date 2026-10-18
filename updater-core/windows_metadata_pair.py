"""Native Windows, read-only two-metadata-file observation on an explicit root.
No enumeration, shmem, LRU, indices, archive, network, write access or CLI.
All ancestor directory handles are held denying delete; BOTH files stay held
READ-only/share-READ while parsed. This is not active-generation proof, an OS
snapshot, hostile-process protection, or authorization to inspect a live game.
"""
import os,ntpath,re,datetime
from pathlib import Path
from release_core import need
from installed_identity import select_active
from installed_preferences import inspect_preferences

class WindowsMetadataPair:
 def __init__(self,root):
  need(os.name=='nt','metadata_native_windows_required')
  import ctypes,msvcrt
  from ctypes import wintypes as w
  self.ctypes=ctypes;self.msvcrt=msvcrt;self.handles=[];self.streams=[];self.closed=False
  raw=os.fspath(root);need(type(raw)is str and not raw.startswith('\\\\'),'metadata_local_drive_path')
  drive,tail=ntpath.splitdrive(raw);need(re.fullmatch('[A-Za-z]:',drive)and tail.startswith('\\'),'metadata_local_drive_path')
  parts=tail.split('\\')[1:];need(parts and all(p and p not in('.','..')and p[-1]not in' .'and not any(ord(c)<32 or c in ':<>"|?*'for c in p)and not re.fullmatch(r'(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?',p)for p in parts),'metadata_root_components')
  self.root=Path(raw);k=ctypes.WinDLL('kernel32',use_last_error=True);self.k=k
  k.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,w.LPVOID,w.DWORD,w.DWORD,w.HANDLE];k.CreateFileW.restype=w.HANDLE
  k.CloseHandle.argtypes=[w.HANDLE];k.CloseHandle.restype=w.BOOL
  k.GetDriveTypeW.argtypes=[w.LPCWSTR];k.GetDriveTypeW.restype=w.UINT
  k.GetFileType.argtypes=[w.HANDLE];k.GetFileType.restype=w.DWORD
  class Info(ctypes.Structure):
   _fields_=[('attributes',w.DWORD),('creation',w.FILETIME),('access',w.FILETIME),('write',w.FILETIME),('volume',w.DWORD),('size_high',w.DWORD),('size_low',w.DWORD),('links',w.DWORD),('index_high',w.DWORD),('index_low',w.DWORD)]
  self.Info=Info;k.GetFileInformationByHandle.argtypes=[w.HANDLE,ctypes.POINTER(Info)];k.GetFileInformationByHandle.restype=w.BOOL
  try:
   need(k.GetDriveTypeW(drive+'\\')==3,'metadata_fixed_drive_required')
   current=drive+'\\';self._directory(current)
   for part in parts:current=ntpath.join(current,part);self._directory(current)
  except BaseException:self.close();raise
 def _error(self):raise self.ctypes.WinError(self.ctypes.get_last_error())
 def _open(self,path,access,share,flags):
  h=self.k.CreateFileW(str(path),access,share,None,3,flags,None)
  if h==self.ctypes.c_void_p(-1).value:self._error()
  return h
 def _info(self,h):
  i=self.Info()
  if not self.k.GetFileInformationByHandle(h,self.ctypes.byref(i)):self._error()
  need(not i.attributes&(0x400|0x1000|0x40000|0x400000)and self.k.GetFileType(h)==1,'metadata_reparse_offline_recall_or_nondisk');return i
 def _directory(self,path):
  h=self._open(path,0x81,3,0x02000000|0x00200000)
  try:need(self._info(h).attributes&0x10,'metadata_directory_required')
  except BaseException:self.k.CloseHandle(h);raise
  self.handles.append(h)
 def _file(self,path,cap):
  h=self._open(path,0x80000000,1,0x00200000)
  try:
   i=self._info(h);n=(i.size_high<<32)|i.size_low;need(not i.attributes&0x10 and i.links==1,'metadata_regular_single_link_file');need(0<n<=cap,'metadata_file_budget')
   fd=self.msvcrt.open_osfhandle(h,os.O_RDONLY|os.O_BINARY);h=None
   try:f=os.fdopen(fd,'rb')
   except BaseException:os.close(fd);raise
   self.streams.append((f,n));return f,n
  finally:
   if h is not None:self.k.CloseHandle(h)
 @staticmethod
 def _read(f,n):
  f.seek(0);raw=f.read(n+1);need(len(raw)==n,'metadata_file_changed');return raw
 def observe(self):
  need(not self.closed and not self.streams,'metadata_pair_single_use')
  started=datetime.datetime.now(datetime.timezone.utc).isoformat()
  try:
   f,n=self._file(self.root/'.build.info',1048576);info=self._read(f,n);row=select_active(info);key=row['buildkey']
   current=self.root
   for part in ('Data','config',key[:2],key[2:4]):current=current/part;self._directory(current)
   g,m=self._file(current/key,4194304);config=self._read(g,m)
   facts=inspect_preferences(info,config)
   need(self._read(f,n)==info and self._read(g,m)==config,'metadata_pair_changed')
   facts.update(source='native_windows_explicit_root_metadata_pair',metadata_pair_write_delete_denied_while_held=True,metadata_pair_observed_at_utc=started,metadata_pair_rechecked_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),files_opened=2,maximum_distinct_content_bytes=5242880,maximum_content_bytes_read=10485760,actual_content_bytes_read=2*(n+m),observed_content_bytes=n+m,ancestors_held_deny_delete=True,game_access=None,root_kind_not_inferred=True,shmem_bytes_read=0,lru_bytes_read=0,index_bytes_read=0,archive_bytes_read=0,directory_enumerations=0,write_access_requested=False,consistency_model='held native read handles deny ordinary write/delete; no OS snapshot or hostile-process guarantee')
   return facts
  except BaseException:self.close();raise
 def close(self):
  if not getattr(self,'closed',True):
   for f,n in reversed(self.streams):f.close()
   for h in reversed(self.handles):self.k.CloseHandle(h)
   self.streams=[];self.handles=[];self.closed=True
 def __enter__(self):return self
 def __exit__(self,*_):self.close()
 def __del__(self):self.close()
