"""Windows loopback TCP owner admission. Not a WFP filter or socket-duplication proof."""
import ctypes as C
from ctypes import wintypes as W
import ipaddress,json,os,socket,struct,time
from pathlib import Path
if os.name!='nt':raise RuntimeError('windows_required')
K=C.WinDLL('kernel32',use_last_error=True);I=C.WinDLL('iphlpapi',use_last_error=True)
K.OpenJobObjectW.argtypes=[W.DWORD,W.BOOL,W.LPCWSTR];K.OpenJobObjectW.restype=W.HANDLE
K.IsProcessInJob.argtypes=[W.HANDLE,W.HANDLE,C.POINTER(W.BOOL)];K.IsProcessInJob.restype=W.BOOL
K.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];K.OpenProcess.restype=W.HANDLE
K.CloseHandle.argtypes=[W.HANDLE];K.CloseHandle.restype=W.BOOL
K.GetProcessTimes.argtypes=[W.HANDLE,C.POINTER(W.FILETIME),C.POINTER(W.FILETIME),C.POINTER(W.FILETIME),C.POINTER(W.FILETIME)];K.GetProcessTimes.restype=W.BOOL
K.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)];K.QueryFullProcessImageNameW.restype=W.BOOL
K.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];K.WaitForSingleObject.restype=W.DWORD
K.GetFileAttributesW.argtypes=[W.LPCWSTR];K.GetFileAttributesW.restype=W.DWORD
I.GetExtendedTcpTable.argtypes=[C.c_void_p,C.POINTER(W.DWORD),W.BOOL,W.ULONG,C.c_int,W.ULONG];I.GetExtendedTcpTable.restype=W.DWORD

def fail(reason):raise ValueError(reason)
def norm(path):return os.path.normcase(os.path.abspath(path))
def verify_controller(row):
 if type(row)!=dict or set(row)!={'pid','created','image'} or type(row['pid'])!=int or not 0<row['pid']<=0xffffffff or type(row['created'])!=int or type(row['image'])!=str or not os.path.isabs(row['image']):fail('peer_policy_invalid')
 h=K.OpenProcess(0x1000|0x100000,False,row['pid'])
 if not h:fail('peer_controller_exited')
 try:
  if K.WaitForSingleObject(h,0)!=258:fail('peer_controller_exited')
  created=W.FILETIME();other=[W.FILETIME() for _ in range(3)]
  if not K.GetProcessTimes(h,C.byref(created),*[C.byref(v) for v in other]):fail('peer_controller_identity_changed')
  image=C.create_unicode_buffer(32768);length=W.DWORD(len(image))
  if not K.QueryFullProcessImageNameW(h,0,image,C.byref(length)):fail('peer_controller_identity_changed')
  if ((created.dwHighDateTime<<32)|created.dwLowDateTime)!=row['created'] or norm(image.value)!=norm(row['image']):fail('peer_controller_identity_changed')
 finally:K.CloseHandle(h)

def policy(path):
 p=Path(path);root=Path(os.environ['ProgramData'])/'BNetOnlineG33'
 try:relative=p.relative_to(root)
 except ValueError:fail('peer_policy_scope')
 if len(relative.parts)!=2 or len(relative.parts[0])!=32 or any(c not in '0123456789abcdef' for c in relative.parts[0]) or relative.parts[1]!='peers.json':fail('peer_policy_scope')
 for item in (root,p.parent,p):
  attr=K.GetFileAttributesW(str(item))
  if attr==0xffffffff or attr&0x400:fail('peer_policy_reparse_or_missing')
 raw=p.read_bytes()
 if len(raw)>4096:fail('peer_policy_limit')
 try:v=json.loads(raw.decode('utf-8-sig'))
 except Exception:fail('peer_policy_invalid')
 if type(v)!=dict or set(v)!={'expires_unix','job_name','controller'} or type(v['expires_unix']) not in (int,float) or not time.time()<v['expires_unix']<=time.time()+600:fail('peer_policy_expired_or_invalid')
 if v['job_name']!='Global\\BNetOnlineG33_'+relative.parts[0]:fail('peer_job_scope')
 lease_path=p.parent/'lease.json';attr=K.GetFileAttributesW(str(lease_path))
 if attr==0xffffffff or attr&0x400:fail('peer_lease_closed')
 data=lease_path.read_bytes()
 if len(data)>4096:fail('peer_lease_closed')
 try:lease=json.loads(data.decode('utf-8-sig'))
 except Exception:fail('peer_lease_closed')
 if type(lease)!=dict or lease.get('phase')!='active':fail('peer_lease_closed')
 verify_controller(v['controller']);return v

def owner(sock):
 local=sock.getsockname();remote=sock.getpeername();version=ipaddress.ip_address(local[0]).version
 if not ipaddress.ip_address(local[0]).is_loopback or not ipaddress.ip_address(remote[0]).is_loopback:fail('peer_not_loopback')
 family=2 if version==4 else 23;size=W.DWORD(0)
 result=I.GetExtendedTcpTable(None,C.byref(size),False,family,5,0)
 if result!=122:fail('peer_table_unavailable')
 for _ in range(3):
  if not 4<=size.value<=4194304:fail('peer_table_limit')
  buf=C.create_string_buffer(size.value);result=I.GetExtendedTcpTable(buf,C.byref(size),False,family,5,0)
  if result==122:continue
  if result:fail('peer_table_unavailable')
  data=buf.raw[:size.value];break
 else:fail('peer_table_changing')
 if len(data)<4:fail('peer_table_invalid')
 count=struct.unpack_from('<I',data)[0];stride=24 if version==4 else 56
 if count>65536 or 4+count*stride>len(data):fail('peer_table_invalid')
 found=[]
 for offset in range(4,4+count*stride,stride):
  if version==4:
   state,la,lp,ra,rp,pid=struct.unpack_from('<6I',data,offset)
   la=socket.inet_ntop(socket.AF_INET,struct.pack('<I',la));ra=socket.inet_ntop(socket.AF_INET,struct.pack('<I',ra))
  else:
   la,ls,lp,ra,rs,rp,state,pid=struct.unpack_from('<16sII16sIIII',data,offset)
   la=socket.inet_ntop(socket.AF_INET6,la);ra=socket.inet_ntop(socket.AF_INET6,ra)
   if ls!=remote[3] or rs!=local[3]:continue
  if state==5 and ipaddress.ip_address(la)==ipaddress.ip_address(remote[0]) and socket.ntohs(lp&0xffff)==remote[1] and ipaddress.ip_address(ra)==ipaddress.ip_address(local[0]) and socket.ntohs(rp&0xffff)==local[1]:found.append(pid)
 if not found:fail('peer_owner_missing')
 if len(found)>1:fail('peer_owner_multiple')
 if found[0]<=0:fail('peer_owner_invalid')
 return found[0]

class Admission:
 def __init__(self,sock,path):
  self.sock=sock;self.path=path;self.handle=None
  try:
   self.pid=owner(sock);self.handle=K.OpenProcess(0x1000|0x100000,False,self.pid)
   if not self.handle:fail('peer_process_unavailable')
   created=W.FILETIME();other=[W.FILETIME() for _ in range(3)]
   if not K.GetProcessTimes(self.handle,C.byref(created),*[C.byref(v) for v in other]):fail('peer_identity_unavailable')
   self.created=(created.dwHighDateTime<<32)|created.dwLowDateTime
   image=C.create_unicode_buffer(32768);length=W.DWORD(len(image))
   if not K.QueryFullProcessImageNameW(self.handle,0,image,C.byref(length)):fail('peer_image_unavailable')
   self.image=norm(image.value);self.revalidate()
  except Exception:self.close();raise
 def revalidate(self):
  if not self.handle or K.WaitForSingleObject(self.handle,0)!=258:fail('peer_process_exited')
  if owner(self.sock)!=self.pid:fail('peer_owner_changed')
  cfg=policy(self.path);job=K.OpenJobObjectW(4,False,cfg['job_name'])
  if not job:fail('peer_job_unavailable')
  try:
   member=W.BOOL(False)
   if not K.IsProcessInJob(self.handle,job,C.byref(member)) or not member.value:fail('peer_not_in_owned_job')
  finally:K.CloseHandle(job)
 def close(self):
  if self.handle:K.CloseHandle(self.handle);self.handle=None

def admit(sock,path):return Admission(sock,path)
