"""Explicit, locked, fixed-path hosts edits. No DNS flush, audit changes or firewall writes."""
import contextlib,hashlib,ipaddress,json,os,re,stat,time,uuid
from pathlib import Path
import hosts_view as view


def standard_path():
 if not view.IS_WINDOWS:raise ValueError('hosts_edit_requires_Windows')
 root=os.environ.get('SystemRoot')
 if not root:raise ValueError('hosts_windows_root_unavailable')
 path=Path(root)/'System32/drivers/etc/hosts'
 for part in (path,*path.parents):
  if part.is_symlink() or (hasattr(part,'is_junction') and part.is_junction()):raise ValueError('hosts_reparse_path_refused')
 return path

@contextlib.contextmanager
def locked_file(path):
 # Keep the existing file object/security descriptor. Windows share-mode 0 denies concurrent opens.
 if os.name=='nt':
  import ctypes,msvcrt
  from ctypes import wintypes
  k=ctypes.WinDLL('kernel32',use_last_error=True)
  k.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE];k.CreateFileW.restype=wintypes.HANDLE
  k.CloseHandle.argtypes=[wintypes.HANDLE];k.CloseHandle.restype=wintypes.BOOL
  handle=k.CreateFileW(str(path),0xC0000000,0,None,3,0x00200000,None) # OPEN_REPARSE_POINT
  if handle==ctypes.c_void_p(-1).value:raise OSError(ctypes.get_last_error(),'hosts_exclusive_open_failed')
  try:
   class Info(ctypes.Structure):_fields_=[('attributes',wintypes.DWORD),('creation',wintypes.FILETIME),('access',wintypes.FILETIME),('write',wintypes.FILETIME),('volume',wintypes.DWORD),('sizehigh',wintypes.DWORD),('sizelow',wintypes.DWORD),('links',wintypes.DWORD),('indexhigh',wintypes.DWORD),('indexlow',wintypes.DWORD)]
   k.GetFileInformationByHandle.argtypes=[wintypes.HANDLE,ctypes.POINTER(Info)];k.GetFileInformationByHandle.restype=wintypes.BOOL
   info=Info()
   if not k.GetFileInformationByHandle(handle,ctypes.byref(info)) or info.attributes & 0x400 or info.links!=1:raise ValueError('hosts_reparse_or_hardlink_refused')
   fd=msvcrt.open_osfhandle(handle,os.O_RDWR|os.O_BINARY);handle=None
  finally:
   if handle is not None:k.CloseHandle(handle)
 else:
  import fcntl
  fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW)
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except Exception:os.close(fd);raise
 with os.fdopen(fd,'r+b') as f:
  info=os.fstat(f.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('hosts_not_regular_single_link_file')
  yield f

def decode(data):
 if data.startswith(b'\xff\xfe'):return data[2:].decode('utf-16-le'),'utf-16-le',b'\xff\xfe'
 if data.startswith(b'\xfe\xff'):return data[2:].decode('utf-16-be'),'utf-16-be',b'\xfe\xff'
 if data.startswith(b'\xef\xbb\xbf'):return data[3:].decode('utf-8'),'utf-8',b'\xef\xbb\xbf'
 try:return data.decode('utf-8'),'utf-8',b''
 except UnicodeError:return data.decode('cp1252'),'cp1252',b''

def prepare(data,changes):
 if not isinstance(changes,list) or not changes or len(changes)>500:raise ValueError('hosts_select_1_to_500_changes')
 cleaned={}
 for change in changes:
  if not isinstance(change,dict):raise ValueError('invalid_hosts_change')
  domain=change.get('domain');name=view.domain_name(domain) if isinstance(domain,str) else None
  if not name or name in view.SYSTEM_NAMES:raise ValueError('hosts_invalid_or_protected_domain')
  if name in cleaned:raise ValueError('hosts_duplicate_change')
  if change.get('action')=='remove':addresses=[]
  elif change.get('action')=='upsert':
   addresses=change.get('addresses')
   if not isinstance(addresses,list) or not 1<=len(addresses)<=16 or any(not isinstance(x,str) for x in addresses):raise ValueError('hosts_invalid_addresses')
   addresses=list(dict.fromkeys(str(ipaddress.ip_address(x)) for x in addresses if isinstance(x,str)))
   if not addresses:raise ValueError('hosts_invalid_addresses')
  else:raise ValueError('hosts_invalid_change_action')
  cleaned[name]=addresses
 text,encoding,bom=decode(data);lines=[];newline='\r\n' if '\r\n' in text else '\n'
 for raw in text.splitlines(keepends=True):
  body=raw.rstrip('\r\n');end=raw[len(body):];active,mark,comment=body.partition('#');tokens=list(re.finditer(r'\S+',active))
  if len(tokens)>=2:
   try:ipaddress.ip_address(tokens[0].group())
   except ValueError:lines.append(raw);continue
   remove=[m for m in tokens[1:] if view.domain_name(m.group()) in cleaned]
   if remove:
    # Remove only targeted aliases. Retain every unrelated alias, address and comment.
    if len(remove)==len(tokens)-1:raw=(active[:len(active)-len(active.lstrip())]+mark+comment+end) if mark else end
    else:
     for m in reversed(remove):active=active[:m.start()]+active[m.end():]
     raw=active+mark+comment+end
  lines.append(raw)
 out=''.join(lines)
 additions=[address+'\t'+domain+newline for domain,addresses in cleaned.items() for address in addresses]
 if additions:
  if out and not out.endswith(('\r','\n')):out+=newline
  out+=''.join(additions)
 result=bom+out.encode(encoding)
 if len(result)>view.MAX_BYTES:raise ValueError('hosts_file_too_large')
 parsed=view.parse_hosts(result)
 # Editing a truncated view is rejected by apply; raw parser only used for validation.
 for name,addresses in cleaned.items():
  actual=next((r['addresses'] for r in parsed['entries'] if r['domain']==name),[])
  if set(actual)!=set(addresses):raise ValueError('hosts_edit_validation_failed')
 return result,cleaned

def apply_hosts(private,payload):
 if payload.get('hosts_edit_consent') is not True:raise ValueError('explicit_system_wide_hosts_consent_required')
 expected=payload.get('expected_sha256')
 if not isinstance(expected,str) or not re.fullmatch('[a-f0-9]{64}',expected):raise ValueError('hosts_read_before_edit')
 path=standard_path();backup_dir=Path(private)/'hosts-backups'
 with locked_file(path) as f:
  before=f.read(view.MAX_BYTES+1)
  if len(before)>view.MAX_BYTES:raise ValueError('hosts_file_too_large')
  if hashlib.sha256(before).hexdigest()!=expected:raise ValueError('hosts_changed_externally_read_again')
  if view.parse_hosts(before)['truncated']:raise ValueError('hosts_truncated_view_edit_refused')
  after,changes=prepare(before,payload.get('changes'))
  if after==before:return dict(changed=False,backup_created=False,system_wide=True)
  backup_dir.mkdir(exist_ok=True);ident=uuid.uuid4().hex;backup=backup_dir/(ident+'.hosts.bak')
  with backup.open('xb') as b:b.write(before);b.flush();os.fsync(b.fileno())
  if backup.read_bytes()!=before:raise ValueError('hosts_backup_verification_failed_no_changes')
  # Existing handle preserves ACL/owner; rollback only while the same exclusive lock is held.
  try:
   f.seek(0);f.write(after);f.truncate();f.flush();os.fsync(f.fileno());f.seek(0)
   if f.read(view.MAX_BYTES+1)!=after:raise OSError('hosts_write_verification_failed')
  except Exception as e:
   try:f.seek(0);f.write(before);f.truncate();f.flush();os.fsync(f.fileno())
   except Exception:raise ValueError('hosts_write_and_rollback_failed_restore_local_backup') from e
   raise ValueError('hosts_write_failed_original_restored') from e
 return dict(changed=True,changed_domains=len(changes),backup_created=True,backup_filename=backup.name,before_sha256=expected,after_sha256=hashlib.sha256(after).hexdigest(),system_wide=True,dns_cache_flushed=False,blocking_verified=False)
