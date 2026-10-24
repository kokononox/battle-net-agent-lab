"""Explicit hosts-only default reset/backup restore. Never invokes firewall, audit or VPN APIs."""
import ctypes,hashlib,json,os,re,stat,subprocess,uuid
from pathlib import Path
from datetime import datetime,timezone
from state import assert_local_tree,locked,atomic_json
import hosts_edit as edit
import hosts_view as view
RESET_CONFIRM='RESET WINDOWS HOSTS'
RESTORE_CONFIRM='RESTORE HOSTS BACKUP'
DEFAULT_HOSTS=(
 '# Copyright (c) 1993-2009 Microsoft Corp.\r\n'
 '#\r\n'
 '# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n'
 '#\r\n'
 '# This file contains the mappings of IP addresses to host names. Each\r\n'
 '# entry should be kept on an individual line. The IP address should\r\n'
 '# be placed in the first column followed by the corresponding host name.\r\n'
 '# The IP address and the host name should be separated by at least one\r\n'
 '# space.\r\n'
 '#\r\n'
 '# Additionally, comments (such as these) may be inserted on individual\r\n'
 '# lines or following the machine name denoted by a \"#\" symbol.\r\n'
 '#\r\n'
 '# For example:\r\n'
 '#\r\n'
 '#      102.54.94.97     rhino.acme.com          # source server\r\n'
 '#       38.25.63.10     x.acme.com              # x client host\r\n'
 '#\r\n'
 '# localhost name resolution is handled within DNS itself.\r\n'
 '#    127.0.0.1       localhost\r\n'
 '#    ::1             localhost\r\n'
).encode('ascii')
def sha(data):return hashlib.sha256(data).hexdigest()
def utc():return datetime.now(timezone.utc).isoformat()
def windows_directory():
 if os.name!='nt':raise ValueError('hosts_reset_requires_Windows')
 k=ctypes.WinDLL('kernel32',use_last_error=True)
 k.GetWindowsDirectoryW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint];k.GetWindowsDirectoryW.restype=ctypes.c_uint
 b=ctypes.create_unicode_buffer(32768);n=k.GetWindowsDirectoryW(b,len(b))
 if not 0<n<len(b):raise ValueError('hosts_windows_directory_unavailable')
 p=Path(b.value)
 if not p.is_absolute() or str(p).startswith('\\\\'):raise ValueError('hosts_local_windows_directory_required')
 return assert_local_tree(p)
def fixed_hosts():return assert_local_tree(windows_directory()/'System32/drivers/etc/hosts')
def require_admin():
 if os.name!='nt' or not ctypes.windll.shell32.IsUserAnAdmin():raise ValueError('hosts_explicit_Run_as_administrator_required')
def machine_id():
 import winreg
 with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Cryptography',0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY) as k:
  return str(winreg.QueryValueEx(k,'MachineGuid')[0])
def backup_root(store):return assert_local_tree(store.root/'hosts-reset-backups')
def read_bytes(path,limit=view.MAX_BYTES):
 path=assert_local_tree(path);info=path.stat()
 if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>limit:raise ValueError('hosts_backup_regular_single_link_bounded_required')
 with path.open('rb') as f:data=f.read(limit+1)
 if len(data)>limit:raise ValueError('hosts_file_too_large')
 return data
def read_current():
 # Read-only snapshot. Apply re-reads through an exclusive existing-file handle.
 return read_bytes(fixed_hosts())
def get_backup(store,ident):
 if not isinstance(ident,str) or not re.fullmatch('[a-f0-9]{32}',ident):raise ValueError('hosts_backup_id_invalid')
 root=backup_root(store);meta=json.loads(read_bytes(root/(ident+'.json'),16384))
 if meta.get('schema')!='unified-hosts-reset-backup-1' or meta.get('id')!=ident or meta.get('machine_id')!=machine_id():raise ValueError('hosts_backup_wrong_schema_or_computer')
 if meta.get('operation') not in ('reset','restore') or not isinstance(meta.get('created_utc'),str):raise ValueError('hosts_backup_metadata_invalid')
 data=read_bytes(root/(ident+'.hosts.bak'))
 if meta.get('sha256')!=sha(data) or meta.get('bytes')!=len(data):raise ValueError('hosts_backup_hash_mismatch')
 return data,meta
def list_backups(store):
 root=backup_root(store)
 if not root.exists():return []
 rows=[]
 # Show at most 20 verified backups, not arbitrary user-supplied paths.
 for p in sorted(root.glob('*.json'),key=lambda x:x.name,reverse=True):
  try:
   data,meta=get_backup(store,p.stem)
   rows.append(dict(id=meta['id'],created_utc=meta['created_utc'],operation=meta['operation'],bytes=len(data),sha256=sha(data)))
  except (ValueError,OSError,KeyError,TypeError):continue
 rows.sort(key=lambda x:x['created_utc'],reverse=True)
 return rows[:20]
def make_plan(store,data,operation,backup_id=None):
 if operation=='reset':target=DEFAULT_HOSTS
 elif operation=='restore':target,_=get_backup(store,backup_id)
 else:raise ValueError('hosts_reset_operation_invalid')
 view.parse_hosts(target) # Validate displayability before any mutation; restore keeps exact bytes.
 parsed=view.parse_hosts(data)
 body=dict(schema='unified-hosts-reset-plan-1',operation=operation,backup_id=backup_id,expected_sha256=sha(data),after_sha256=sha(target),before_bytes=len(data),after_bytes=len(target),visible_domain_count=len(parsed['entries']),entries_truncated=parsed['truncated'],changes_required=data!=target,system_wide=True,firewall_changed=False,saved_drafts_changed=False,dns_cache_flush_requested=True)
 body['plan_digest']=sha(json.dumps(body,sort_keys=True,separators=(',',':')).encode())
 return body,target
def write_backup(store,before,operation):
 root=backup_root(store);root.mkdir(exist_ok=True);ident=uuid.uuid4().hex
 path=assert_local_tree(root/(ident+'.hosts.bak'))
 # Inherits the package private-state ACL. Never shipped or uploaded.
 with path.open('xb') as f:f.write(before);f.flush();os.fsync(f.fileno())
 meta=dict(schema='unified-hosts-reset-backup-1',id=ident,created_utc=utc(),operation=operation,machine_id=machine_id(),bytes=len(before),sha256=sha(before))
 atomic_json(root/(ident+'.json'),meta)
 verified,_=get_backup(store,ident)
 if verified!=before:raise ValueError('hosts_backup_verification_failed_no_changes')
 return ident

def write_verified(f,data):
 f.seek(0);written=f.write(data)
 if written!=len(data):raise OSError('hosts_short_write')
 f.truncate();f.flush();os.fsync(f.fileno());f.seek(0)
 if f.read(view.MAX_BYTES+1)!=data:raise OSError('hosts_write_verification_failed')
def flush_dns():
 try:
  exe=assert_local_tree(windows_directory()/'System32/ipconfig.exe')
  # No shell, timeout, termination, retries or changes to DNS server settings.
  p=subprocess.run([str(exe),'/flushdns'],capture_output=True,creationflags=0x08000000)
  return dict(succeeded=p.returncode==0,exit_code=p.returncode)
 except Exception:return dict(succeeded=False,error='dns_flush_failed_hosts_already_verified')
def handle(store,action,payload,job):
 if action=='hosts_reset_list':return dict(hosts_reset_backups=list_backups(store),firewall_changed=False)
 if action in ('hosts_reset_prepare','hosts_reset_restore_prepare'):
  operation='reset' if action=='hosts_reset_prepare' else 'restore'
  plan,_=make_plan(store,read_current(),operation,payload.get('backup_id'))
  return dict(hosts_reset_plan=plan,firewall_changed=False)
 if action not in ('hosts_reset_apply','hosts_reset_restore_apply'):raise ValueError('unknown_hosts_reset_action')
 operation='reset' if action=='hosts_reset_apply' else 'restore'
 if payload.get('confirmation')!=(RESET_CONFIRM if operation=='reset' else RESTORE_CONFIRM):raise ValueError('hosts_reset_exact_typed_confirmation_required')
 require_admin();root=assert_local_tree(store.root)
 with locked(root/'hosts-operation.lock'):
  path=fixed_hosts()
  if path.stat().st_mode & stat.S_IWRITE==0 or getattr(path.stat(),'st_file_attributes',0)&1:raise ValueError('hosts_readonly_not_overridden')
  with edit.locked_file(path) as f:
   before=f.read(view.MAX_BYTES+1)
   plan,target=make_plan(store,before,operation,payload.get('backup_id'))
   if payload.get('expected_sha256')!=plan['expected_sha256'] or payload.get('plan_digest')!=plan['plan_digest']:raise ValueError('hosts_reset_preview_stale_read_and_preview_again')
   ident=write_backup(store,before,operation)
   receipt=assert_local_tree(backup_root(store)/(ident+'.operation.json'))
   atomic_json(receipt,dict(phase='backup_verified_before_change',operation=operation,backup_id=ident,plan=plan))
   atomic_json(receipt,dict(phase='write_starting_inspect_on_error_no_blind_retry',operation=operation,backup_id=ident,plan=plan))
   try:
    if target!=before:write_verified(f,target)
   except Exception as e:
    try:write_verified(f,before)
    except Exception:raise ValueError('hosts_reset_write_and_rollback_failed_keep_backup') from e
    raise ValueError('hosts_reset_write_failed_original_restored') from e
   # Hosts bytes are now verified. A later DNS/report failure must not trigger a second write.
   result=dict(operation=operation,changed=target!=before,backup_id=ident,backup_filename=ident+'.hosts.bak',before_sha256=sha(before),after_sha256=sha(target),system_wide=True,firewall_changed=False,saved_drafts_changed=False,hosts_write_verified=True,blocking_verified=False)
  result['dns_cache_flush']=flush_dns()
  try:atomic_json(receipt,dict(phase='hosts_verified',result=result))
  except Exception:result['receipt_warning']='hosts_verified_final_receipt_write_failed_keep_backup'
  try:backups=list_backups(store)
  except Exception:backups=[];result['backup_list_warning']='refresh_backup_list'
 return dict(hosts_reset_result=result,hosts=view.parse_hosts(target),hosts_reset_backups=backups,firewall_changed=False)
