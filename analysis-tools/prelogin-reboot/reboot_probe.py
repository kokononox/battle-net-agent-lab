"""Registry-only before/after OS-boot comparison. No automatic reboot/target launch.
Private state is Windows CurrentUser DPAPI; never upload it or identifier hashes.
"""
import argparse,ctypes,datetime,hashlib,json,os,re,subprocess,sys
from pathlib import Path
UTC=datetime.timezone.utc
KEY=r'Software\Blizzard Entertainment\Blizzard Error'
UUID=re.compile(r'[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}')
FIELDS={'schema','status','same_environment','boot_change_verified','value_equal','registry_only','outgoing_host_id_after_reboot_verified','intervening_target_activity_excluded','raw_identifiers_exported','identifier_hashes_exported','automatic_reboot_performed','target_launch_performed'}
STATUSES={'prepared_waiting_for_manual_reboot','blocked_target_running','value_absent_before','value_invalid_before','same_boot_not_a_reboot_test','environment_changed','boot_time_check_failed','same_value_after_boot','changed_value_after_boot','value_absent_after_boot','value_invalid_after_boot','private_state_exists','private_state_unavailable','private_state_invalid','probe_failed'}
def public(status):return dict(schema='bnet-reboot-registry-probe-1',status=status,same_environment=False,boot_change_verified=False,value_equal=None,registry_only=True,outgoing_host_id_after_reboot_verified=False,intervening_target_activity_excluded=False,raw_identifiers_exported=False,identifier_hashes_exported=False,automatic_reboot_performed=False,target_launch_performed=False)
def validate_public(r):
 if type(r) is not dict or set(r)!=FIELDS or r['schema']!='bnet-reboot-registry-probe-1' or r['status'] not in STATUSES:raise ValueError('public_schema')
 for k in FIELDS-{'schema','status','value_equal'}:
  if type(r[k]) is not bool:raise ValueError('boolean')
 if r['value_equal'] is not None and type(r['value_equal']) is not bool:raise ValueError('comparison')
 for k,v in public('probe_failed').items():
  if k not in ('schema','status','same_environment','boot_change_verified','value_equal') and r[k]!=v:raise ValueError('scope')
 positive=r['status'] in {'same_value_after_boot','changed_value_after_boot','value_absent_after_boot','value_invalid_after_boot'}
 if r['boot_change_verified']!=positive or (positive and not r['same_environment']):raise ValueError('boot_claim')
 expected=True if r['status']=='same_value_after_boot' else False if r['status']=='changed_value_after_boot' else None
 if r['value_equal'] is not expected:raise ValueError('value_claim')
 return r

def moment(s):
 if not isinstance(s,str) or len(s)>64:raise ValueError('time')
 t=datetime.datetime.fromisoformat(s.replace('Z','+00:00'))
 if t.tzinfo is None:raise ValueError('timezone')
 return t.astimezone(UTC)
def now():return datetime.datetime.now(UTC).isoformat()
def code_hash():return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
def state_valid(s):
 if type(s) is not dict or set(s)!={'schema','context','value','created_utc','code_sha256'} or s['schema']!='bnet-reboot-private-state-1':raise ValueError('private_schema')
 c=s['context']
 if type(c) is not dict or set(c)!={'boot_utc','machine_guid','user_sid','profile','volume_serial','target_running'}:raise ValueError('private_context')
 if not all(isinstance(c[k],str) and 0<len(c[k])<=1024 for k in ('boot_utc','machine_guid','user_sid','profile')):raise ValueError('context_text')
 if type(c['target_running']) is not bool or c['target_running'] or type(c['volume_serial']) is not int:raise ValueError('context')
 if not isinstance(s['value'],str) or not UUID.fullmatch(s['value']):raise ValueError('private_uuid')
 if not isinstance(s['code_sha256'],str) or not re.fullmatch('[a-f0-9]{64}',s['code_sha256']):raise ValueError('code')
 if moment(c['boot_utc'])>moment(s['created_utc']):raise ValueError('before_time')
 return s

def prepare(context,value,created,sha):
 if context['target_running']:return public('blocked_target_running'),None
 if value is None:return public('value_absent_before'),None
 if not isinstance(value,str) or not UUID.fullmatch(value):return public('value_invalid_before'),None
 s=state_valid(dict(schema='bnet-reboot-private-state-1',context=context,value=value,created_utc=created,code_sha256=sha))
 return public('prepared_waiting_for_manual_reboot'),s

def compare(s,context,value,observed,sha):
 state_valid(s)
 if context['target_running']:return public('blocked_target_running')
 r=public('environment_changed')
 if s['code_sha256']!=sha or any(s['context'][k]!=context[k] for k in ('machine_guid','user_sid','profile','volume_serial')):return r
 r['same_environment']=True
 old=moment(s['context']['boot_utc']);new=moment(context['boot_utc'])
 if old==new:r['status']='same_boot_not_a_reboot_test';return r
 if not(old<=moment(s['created_utc'])<new<=moment(observed)):
  r['status']='boot_time_check_failed';return r
 r['boot_change_verified']=True
 if value is None:r['status']='value_absent_after_boot'
 elif not isinstance(value,str) or not UUID.fullmatch(value):r['status']='value_invalid_after_boot'
 else:r.update(status='same_value_after_boot' if value==s['value'] else 'changed_value_after_boot',value_equal=value==s['value'])
 return validate_public(r)

def powershell(script):
 p=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30,check=True)
 if len(p.stdout)>16384:raise ValueError('powershell_size')
 return p.stdout.decode('utf-8-sig').strip()

def context_real():
 import winreg
 # Private metadata returned only into RAM / DPAPI state, never public output.
 script="""$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$os=Get-CimInstance Win32_OperatingSystem;$x=@{boot_utc=$os.LastBootUpTime.ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture);user_sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;target_running=[bool](Get-Process -Name 'Battle.net','Battle.net-Setup','Agent','AgentHelper','Wow','WowClassic' -ErrorAction SilentlyContinue)};$x|ConvertTo-Json -Compress"""
 c=json.loads(powershell(script))
 if set(c)!={'boot_utc','user_sid','target_running'}:raise ValueError('context')
 with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Cryptography',0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY) as k:c['machine_guid']=winreg.QueryValueEx(k,'MachineGuid')[0]
 profile=Path(os.environ['USERPROFILE']).resolve();c['profile']=str(profile).casefold()
 kernel=ctypes.WinDLL('kernel32',use_last_error=True)
 kernel.GetVolumePathNameW.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_uint32];kernel.GetVolumePathNameW.restype=ctypes.c_int
 kernel.GetVolumeInformationW.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint32),ctypes.POINTER(ctypes.c_uint32),ctypes.POINTER(ctypes.c_uint32),ctypes.c_wchar_p,ctypes.c_uint32];kernel.GetVolumeInformationW.restype=ctypes.c_int
 root=ctypes.create_unicode_buffer(1024)
 if not kernel.GetVolumePathNameW(str(profile),root,1024):raise OSError('volume_root')
 serial=ctypes.c_uint32();maximum=ctypes.c_uint32();flags=ctypes.c_uint32()
 if not kernel.GetVolumeInformationW(root.value,None,0,ctypes.byref(serial),ctypes.byref(maximum),ctypes.byref(flags),None,0):raise OSError('volume')
 c['volume_serial']=serial.value;return c

def registry_real():
 import winreg
 try:
  with winreg.OpenKey(winreg.HKEY_CURRENT_USER,KEY,0,winreg.KEY_READ) as k:v,t=winreg.QueryValueEx(k,'UserUUID')
  return v if t==winreg.REG_SZ else ''
 except FileNotFoundError:return None

class Blob(ctypes.Structure):_fields_=[('cbData',ctypes.c_uint32),('pbData',ctypes.POINTER(ctypes.c_ubyte))]
def dpapi(raw,protect):
 if os.name!='nt' or not 0<len(raw)<=65536:raise ValueError('dpapi_scope')
 buf=ctypes.create_string_buffer(raw);src=Blob(len(raw),ctypes.cast(buf,ctypes.POINTER(ctypes.c_ubyte)));dst=Blob()
 crypt=ctypes.WinDLL('crypt32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
 f=crypt.CryptProtectData if protect else crypt.CryptUnprotectData
 f.argtypes=[ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint32,ctypes.POINTER(Blob)];f.restype=ctypes.c_int
 # UI forbidden, CurrentUser scope; no CRYPTPROTECT_LOCAL_MACHINE flag.
 if not f(ctypes.byref(src),None,None,None,None,1,ctypes.byref(dst)):raise OSError('dpapi_failed')
 try:return ctypes.string_at(dst.pbData,dst.cbData)
 finally:
  kernel.LocalFree.argtypes=[ctypes.c_void_p];kernel.LocalFree.restype=ctypes.c_void_p;kernel.LocalFree(dst.pbData)

def secure_folder(path,sid):
 if path.exists():
  if not path.is_dir() or path.is_symlink() or getattr(path.stat(),'st_file_attributes',0)&1024:raise ValueError('state_folder')
 else:path.mkdir(parents=False)
 if not re.fullmatch(r'S-1-5-[0-9-]{1,180}',sid):raise ValueError('sid')
 subprocess.run(['icacls.exe',str(path),'/inheritance:r','/grant:r','*'+sid+':(OI)(CI)F','*S-1-5-18:(OI)(CI)F'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=15)

def main():
 ap=argparse.ArgumentParser(description='Compare UserUUID locally across a manually performed real Windows reboot. Never upload private state.')
 ap.add_argument('phase',choices=('before','after'));a=ap.parse_args();r=public('probe_failed')
 try:
  if os.name!='nt':raise ValueError('windows_only')
  c=context_real();base=Path(os.environ['LOCALAPPDATA'])/'BattleNetRebootProbe';state=base/'private-state.dpapi'
  if a.phase=='before':
   if state.exists():r=public('private_state_exists')
   else:
    r,s=prepare(c,registry_real(),now(),code_hash())
    if s is not None:
     secure_folder(base,c['user_sid']);encrypted=dpapi(json.dumps(s,ensure_ascii=False).encode(),True)
     with state.open('xb') as f:f.write(encrypted)
  else:
   if not state.is_file() or state.is_symlink() or getattr(state.stat(),'st_file_attributes',0)&1024 or not 0<state.stat().st_size<=65536:r=public('private_state_unavailable')
   else:
    try:s=json.loads(dpapi(state.read_bytes(),False));state_valid(s)
    except (ValueError,UnicodeError,OSError):r=public('private_state_invalid')
    else:r=compare(s,c,registry_real(),now(),code_hash())
 except Exception:r=public('probe_failed')
 validate_public(r);print(json.dumps(r,indent=2))
 return 0 if r['status'] in ('prepared_waiting_for_manual_reboot','same_value_after_boot','changed_value_after_boot','value_absent_after_boot','value_invalid_after_boot') else 2
if __name__=='__main__':sys.exit(main())
