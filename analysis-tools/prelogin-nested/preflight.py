"""Owned virtualization capability probe only. No guest OS, targets or reboots."""
import argparse,json,os,re,shutil,stat,subprocess,sys
from pathlib import Path
SCHEMA='bnet-nested-preflight-1'
LIMITS=dict(guest_os_downloaded=False,guest_os_booted=False,guest_reboot_tested=False,host_rebooted=False,target_launched=False,hypervisor_feature_enabled_by_probe=False,device_permissions_changed=False,raw_identifiers_exported=False)
LINUX={'cpu_virtualization_flag','kvm_device_present','kvm_open_succeeded','kvm_api_version','kvm_user_memory_capable','kvm_vm_created','qemu_binary_present','diagnostic'}
WINDOWS={'admin','hypervisor_present','firmware_virtualization','slat','vm_monitor_extensions','hyperv_feature_installed','new_vm_command','vmms_present','vmms_running','vm_definition_created','vm_definition_removed','diagnostic'}
BOOL_LINUX=LINUX-{'kvm_api_version','diagnostic'}
BOOL_WINDOWS=WINDOWS-{'diagnostic'}
DIAGNOSTICS={'none','missing_device','permission_denied','unsupported_api','ioctl_failed','probe_failed','feature_or_service_unavailable','vm_definition_failed','vm_cleanup_failed'}
def blank(source,run,platform,access):return dict(schema=SCHEMA,source_commit=source,run_id=run,platform=platform,access=access,status='probe_failed',facts={},resources=dict(cpu_count=0,ram_gib=None,disk_free_gib=None),limits=dict(LIMITS))
def validate(r):
 if type(r) is not dict or set(r)!=set(blank('','','','')) or r['schema']!=SCHEMA:raise ValueError('schema')
 if not isinstance(r['source_commit'],str) or not re.fullmatch('[a-f0-9]{40}',r['source_commit']):raise ValueError('source')
 if not isinstance(r['run_id'],str) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('run')
 if r['platform'] not in ('linux','windows') or r['access'] not in ('runner','privileged_probe'):raise ValueError('platform')
 if r['platform']=='windows' and r['access']!='runner':raise ValueError('access')
 if r['limits']!=LIMITS or any(type(v) is not bool for v in r['limits'].values()):raise ValueError('limits')
 f=r['facts'];keys=LINUX if r['platform']=='linux' else WINDOWS
 if type(f) is not dict or set(f)!=keys or f['diagnostic'] not in DIAGNOSTICS:raise ValueError('facts')
 bools=BOOL_LINUX if r['platform']=='linux' else BOOL_WINDOWS
 for k in bools:
  if f[k] is not None and type(f[k]) is not bool:raise ValueError('boolean')
 if r['platform']=='linux':
  if f['kvm_api_version'] is not None and (type(f['kvm_api_version']) is not int or not 0<=f['kvm_api_version']<=1000):raise ValueError('api')
  if f['kvm_vm_created'] and not(f['kvm_open_succeeded'] and f['kvm_device_present'] and f['kvm_api_version']==12 and f['kvm_user_memory_capable']):raise ValueError('kvm_claim')
  expected='kvm_vm_creation_verified_not_guest_boot' if f['kvm_vm_created'] else 'kvm_not_verified'
 else:
  if f['vm_definition_created'] and not(f['new_vm_command'] and f['vmms_running'] and f['vmms_present'] and f['hyperv_feature_installed']):raise ValueError('windows_claim')
  if f['vm_definition_removed'] and not f['vm_definition_created']:raise ValueError('remove_claim')
  expected='vm_definition_created_not_guest_boot' if f['vm_definition_created'] and f['vm_definition_removed'] else 'vm_cleanup_failed' if f['vm_definition_created'] else 'hyperv_not_verified'
 if r['status'] not in (expected,'probe_failed'):raise ValueError('status')
 x=r['resources']
 if type(x) is not dict or set(x)!={'cpu_count','ram_gib','disk_free_gib'}:raise ValueError('resources')
 for k,v in x.items():
  if v is None and k!='cpu_count':continue
  if type(v) is not int or not 0<=v<=65536:raise ValueError('resource')
 return r

def linux_probe():
 f={k:None for k in LINUX};f.update(kvm_device_present=False,kvm_open_succeeded=False,kvm_vm_created=False,qemu_binary_present=bool(shutil.which('qemu-system-x86_64')),diagnostic='none')
 try:
  flags=Path('/proc/cpuinfo').read_text();f['cpu_virtualization_flag']=bool(re.search(r'\b(vmx|svm)\b',flags))
 except OSError:pass
 try:f['kvm_device_present']=stat.S_ISCHR(Path('/dev/kvm').stat().st_mode)
 except OSError:pass
 fd=vm=None
 try:
  if not f['kvm_device_present']:f['diagnostic']='missing_device';return f
  import fcntl
  fd=os.open('/dev/kvm',os.O_RDWR|os.O_CLOEXEC);f['kvm_open_succeeded']=True
  f['kvm_api_version']=fcntl.ioctl(fd,0xae00,0)
  if f['kvm_api_version']!=12:f['diagnostic']='unsupported_api';return f
  f['kvm_user_memory_capable']=fcntl.ioctl(fd,0xae03,3)>0
  if f['kvm_user_memory_capable']:
   vm=fcntl.ioctl(fd,0xae01,0);f['kvm_vm_created']=type(vm) is int and vm>=0
 except PermissionError:f['diagnostic']='permission_denied'
 except OSError:f['diagnostic']='ioctl_failed'
 finally:
  if vm is not None:os.close(vm)
  if fd is not None:os.close(fd)
 return f

def windows_probe():
 p=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(Path(__file__).with_name('windows_probe.ps1'))],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=90,check=True)
 if len(p.stdout)>8192:raise ValueError('size')
 return json.loads(p.stdout.decode('utf-8-sig'))

def resources(platform):
 x=dict(cpu_count=os.cpu_count() or 0,ram_gib=None,disk_free_gib=shutil.disk_usage(Path.cwd()).free//(1024**3))
 if platform=='linux':
  try:
   m=re.search(r'^MemTotal:\s*(\d+)\s*kB',Path('/proc/meminfo').read_text(),re.M);x['ram_gib']=int(m[1])//(1024**2) if m else None
  except OSError:pass
 else:
  try:
   import ctypes
   class MEMORY(ctypes.Structure):_fields_=[('length',ctypes.c_uint32),('load',ctypes.c_uint32)]+[(n,ctypes.c_uint64) for n in ('total','available','page','available_page','virtual','available_virtual','extended')]
   m=MEMORY();m.length=ctypes.sizeof(m)
   if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):x['ram_gib']=m.total//(1024**3)
  except (AttributeError,OSError):pass
 return x

def main():
 p=argparse.ArgumentParser();p.add_argument('--platform',choices=('linux','windows'),required=True);p.add_argument('--access',choices=('runner','privileged_probe'),default='runner');p.add_argument('--out',required=True);a=p.parse_args()
 if not(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1' and os.environ.get('GITHUB_EVENT_NAME')=='push' and os.environ.get('GITHUB_REF')=='refs/heads/research/prelogin-telemetry-wow-data-provenance' and os.environ.get('BNET_NESTED_PREFLIGHT')=='owned-nested-c1' and ((a.platform=='windows' and sys.platform=='win32') or (a.platform=='linux' and sys.platform.startswith('linux')))):raise SystemExit('guard')
 if a.access=='privileged_probe' and (a.platform!='linux' or os.geteuid()!=0):raise SystemExit('privilege_guard')
 r=blank(os.environ['GITHUB_SHA'],os.environ['GITHUB_RUN_ID'],a.platform,a.access)
 r['facts']={k:None for k in (LINUX if a.platform=='linux' else WINDOWS)};r['facts']['diagnostic']='probe_failed'
 try:
  r['resources']=resources(a.platform);r['facts']=linux_probe() if a.platform=='linux' else windows_probe()
  if a.platform=='linux':r['status']='kvm_vm_creation_verified_not_guest_boot' if r['facts']['kvm_vm_created'] else 'kvm_not_verified'
  else:r['status']='vm_definition_created_not_guest_boot' if r['facts']['vm_definition_created'] and r['facts']['vm_definition_removed'] else 'vm_cleanup_failed' if r['facts']['vm_definition_created'] else 'hyperv_not_verified'
 except Exception:pass
 validate(r);out=Path(a.out);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'platform':a.platform,'access':a.access,'status':r['status']}))
if __name__=='__main__':
 if len(sys.argv)==4 and sys.argv[1]=='validate':
  r=validate(json.loads(Path(sys.argv[2]).read_text()));dst=Path(sys.argv[3]);dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text(json.dumps(r,indent=2)+'\n')
 else:main()
