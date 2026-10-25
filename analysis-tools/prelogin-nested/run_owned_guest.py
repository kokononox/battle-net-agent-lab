"""Execute only the compiled owned synthetic KVM probe; sanitize stdout strictly."""
import hashlib,json,os,re,subprocess,sys
from pathlib import Path
FLAGS={'vm_created','memory_registered','vcpu_created','synthetic_marker_received','halt_exit_received','guest_os_booted','guest_reboot_tested','target_launched'}
RAW=FLAGS|{'schema','api_version','failure_stage'}
TOP={'schema','source_commit','run_id','status','binary_sha256','result','host_rebooted','guest_os_downloaded','raw_identifiers_exported'}
def validate_raw(x):
 if type(x) is not dict or set(x)!=RAW or x['schema']!='owned-kvm-guest-1':raise ValueError('raw_schema')
 for k in FLAGS:
  if type(x[k]) is not bool:raise ValueError('boolean')
 for k,n in [('api_version',1000),('failure_stage',99)]:
  if type(x[k]) is not int or not 0<=x[k]<=n:raise ValueError('counter')
 for k in ('guest_os_booted','guest_reboot_tested','target_launched'):
  if x[k]:raise ValueError('scope')
 if x['memory_registered'] and not x['vm_created']:raise ValueError('memory')
 if x['vcpu_created'] and not x['memory_registered']:raise ValueError('vcpu')
 if (x['synthetic_marker_received'] or x['halt_exit_received']) and not x['vcpu_created']:raise ValueError('execution')
 return x

def validate(r):
 if type(r) is not dict or set(r)!=TOP or r['schema']!='bnet-owned-kvm-result-1':raise ValueError('schema')
 for k,n in [('source_commit',40),('binary_sha256',64)]:
  if not isinstance(r[k],str) or not re.fullmatch('[a-f0-9]{'+str(n)+'}',r[k]):raise ValueError('provenance')
 if not isinstance(r['run_id'],str) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('run')
 for k in ('host_rebooted','guest_os_downloaded','raw_identifiers_exported'):
  if r[k] is not False:raise ValueError('scope')
 if r['status'] not in ('owned_guest_executed_no_OS_boot','inconclusive'):raise ValueError('status')
 if r['result'] is not None:validate_raw(r['result'])
 good=r['result'] is not None and r['result']['api_version']==12 and r['result']['failure_stage']==0 and all(r['result'][k] for k in ('vm_created','memory_registered','vcpu_created','synthetic_marker_received','halt_exit_received'))
 if (r['status']=='owned_guest_executed_no_OS_boot')!=good:raise ValueError('claim')
 return r

def main():
 if not(sys.platform.startswith('linux') and os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1' and os.environ.get('GITHUB_EVENT_NAME')=='push' and os.environ.get('GITHUB_REF')=='refs/heads/research/prelogin-telemetry-wow-data-provenance' and os.environ.get('BNET_NESTED_PREFLIGHT')=='owned-nested-c2'):raise SystemExit('guard')
 exe=Path('output/owned-kvm-guest').resolve();r=dict(schema='bnet-owned-kvm-result-1',source_commit=os.environ['GITHUB_SHA'],run_id=os.environ['GITHUB_RUN_ID'],status='inconclusive',binary_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),result=None,host_rebooted=False,guest_os_downloaded=False,raw_identifiers_exported=False)
 try:
  p=subprocess.run([str(exe)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,check=True)
  if len(p.stdout)>4096:raise ValueError('size')
  x=validate_raw(json.loads(p.stdout));r['result']=x
  if x['api_version']==12 and x['failure_stage']==0 and all(x[k] for k in ('vm_created','memory_registered','vcpu_created','synthetic_marker_received','halt_exit_received')):r['status']='owned_guest_executed_no_OS_boot'
 except (ValueError,OSError,subprocess.SubprocessError):pass
 validate(r);Path('output/owned-kvm-runtime.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'status':r['status'],'windows_booted':False}))
if __name__=='__main__':
 if len(sys.argv)==4 and sys.argv[1]=='validate':
  r=validate(json.loads(Path(sys.argv[2]).read_text()));p=Path(sys.argv[3]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
 else:main()
