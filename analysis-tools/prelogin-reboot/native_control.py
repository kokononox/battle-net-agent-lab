"""Owned state/DPAPI and real boot-marker NEGATIVE control. Never runs/reboots target."""
import json,os,sys,tempfile
from pathlib import Path
from reboot_probe import prepare,compare,dpapi,context_real,secure_folder,code_hash,now,validate_public
KEYS={'schema','source_commit','run_id','status','dpapi_roundtrip','tampered_dpapi_rejected','same_boot_rejected','boot_marker_available','private_acl_applied','target_launched','os_reboot_performed','registry_target_modified','identifiers_or_hashes_exported'}
def validate(r):
 if type(r) is not dict or set(r)!=KEYS or r['schema']!='bnet-reboot-native-control-1':raise ValueError('schema')
 import re
 if not isinstance(r['source_commit'],str) or not re.fullmatch('[a-f0-9]{40}',r['source_commit']) or not isinstance(r['run_id'],str) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('provenance')
 for k in KEYS-{'schema','source_commit','run_id','status'}:
  if type(r[k]) is not bool:raise ValueError('boolean')
 if r['status'] not in ('passed_control_only_no_reboot','failed'):raise ValueError('status')
 if any(r[k] for k in ('target_launched','os_reboot_performed','registry_target_modified','identifiers_or_hashes_exported')):raise ValueError('scope')
 if r['status']=='passed_control_only_no_reboot' and not all(r[k] for k in ('dpapi_roundtrip','tampered_dpapi_rejected','same_boot_rejected','boot_marker_available','private_acl_applied')):raise ValueError('gate')
 return r

def main():
 if not(sys.platform=='win32' and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1' and os.environ.get('GITHUB_EVENT_NAME')=='push' and os.environ.get('GITHUB_REF')=='refs/heads/research/prelogin-telemetry-wow-data-provenance' and os.environ.get('BNET_REBOOT_CONTROL')=='owned-no-reboot-b1'):raise SystemExit('owned_hosted_once_required')
 r={k:False for k in KEYS};r.update(schema='bnet-reboot-native-control-1',source_commit=os.environ['GITHUB_SHA'],run_id=os.environ['GITHUB_RUN_ID'],status='failed')
 try:
  c=context_real();c['target_running']=False # Fixture is synthetic; no target is launched or registry target read.
  result,s=prepare(c,'abcdefab-abcd-4abc-abcd-abcdefabcdef',now(),code_hash());validate_public(result);r['boot_marker_available']=bool(c['boot_utc'])
  raw=json.dumps(s).encode();encrypted=dpapi(raw,True)
  with tempfile.TemporaryDirectory(prefix='reboot-control-',dir=os.environ['RUNNER_TEMP']) as tmp:
   folder=Path(tmp)/'private';secure_folder(folder,c['user_sid']);r['private_acl_applied']=True;p=folder/'synthetic-state.dpapi';p.write_bytes(encrypted);decoded=dpapi(p.read_bytes(),False);r['dpapi_roundtrip']=decoded==raw
   t=bytearray(encrypted);t[len(t)//2]^=0x40
   try:dpapi(bytes(t),False)
   except OSError:r['tampered_dpapi_rejected']=True
   after=context_real();after['target_running']=False
   result=compare(json.loads(decoded),after,s['value'],now(),code_hash());validate_public(result)
   r['same_boot_rejected']=result['status']=='same_boot_not_a_reboot_test' and not result['boot_change_verified'] and result['value_equal'] is None
  if all(r[k] for k in ('dpapi_roundtrip','tampered_dpapi_rejected','same_boot_rejected','boot_marker_available','private_acl_applied')):r['status']='passed_control_only_no_reboot'
 except Exception:pass
 validate(r);p=Path('output/reboot-native-control.json');p.parent.mkdir(exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'status':r['status'],'real_reboot_tested':False}))
if __name__=='__main__':
 if len(sys.argv)==4 and sys.argv[1]=='validate':
  r=validate(json.loads(Path(sys.argv[2]).read_text()));dst=Path(sys.argv[3]);dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text(json.dumps(r,indent=2)+'\n')
 else:main()
