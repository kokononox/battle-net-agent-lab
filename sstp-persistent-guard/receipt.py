import json,os,re,hashlib,sys
from pathlib import Path
FLAGS='whole_machine_guard_tested profile_defaults_changed ipv6_packet_tested sstp_tested reboot_tested user_device_tested ready_for_user_apply'.split()
COUNTS={'checks':(0,1000),'fault_cases':(0,6),'fresh_process_recoveries':(0,6),'packet_block_pairs':(0,2),'owned_conflict_stops':(0,2),'fixture_rules':(0,9),'remaining_test_rules':(-1,9),'unrelated_display_changes':(-1,10000)}
KEYS=set('schema source_commit run_id passed error_code unrelated_full_policy_equal'.split()+FLAGS+list(COUNTS))
def validate(n):
 if type(n) is not dict or set(n)!=KEYS or n['schema']!='sstp-guard-test-1':raise ValueError('schema')
 if not re.fullmatch('[a-f0-9]{40}',n['source_commit']) or not re.fullmatch('[0-9]{1,30}',n['run_id']):raise ValueError('identity')
 if any(n[k] is not False for k in FLAGS):raise ValueError('scope')
 for k in ['passed','unrelated_full_policy_equal']:
  if type(n[k]) is not bool:raise ValueError('bool')
 for k,(lo,hi) in COUNTS.items():
  if type(n[k]) is not int or not lo<=n[k]<=hi:raise ValueError('count')
 if n['error_code'] not in [None,'guard_test_failed','guard_cleanup_failed','guard_native_unavailable']:raise ValueError('error')
 if n['passed'] and (n['checks']<60 or any(n[k]!=v for k,v in {'fault_cases':6,'fresh_process_recoveries':6,'packet_block_pairs':2,'owned_conflict_stops':2,'fixture_rules':9,'remaining_test_rules':0}.items()) or not n['unrelated_full_policy_equal'] or n['unrelated_display_changes']<0 or n['error_code'] is not None):raise ValueError('pass')
 return n
if __name__=='__main__':
 root=Path(__file__).parent;src=os.environ['GITHUB_SHA'];run=os.environ['GITHUB_RUN_ID'];p=Path(os.environ['RUNNER_TEMP'])/'guard.json'
 n=json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else dict(schema='sstp-guard-test-1',source_commit=src,run_id=run,passed=False,error_code='guard_native_unavailable',unrelated_full_policy_equal=False,**{k:False for k in FLAGS},**{k:(-1 if lo<0 else 0) for k,(lo,hi) in COUNTS.items()})
 validate(n)
 if n['source_commit']!=src or n['run_id']!=run:raise ValueError('identity')
 outcome=os.environ['NATIVE_OUTCOME']
 if outcome not in ['success','failure','cancelled','skipped'] or (outcome=='success')!=n['passed']:raise ValueError('outcome')
 files={f:root/f for f in ['Guard.ps1','Worker.ps1','Test-Guard.ps1','Probe.cs','receipt.py']}
 files.update({'Journal.ps1':root.parent/'sstp-allowlist-backend/Journal.ps1','Inventory.ps1':root.parent/'sstp-policy-compare/Inventory.ps1','Engine.ps1':root.parent/'sstp-integrated-transaction/Engine.ps1'})
 r=dict(schema='sstp-guard-build-1',source_commit=src,run_id=run,native_outcome=outcome,native=n,hashes={f:hashlib.sha256(p.read_bytes()).hexdigest() for f,p in files.items()},ready_for_user_apply=False)
 (root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
 if not n['passed']:sys.exit(1)
