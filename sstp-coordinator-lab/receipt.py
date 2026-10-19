import json,os,re,sys,hashlib
from pathlib import Path
FLAGS='whole_machine_guard_tested active_profile_targeted sstp_binding_tested packet_enforcement_tested reboot_tested user_device_tested ready_for_user_apply'.split()
BOOLS='passed cleanup_exact final_stored_notconfigured unrelated_full_policy_equal'.split()
COUNTS={'checks':(0,2000),'model_pending_cases':(0,20),'fault_cases':(0,8),'fresh_process_recoveries':(0,8),'partial_enable_disables':(0,2),'release_conflict_stops':(0,2),'pre_release_pause_cases':(0,2),'injected_process_exits':(0,10),'fixture_rules':(0,4),'remaining_test_rules':(-1,4),'unrelated_display_changes':(-1,10000)}
KEYS=set('schema source_commit run_id error_code'.split()+FLAGS+BOOLS+list(COUNTS))
def validate(n):
 if type(n) is not dict or set(n)!=KEYS or n['schema']!='sstp-coordinator-test-1':raise ValueError('schema')
 if not re.fullmatch('[a-f0-9]{40}',n['source_commit']) or not re.fullmatch('[0-9]{1,30}',n['run_id']):raise ValueError('identity')
 if any(n[k] is not False for k in FLAGS):raise ValueError('scope')
 if any(type(n[k]) is not bool for k in BOOLS):raise ValueError('bool')
 for k,(lo,hi) in COUNTS.items():
  if type(n[k]) is not int or not lo<=n[k]<=hi:raise ValueError('count')
 if n['error_code'] not in [None,'coord_test_failed','coord_cleanup_failed','coord_native_unavailable']:raise ValueError('error')
 expected={'model_pending_cases':20,'fault_cases':8,'fresh_process_recoveries':8,'partial_enable_disables':2,'release_conflict_stops':2,'pre_release_pause_cases':2,'injected_process_exits':10,'fixture_rules':4,'remaining_test_rules':0}
 if n['passed'] and (not all(n[k] for k in BOOLS) or n['checks']<120 or any(n[k]!=v for k,v in expected.items()) or n['unrelated_display_changes']<0 or n['error_code'] is not None):raise ValueError('pass')
 return n
if __name__=='__main__':
 root=Path(__file__).parent;src=os.environ['GITHUB_SHA'];run=os.environ['GITHUB_RUN_ID'];p=Path(os.environ['RUNNER_TEMP'])/'coordinator.json'
 n=json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else dict(schema='sstp-coordinator-test-1',source_commit=src,run_id=run,error_code='coord_native_unavailable',**{k:False for k in FLAGS+BOOLS},**{k:(-1 if lo<0 else 0) for k,(lo,hi) in COUNTS.items()})
 validate(n)
 if n['source_commit']!=src or n['run_id']!=run:raise ValueError('identity')
 outcome=os.environ['NATIVE_OUTCOME']
 if outcome not in ['success','failure','cancelled','skipped'] or (outcome=='success')!=n['passed']:raise ValueError('outcome')
 files={f:root/f for f in ['Coordinator.ps1','Worker.ps1','Test-Coordinator.ps1','receipt.py']}
 files.update({'Profile.ps1':root.parent/'sstp-profile-roundtrip/Profile.ps1','Engine.ps1':root.parent/'sstp-integrated-transaction/Engine.ps1','Journal.ps1':root.parent/'sstp-allowlist-backend/Journal.ps1','Inventory.ps1':root.parent/'sstp-policy-compare/Inventory.ps1'})
 r=dict(schema='sstp-coordinator-build-1',source_commit=src,run_id=run,native_outcome=outcome,native=n,hashes={f:hashlib.sha256(p.read_bytes()).hexdigest() for f,p in files.items()},ready_for_user_apply=False)
 (root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
 if not n['passed']:sys.exit(1)
