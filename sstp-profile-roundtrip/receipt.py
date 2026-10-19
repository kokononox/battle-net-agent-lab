import json,os,re,sys,hashlib
from pathlib import Path
FLAGS='active_profile_targeted whole_machine_enforcement_tested guard_coordinator_tested sstp_tested reboot_tested user_device_tested ready_for_user_apply'.split()
BOOLS='passed cleanup_exact final_stored_notconfigured unrelated_full_policy_equal observed_inactive_domain_block'.split()
COUNTS={'checks':(0,2000),'profile_field_cases':(0,1500),'fault_cases':(0,6),'fresh_process_recoveries':(0,6),'partial_restores':(0,2),'native_notconfigured_noops':(0,9),'verified_restore_completions':(0,8),'external_conflict_stops':(0,1),'unrelated_display_changes':(-1,10000)}
KEYS=set('schema source_commit run_id error_code'.split()+FLAGS+BOOLS+list(COUNTS))
def validate(n):
 if type(n) is not dict or set(n)!=KEYS or n['schema']!='sstp-profile-test-1':raise ValueError('schema')
 if not re.fullmatch('[a-f0-9]{40}',n['source_commit']) or not re.fullmatch('[0-9]{1,30}',n['run_id']):raise ValueError('identity')
 if any(n[k] is not False for k in FLAGS):raise ValueError('scope')
 if any(type(n[k]) is not bool for k in BOOLS):raise ValueError('bool')
 for k,(lo,hi) in COUNTS.items():
  if type(n[k]) is not int or not lo<=n[k]<=hi:raise ValueError('count')
 if n['error_code'] not in [None,'profile_test_failed','profile_cleanup_failed','profile_native_unavailable']:raise ValueError('error')
 if n['passed'] and (not all(n[k] for k in BOOLS) or n['checks']<n['profile_field_cases']+50 or n['profile_field_cases']<50 or any(n[k]!=v for k,v in {'fault_cases':6,'fresh_process_recoveries':6,'partial_restores':2,'native_notconfigured_noops':9,'verified_restore_completions':8,'external_conflict_stops':1}.items()) or n['unrelated_display_changes']<0 or n['error_code'] is not None):raise ValueError('pass')
 return n
if __name__=='__main__':
 root=Path(__file__).parent;src=os.environ['GITHUB_SHA'];run=os.environ['GITHUB_RUN_ID'];p=Path(os.environ['RUNNER_TEMP'])/'profile.json'
 n=json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else dict(schema='sstp-profile-test-1',source_commit=src,run_id=run,error_code='profile_native_unavailable',**{k:False for k in FLAGS+BOOLS},**{k:(-1 if lo<0 else 0) for k,(lo,hi) in COUNTS.items()})
 validate(n)
 if n['source_commit']!=src or n['run_id']!=run:raise ValueError('identity')
 outcome=os.environ['NATIVE_OUTCOME']
 if outcome not in ['success','failure','cancelled','skipped'] or (outcome=='success')!=n['passed']:raise ValueError('outcome')
 files={f:root/f for f in ['Profile.ps1','Worker.ps1','Test-Profile.ps1','receipt.py']}
 files.update({'Journal.ps1':root.parent/'sstp-allowlist-backend/Journal.ps1','Inventory.ps1':root.parent/'sstp-policy-compare/Inventory.ps1','Engine.ps1':root.parent/'sstp-integrated-transaction/Engine.ps1'})
 r=dict(schema='sstp-profile-build-1',source_commit=src,run_id=run,native_outcome=outcome,native=n,hashes={f:hashlib.sha256(p.read_bytes()).hexdigest() for f,p in files.items()},ready_for_user_apply=False)
 (root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
 if not n['passed']:sys.exit(1)
