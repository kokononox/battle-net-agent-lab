import json,os,sys,re,hashlib
from pathlib import Path
FLAGS='profile_defaults_changed real_guard_tested enforcement_tested sstp_binding_tested user_device_tested ready_for_user_apply'.split()
BASE='schema source_commit run_id passed error_code checks seal_field_cases fault_cases fresh_process_recoveries partial_quarantine_restores external_conflict_stops metadata_preserved_cases capacity_rejections corrupt_journal_stops missing_journal_stops verified_fixture_rules remaining_test_rules journal_baseline_seals_min unrelated_full_policy_equal unrelated_display_changes verified_native_enabled_changes'.split()
def integer(v,lo,hi):
 if type(v) is not int or not lo<=v<=hi:raise ValueError('integer')
def validate(n):
 if type(n) is not dict or set(n)!=set(BASE+FLAGS) or n['schema']!='sstp-integrated-test-1':raise ValueError('schema')
 if not re.fullmatch('[a-f0-9]{40}',n['source_commit']) or not re.fullmatch('[0-9]{1,30}',n['run_id']):raise ValueError('identity')
 for k in ['passed','unrelated_full_policy_equal','verified_native_enabled_changes']:
  if type(n[k]) is not bool:raise ValueError('bool')
 if any(n[k] is not False for k in FLAGS):raise ValueError('scope')
 for k,hi in [('checks',2000),('seal_field_cases',1500),('fault_cases',6),('fresh_process_recoveries',6),('partial_quarantine_restores',2),('external_conflict_stops',4),('metadata_preserved_cases',1),('capacity_rejections',1),('corrupt_journal_stops',1),('missing_journal_stops',1),('verified_fixture_rules',21)]:integer(n[k],0,hi)
 integer(n['remaining_test_rules'],-1,21);integer(n['journal_baseline_seals_min'],0,10000);integer(n['unrelated_display_changes'],-1,10000)
 if n['error_code'] not in [None,'integrated_native_failure','integrated_native_unavailable','integrated_cleanup_failure','integrated_baseline_mismatch']:raise ValueError('error')
 if n['passed'] and (n['checks']<n['seal_field_cases']+55 or n['seal_field_cases']<50 or n['fault_cases']!=6 or n['fresh_process_recoveries']!=6 or n['partial_quarantine_restores']!=2 or n['external_conflict_stops']!=4 or any(n[k]!=1 for k in ['metadata_preserved_cases','capacity_rejections','corrupt_journal_stops','missing_journal_stops']) or n['verified_fixture_rules']!=21 or n['remaining_test_rules']!=0 or n['journal_baseline_seals_min']<21 or not n['unrelated_full_policy_equal'] or n['unrelated_display_changes']<0 or not n['verified_native_enabled_changes'] or n['error_code'] is not None):raise ValueError('pass')
 return n
if __name__=='__main__':
 root=Path(__file__).parent;src=os.environ['GITHUB_SHA'];run=os.environ['GITHUB_RUN_ID'];p=Path(os.environ['RUNNER_TEMP'])/'integrated.json'
 n=json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else dict(schema='sstp-integrated-test-1',source_commit=src,run_id=run,passed=False,error_code='integrated_native_unavailable',checks=0,seal_field_cases=0,fault_cases=0,fresh_process_recoveries=0,partial_quarantine_restores=0,external_conflict_stops=0,metadata_preserved_cases=0,capacity_rejections=0,corrupt_journal_stops=0,missing_journal_stops=0,verified_fixture_rules=0,remaining_test_rules=-1,journal_baseline_seals_min=0,unrelated_full_policy_equal=False,unrelated_display_changes=-1,verified_native_enabled_changes=False,**{k:False for k in FLAGS})
 validate(n)
 if n['source_commit']!=src or n['run_id']!=run:raise ValueError('expected_identity')
 outcome=os.environ['NATIVE_OUTCOME']
 if outcome not in ['success','failure','cancelled','skipped'] or (outcome=='success' and not n['passed']):raise ValueError('outcome')
 files={f:root/f for f in ['Engine.ps1','Worker.ps1','Test-Engine.ps1','receipt.py']};files.update({'Journal.ps1':root.parent/'sstp-allowlist-backend/Journal.ps1','Inventory.ps1':root.parent/'sstp-policy-compare/Inventory.ps1'})
 r=dict(schema='sstp-integrated-build-1',source_commit=src,run_id=run,native_outcome=outcome,native=n,hashes={f:hashlib.sha256(p.read_bytes()).hexdigest() for f,p in files.items()},ready_for_user_apply=False)
 (root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
 if not n['passed']:sys.exit(1)
