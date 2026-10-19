import hashlib,json,os,re,sys
from pathlib import Path
FLAGS='effective_network_policy_changed dns_queried resident_program_created real_guard_tested enforcement_tested sstp_binding_tested user_device_tested ready_for_user_apply'.split()
KEYS=set('schema source_commit run_id passed checks fault_cases fresh_process_recoveries ambiguous_review_stops error_code adapter_kind remaining_test_rules profiles_unchanged existing_rule_properties_unchanged'.split()+FLAGS)
def validate(n):
 if type(n) is not dict or set(n)!=KEYS or n['schema']!='sstp-native-journal-test-1' or n['adapter_kind']!='native_disabled_rules':raise ValueError('schema')
 if not re.fullmatch('[a-f0-9]{40}',n['source_commit']) or not re.fullmatch('[0-9]{1,30}',n['run_id']):raise ValueError('identity')
 if type(n['passed']) is not bool:raise ValueError('bool')
 for k,m in [('checks',39),('fault_cases',5),('fresh_process_recoveries',4),('ambiguous_review_stops',2)]:
  if type(n[k]) is not int or not 0<=n[k]<=m:raise ValueError('counts')
 if type(n['remaining_test_rules']) is not int or not -1<=n['remaining_test_rules']<=10:raise ValueError('remaining')
 for k in ['profiles_unchanged','existing_rule_properties_unchanged']:
  if type(n[k]) is not bool:raise ValueError('baseline_type')
 if any(n[k] is not False for k in FLAGS):raise ValueError('scope')
 if n['error_code'] not in [None,'staging_native_failure','staging_native_unavailable','staging_cleanup_failure','staging_baseline_mismatch']:raise ValueError('error')
 if n['passed'] and (n['checks']!=39 or n['fault_cases']!=5 or n['fresh_process_recoveries']!=4 or n['ambiguous_review_stops']!=2 or n['remaining_test_rules']!=0 or not n['profiles_unchanged'] or not n['existing_rule_properties_unchanged'] or n['error_code'] is not None):raise ValueError('pass')
 return n
if __name__=='__main__':
 root=Path(__file__).parent;src=os.environ['GITHUB_SHA'];run=os.environ['GITHUB_RUN_ID'];p=Path(os.environ['RUNNER_TEMP'])/'native-journal.json'
 n=json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else dict(schema='sstp-native-journal-test-1',source_commit=src,run_id=run,passed=False,checks=0,fault_cases=0,fresh_process_recoveries=0,ambiguous_review_stops=0,error_code='staging_native_unavailable',adapter_kind='native_disabled_rules',remaining_test_rules=-1,profiles_unchanged=False,existing_rule_properties_unchanged=False,**{k:False for k in FLAGS})
 validate(n)
 if n['source_commit']!=src or n['run_id']!=run:raise ValueError('expected_identity')
 outcome=os.environ['NATIVE_OUTCOME']
 if outcome not in ['success','failure','cancelled','skipped'] or (outcome=='success' and not n['passed']):raise ValueError('outcome')
 files={f:root/f for f in ['NativeJournal.ps1','Worker.ps1','Test-NativeJournal.ps1']}
 files.update({'Journal.ps1':root.parent/'sstp-allowlist-backend/Journal.ps1','Firewall.ps1':root.parent/'sstp-allowlist-adapter/Firewall.ps1','Policy.ps1':root.parent/'sstp-allowlist-policy/Policy.ps1'})
 r=dict(schema='sstp-native-journal-build-1',source_commit=src,run_id=run,native_outcome=outcome,native=n,hashes={f:hashlib.sha256(p.read_bytes()).hexdigest() for f,p in files.items()},ready_for_user_apply=False)
 (root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
 if not n['passed']:sys.exit(1)
