import hashlib,json,os,re,sys
from pathlib import Path
FLAGS='profile_defaults_changed dns_queried resident_program_created real_guard_tested enforcement_tested sstp_binding_tested user_device_tested ready_for_user_apply'.split()
BASE='schema source_commit run_id passed checks fault_cases fresh_process_recoveries partial_quarantine_restores error_code verified_fixture_rules remaining_test_rules profiles_unchanged existing_rule_properties_unchanged test_rule_enabled_states_changed unrelated_rule_delta'.split()
def validate(n):
 if type(n) is not dict or set(n)!=set(BASE+FLAGS) or n['schema']!='sstp-quarantine-test-2':raise ValueError('schema')
 if not re.fullmatch('[a-f0-9]{40}',n['source_commit']) or not re.fullmatch('[0-9]{1,30}',n['run_id']):raise ValueError('identity')
 for k in ['passed','profiles_unchanged','existing_rule_properties_unchanged','test_rule_enabled_states_changed']:
  if type(n[k]) is not bool:raise ValueError('bool')
 for k,m in [('checks',87),('fault_cases',10),('fresh_process_recoveries',10),('partial_quarantine_restores',2),('verified_fixture_rules',29)]:
  if type(n[k]) is not int or not 0<=n[k]<=m:raise ValueError('counts')
 if type(n['remaining_test_rules']) is not int or not -1<=n['remaining_test_rules']<=29:raise ValueError('remaining')
 d=n['unrelated_rule_delta']
 if type(d) is not dict or set(d)!=set('added removed modified property_names'.split()):raise ValueError('delta_schema')
 if any(type(d[k]) is not int or not -1<=d[k]<=10000 for k in ['added','removed','modified']):raise ValueError('delta_counts')
 if type(d['property_names']) is not list or len(d['property_names'])>128 or any(type(x) is not str or not re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,80}',x) for x in d['property_names']):raise ValueError('delta_fields')
 if n['existing_rule_properties_unchanged'] != (not any(d[k] for k in ['added','removed','modified'])):raise ValueError('delta_baseline')
 if any(n[k] is not False for k in FLAGS):raise ValueError('scope')
 if n['error_code'] not in [None,'quarantine_native_failure','quarantine_native_unavailable','quarantine_cleanup_failure','quarantine_baseline_mismatch']:raise ValueError('error')
 if n['passed'] and (n['checks']!=87 or n['fault_cases']!=10 or n['fresh_process_recoveries']!=10 or n['partial_quarantine_restores']!=2 or n['verified_fixture_rules']!=29 or n['remaining_test_rules']!=0 or not n['profiles_unchanged'] or not n['existing_rule_properties_unchanged'] or not n['test_rule_enabled_states_changed'] or n['error_code'] is not None):raise ValueError('pass')
 return n
if __name__=='__main__':
 root=Path(__file__).parent;src=os.environ['GITHUB_SHA'];run=os.environ['GITHUB_RUN_ID'];p=Path(os.environ['RUNNER_TEMP'])/'quarantine.json'
 n=json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else dict(schema='sstp-quarantine-test-2',source_commit=src,run_id=run,passed=False,checks=0,fault_cases=0,fresh_process_recoveries=0,partial_quarantine_restores=0,error_code='quarantine_native_unavailable',verified_fixture_rules=0,remaining_test_rules=-1,profiles_unchanged=False,existing_rule_properties_unchanged=False,test_rule_enabled_states_changed=False,unrelated_rule_delta=dict(added=-1,removed=-1,modified=-1,property_names=[]),**{k:False for k in FLAGS})
 validate(n)
 if n['source_commit']!=src or n['run_id']!=run:raise ValueError('expected_identity')
 outcome=os.environ['NATIVE_OUTCOME']
 if outcome not in ['success','failure','cancelled','skipped'] or (outcome=='success' and not n['passed']):raise ValueError('outcome')
 files={f:root/f for f in ['Quarantine.ps1','Worker.ps1','Test-Quarantine.ps1']}
 files.update({'Journal.ps1':root.parent/'sstp-allowlist-backend/Journal.ps1','Firewall.ps1':root.parent/'sstp-allowlist-adapter/Firewall.ps1','Policy.ps1':root.parent/'sstp-allowlist-policy/Policy.ps1'})
 r=dict(schema='sstp-quarantine-build-2',source_commit=src,run_id=run,native_outcome=outcome,native=n,hashes={f:hashlib.sha256(p.read_bytes()).hexdigest() for f,p in files.items()},ready_for_user_apply=False)
 (root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
 if not n['passed']:sys.exit(1)
