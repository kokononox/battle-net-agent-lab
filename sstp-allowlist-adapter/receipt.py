import hashlib,json,os,re,sys
from pathlib import Path
FLAGS='effective_network_policy_changed dns_queried resident_program_created enforcement_tested sstp_binding_tested user_device_tested ready_for_user_apply'.split()
KEYS=set('schema source_commit run_id passed checks error_code disabled_rules_created remaining_test_rules profiles_unchanged existing_rule_properties_unchanged'.split()+FLAGS)
def validate(n):
 if type(n) is not dict or set(n)!=KEYS or n['schema']!='sstp-adapter-test-1':raise ValueError('schema')
 if not re.fullmatch('[a-f0-9]{40}',n['source_commit']) or not re.fullmatch('[0-9]{1,30}',n['run_id']):raise ValueError('identity')
 if type(n['passed']) is not bool or type(n['checks']) is not int or not 0<=n['checks']<=29:raise ValueError('counts')
 if any(n[k] is not False for k in FLAGS):raise ValueError('scope')
 for k in ['disabled_rules_created','profiles_unchanged','existing_rule_properties_unchanged']:
  if type(n[k]) is not bool:raise ValueError('bool')
 if type(n['remaining_test_rules']) is not int or not -1<=n['remaining_test_rules']<=4:raise ValueError('remaining')
 if n['error_code'] not in [None,'adapter_native_failure','adapter_native_unavailable','adapter_baseline_mismatch']:raise ValueError('error')
 if n['passed'] and (n['checks']!=29 or n['error_code'] is not None or not n['disabled_rules_created'] or n['remaining_test_rules']!=0 or not n['profiles_unchanged'] or not n['existing_rule_properties_unchanged']):raise ValueError('pass')
 return n
if __name__=='__main__':
 root=Path(__file__).parent;src=os.environ['GITHUB_SHA'];run=os.environ['GITHUB_RUN_ID'];p=Path(os.environ['RUNNER_TEMP'])/'adapter-native.json'
 n=json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else dict(schema='sstp-adapter-test-1',source_commit=src,run_id=run,passed=False,checks=0,error_code='adapter_native_unavailable',disabled_rules_created=False,remaining_test_rules=-1,profiles_unchanged=False,existing_rule_properties_unchanged=False,**{k:False for k in FLAGS})
 validate(n)
 if n['source_commit']!=src or n['run_id']!=run:raise ValueError('expected_identity')
 outcome=os.environ['NATIVE_OUTCOME']
 if outcome not in ['success','failure','cancelled','skipped'] or (outcome=='success' and not n['passed']):raise ValueError('outcome')
 paths={'Firewall.ps1':root/'Firewall.ps1','Test-Firewall.ps1':root/'Test-Firewall.ps1','Policy.ps1':root.parent/'sstp-allowlist-policy/Policy.ps1'}
 r=dict(schema='sstp-adapter-build-1',source_commit=src,run_id=run,native_outcome=outcome,native=n,hashes={f:hashlib.sha256(p.read_bytes()).hexdigest() for f,p in paths.items()},ready_for_user_apply=False)
 (root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
 if not n['passed']:sys.exit(1)
