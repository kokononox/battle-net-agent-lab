import json,re,hashlib,os,sys
from pathlib import Path
FALSE_FLAGS='firewall_mutations mutation_modules_imported enforcement_tested user_device_tested ready_for_user_apply'.split()
KEYS=set('schema source_commit run_id passed error_code checks raw_field_cases filter_types_tested owned_display_cases missing_filter_cases association_checks native_rule_count native_display_changes read_only'.split()+FALSE_FLAGS)
def integer(v,lo,hi):
 if type(v) is not int or not lo<=v<=hi:raise ValueError('integer')
def validate(n):
 if type(n) is not dict or set(n)!=KEYS or n['schema']!='sstp-policy-compare-test-1':raise ValueError('schema')
 if not re.fullmatch('[a-f0-9]{40}',n['source_commit']) or not re.fullmatch('[0-9]{1,30}',n['run_id']):raise ValueError('identity')
 if type(n['passed']) is not bool or n['read_only'] is not True or any(n[k] is not False for k in FALSE_FLAGS):raise ValueError('scope')
 for k,hi in [('checks',2000),('raw_field_cases',1500),('filter_types_tested',7),('owned_display_cases',3),('missing_filter_cases',7),('association_checks',42)]:integer(n[k],0,hi)
 integer(n['native_rule_count'],-1,10000);integer(n['native_display_changes'],-1,10000)
 if n['error_code'] not in [None,'inventory_native_failure','inventory_native_unavailable']:raise ValueError('error')
 if n['passed'] and (n['checks']!=n['raw_field_cases']+70 or n['raw_field_cases']<50 or n['filter_types_tested']!=7 or n['owned_display_cases']!=3 or n['missing_filter_cases']!=7 or n['association_checks']!=42 or n['native_rule_count']<6 or n['native_display_changes']<0 or n['error_code'] is not None):raise ValueError('pass')
 return n
if __name__=='__main__':
 root=Path(__file__).parent;src=os.environ['GITHUB_SHA'];run=os.environ['GITHUB_RUN_ID'];p=Path(os.environ['RUNNER_TEMP'])/'policy-compare.json'
 n=json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else dict(schema='sstp-policy-compare-test-1',source_commit=src,run_id=run,passed=False,error_code='inventory_native_unavailable',checks=0,raw_field_cases=0,filter_types_tested=0,owned_display_cases=0,missing_filter_cases=0,association_checks=0,native_rule_count=-1,native_display_changes=-1,read_only=True,**{k:False for k in FALSE_FLAGS})
 validate(n)
 if n['source_commit']!=src or n['run_id']!=run:raise ValueError('expected_identity')
 outcome=os.environ['NATIVE_OUTCOME']
 if outcome not in ['success','failure','cancelled','skipped'] or (outcome=='success' and not n['passed']):raise ValueError('outcome')
 r=dict(schema='sstp-policy-compare-build-1',source_commit=src,run_id=run,native_outcome=outcome,native=n,hashes={f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in ['Inventory.ps1','Test-Inventory.ps1','receipt.py']},ready_for_user_apply=False)
 (root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
 if not n['passed']:sys.exit(1)
