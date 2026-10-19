import hashlib,json,os,re,sys
from pathlib import Path
FLAGS='tool_firewall_mutations fixture_rules_created dns_queried user_device_tested enforcement_tested ready_for_user_apply'.split()
KEYS=set('schema source_commit run_id completed pure_checks error_code elapsed_seconds changed_rule_union_count samples'.split()+FLAGS)
def integer(v,lo,hi):
 if type(v) is not int or not lo<=v<=hi:raise ValueError('integer')
def delta(d):
 if type(d) is not dict or set(d)!=set('added removed modified property_names display_kind_transitions'.split()):raise ValueError('delta_schema')
 for k in ['added','removed','modified']:integer(d[k],0,10000)
 if type(d['property_names']) is not list or len(d['property_names'])>128 or any(type(v) is not str or not re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,80}',v) for v in d['property_names']):raise ValueError('field_names')
 if type(d['display_kind_transitions']) is not list or len(d['display_kind_transitions'])>27:raise ValueError('kinds')
 for t in d['display_kind_transitions']:
  if type(t) is not dict or set(t)!=set('property_name before_kind after_kind item_count'.split()) or t['property_name'] not in ['Description','DisplayGroup','DisplayName']:raise ValueError('transition')
  if any(t[k] not in ['empty','resource_reference','literal'] for k in ['before_kind','after_kind']):raise ValueError('kind')
  integer(t['item_count'],1,10000)
def validate(n):
 if type(n) is not dict or set(n)!=KEYS or n['schema']!='sstp-rule-readonly-control-1':raise ValueError('schema')
 if not re.fullmatch('[a-f0-9]{40}',n['source_commit']) or not re.fullmatch('[0-9]{1,30}',n['run_id']):raise ValueError('identity')
 if type(n['completed']) is not bool or any(n[k] is not False for k in FLAGS):raise ValueError('scope')
 integer(n['pure_checks'],0,5);integer(n['elapsed_seconds'],0,890);integer(n['changed_rule_union_count'],0,10000)
 if n['error_code'] not in [None,'control_read_failed','control_unavailable']:raise ValueError('error')
 if type(n['samples']) is not list or len(n['samples'])>13:raise ValueError('samples')
 last=-1
 for i,s in enumerate(n['samples']):
  if type(s) is not dict or set(s)!=set('sequence elapsed_seconds rule_count baseline_delta previous_delta profiles_equal_to_baseline'.split()):raise ValueError('sample_schema')
  if type(s['sequence']) is not int or s['sequence']!=i:raise ValueError('sequence')
  integer(s['elapsed_seconds'],0,890);integer(s['rule_count'],1,10000)
  if s['elapsed_seconds']<last or type(s['profiles_equal_to_baseline']) is not bool:raise ValueError('sample_order')
  last=s['elapsed_seconds'];delta(s['baseline_delta']);delta(s['previous_delta'])
 if n['completed'] and (len(n['samples'])!=13 or n['pure_checks']!=5 or n['elapsed_seconds']<660 or n['samples'][-1]['elapsed_seconds']<660 or n['error_code'] is not None):raise ValueError('completion')
 return n
if __name__=='__main__':
 root=Path(__file__).parent;src=os.environ['GITHUB_SHA'];run=os.environ['GITHUB_RUN_ID'];p=Path(os.environ['RUNNER_TEMP'])/'readonly-control.json'
 n=json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else dict(schema='sstp-rule-readonly-control-1',source_commit=src,run_id=run,completed=False,pure_checks=0,error_code='control_unavailable',elapsed_seconds=0,changed_rule_union_count=0,samples=[],**{k:False for k in FLAGS})
 validate(n)
 if n['source_commit']!=src or n['run_id']!=run:raise ValueError('expected_identity')
 outcome=os.environ['NATIVE_OUTCOME']
 if outcome not in ['success','failure','cancelled','skipped'] or (outcome=='success' and not n['completed']):raise ValueError('outcome')
 r=dict(schema='sstp-rule-readonly-control-build-1',source_commit=src,run_id=run,native_outcome=outcome,native=n,hashes={f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in ['Control.ps1','receipt.py']},ready_for_user_apply=False)
 (root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
 if not n['completed']:sys.exit(1)
