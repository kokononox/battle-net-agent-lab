import json,os,re,sys
from pathlib import Path
BOOLS='setup_succeeded cleanup_attempted cleanup_succeeded independent_cleanup_armed timer_fallback_used profiles_exact selected_rules_exact cleanup_task_removed fixture_only user_device_tested ready_for_user_apply'.split()
COUNTS=dict(program_count=2,remote_address_count=32,rules_created=2,rules_removed=2,remaining_rules=2,fixture_checks=7)
KEYS=set(['schema','source_commit','run_id','error_code']+BOOLS+list(COUNTS))
def validate(r):
 if type(r) is not dict or set(r)!=KEYS or r['schema']!='sstp-ci-control-1':raise ValueError('schema')
 if not re.fullmatch('[a-f0-9]{40}',r['source_commit']) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('identity')
 if any(type(r[k]) is not bool for k in BOOLS):raise ValueError('bool')
 if r['fixture_only'] is not True or r['user_device_tested'] is not False or r['ready_for_user_apply'] is not False:raise ValueError('scope')
 for k,cap in COUNTS.items():
  if type(r[k]) is not int or not 0<=r[k]<=cap:raise ValueError('count')
 if r['error_code'] is not None and not re.fullmatch('ci_control_[a-z_]{1,80}',r['error_code']):raise ValueError('error')
 if r['setup_succeeded'] and (r['program_count']!=2 or r['rules_created']!=2 or r['remote_address_count']<1 or r['fixture_checks']!=7 or not r['independent_cleanup_armed']):raise ValueError('setup')
 if r['cleanup_succeeded'] and (not r['cleanup_attempted'] or r['remaining_rules']!=0 or r['timer_fallback_used'] or not all(r[k] for k in ['profiles_exact','selected_rules_exact','cleanup_task_removed'])):raise ValueError('cleanup')
 if r['setup_succeeded'] and r['cleanup_succeeded'] and r['rules_removed']!=2:raise ValueError('removed_count')
 return r
if __name__=='__main__':
 if sys.argv[1]=='--pack':
  target=Path(sys.argv[2])
  if not target.exists():
   r={k:False for k in BOOLS};r.update({k:0 for k in COUNTS});r.update(schema='sstp-ci-control-1',source_commit=os.environ['EXPECTED_COMMIT'],run_id=os.environ['EXPECTED_RUN_ID'],error_code='ci_control_no_receipt',fixture_only=True);target.write_text(json.dumps(r))
  sys.argv=[sys.argv[0],str(target),str(target)]
 a,b=map(Path,sys.argv[1:]);r=validate(json.loads(a.read_text(encoding='utf-8-sig')))
 if r['source_commit']!=os.environ['EXPECTED_COMMIT'] or r['run_id']!=os.environ['EXPECTED_RUN_ID']:raise ValueError('expected_identity')
 b.parent.mkdir(parents=True,exist_ok=True);b.write_text(json.dumps(r,indent=2)+'\n')
