"""Strict source-bound job supervisor receipts; no arbitrary paths or labels."""
import json,re,sys
from pathlib import Path
MODES={'fixture_timeout','fixture_network','fixture_disk','observe'}
STATUSES={'not_started','environment_refused','metrics_failed','launch_failed','assignment_failed','resume_failed','worker_completed','worker_failed','time_limit','network_limit','disk_limit','monitor_failed','cleanup_failed'}
FLAGS={'job_kill_on_close_configured','child_assigned_before_resume','child_resumed','termination_requested','job_drained','metrics_available','hard_network_byte_cap','game_transfer_requested'}
NUMS={'max_active_processes','final_active_processes','win32_error','elapsed_ms','time_limit_ms','network_threshold_bytes','network_delta_bytes','minimum_free_bytes','disk_reserve_bytes','poll_interval_ms'}
def identity(d):
 if type(d.get('source_commit'))is not str or not re.fullmatch('[0-9a-f]{40}',d['source_commit']) or type(d.get('run_id'))is not str or not re.fullmatch('[0-9]{1,30}',d['run_id']):raise ValueError('identity')
def receipt(r):
 keys={'schema','source_commit','run_id','mode','status','root_exit_code','network_scope'}|FLAGS|NUMS
 if type(r)is not dict or set(r)!=keys or r['schema']!='bnet-retail-supervisor-1' or r['mode']not in MODES or r['status']not in STATUSES:raise ValueError('receipt_schema')
 identity(r)
 for k in FLAGS:
  if type(r[k])is not bool:raise ValueError('flag')
 for k in NUMS:
  if type(r[k])is not int or not 0<=r[k]<=2**64-1:raise ValueError('number')
 if r['root_exit_code']is not None and(type(r['root_exit_code'])is not int or not 0<=r['root_exit_code']<2**32):raise ValueError('exit')
 fixture=r['mode']!='observe'
 if r['network_scope']!=('synthetic_fixture' if fixture else 'hostwide_adapter_counters') or r['poll_interval_ms']!=250 or r['time_limit_ms']!=(3000 if fixture else 240000) or r['network_threshold_bytes']!=(2 if r['mode']=='fixture_network' else 1073741824) or r['disk_reserve_bytes']!=10737418240:raise ValueError('limits')
 if r['hard_network_byte_cap']is not False or r['game_transfer_requested']is not False:raise ValueError('fixed')
 if r['child_resumed'] and not(r['child_assigned_before_resume'] and r['job_kill_on_close_configured']):raise ValueError('resume')
 if r['job_drained'] and (not r['termination_requested'] or r['final_active_processes']!=0):raise ValueError('drain')
 if r['status']=='worker_completed' and not(r['child_resumed'] and r['job_drained'] and r['metrics_available'] and r['root_exit_code']==0):raise ValueError('completed')
 return r
def fixture_passed(r):
 receipt(r);expected={'fixture_timeout':'time_limit','fixture_network':'network_limit','fixture_disk':'disk_limit'}
 return r['mode']in expected and r['status']==expected[r['mode']] and r['child_resumed'] and r['max_active_processes']>=2 and r['job_drained'] and r['termination_requested']
def blank(source,run):return dict(schema='bnet-retail-supervision-gate-1',source_commit=source,run_id=run,status='not_started',error_kind=None,fixtures={},observation=None)
def validate(r):
 if type(r)is not dict or set(r)!=set(blank('a'*40,'1')) or r['schema']!='bnet-retail-supervision-gate-1' or r['status']not in {'not_started','refused','completed'} or r['error_kind']not in {None,'build_failed','fixture_failed','native_failed','validation_failed','other'}:raise ValueError('gate_schema')
 identity(r)
 if type(r['fixtures'])is not dict or not set(r['fixtures'])<=MODES-{'observe'}:raise ValueError('fixtures')
 for k,v in r['fixtures'].items():
  receipt(v)
  if v['mode']!=k or any(v[x]!=r[x]for x in ('source_commit','run_id')):raise ValueError('fixture_identity')
 o=r['observation']
 if o is not None:
  receipt(o)
  if o['mode']!='observe' or any(o[x]!=r[x]for x in ('source_commit','run_id')) or set(r['fixtures'])!=MODES-{'observe'} or not all(fixture_passed(v)for v in r['fixtures'].values()):raise ValueError('gate_prerequisite')
 if r['status']=='completed' and(o is None or o['status']!='worker_completed' or not o['job_drained'] or r['error_kind']is not None):raise ValueError('gate_complete')
 return r
def read(path):
 raw=Path(path).read_bytes()
 if len(raw)>32768:raise ValueError('size')
 def unique(pairs):
  d={}
  for k,v in pairs:
   if k in d:raise ValueError('duplicate')
   d[k]=v
  return d
 return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('constant')))
if __name__=='__main__':
 r=validate(read(sys.argv[1]));p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
