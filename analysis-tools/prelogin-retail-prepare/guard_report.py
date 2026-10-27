"""Strict source-bound job supervisor receipts; no arbitrary paths or labels."""
import json,re,sys
from pathlib import Path
MODES={'fixture_timeout','fixture_network','fixture_disk','fixture_phase_timeout','fixture_phase_network','observe'}
STATUSES={'not_started','environment_refused','metrics_failed','launch_failed','assignment_failed','resume_failed','worker_completed','worker_failed','time_limit','network_limit','disk_limit','monitor_failed','cleanup_failed','phase_network_limit','phase_time_limit'}
FLAGS={'job_kill_on_close_configured','child_assigned_before_resume','child_resumed','termination_requested','job_drained','metrics_available','hard_network_byte_cap','game_transfer_request_proven_by_supervisor','transfer_phase_signal_seen'}
NUMS={'max_active_processes','final_active_processes','win32_error','elapsed_ms','time_limit_ms','network_threshold_bytes','network_delta_bytes','minimum_free_bytes','disk_reserve_bytes','poll_interval_ms','phase_elapsed_ms','phase_network_delta_bytes','phase_time_limit_ms','phase_network_threshold_bytes'}
def identity(d):
 if type(d.get('source_commit'))is not str or not re.fullmatch('[0-9a-f]{40}',d['source_commit']) or type(d.get('run_id'))is not str or not re.fullmatch('[0-9]{1,30}',d['run_id']):raise ValueError('identity')
DIAG_NUMS={'samples','interface_set_changes','counter_reset_intervals','last_sample_gap_ms','max_sample_gap_ms','last_sample_delta_bytes','max_sample_delta_bytes','phase_boundary_gap_ms','phase_boundary_delta_bytes'}
DIAG_FLAGS={'phase_boundary_observed','phase_boundary_interfaces_changed','phase_boundary_counter_reset'}
def validate_diagnostics(d):
 if type(d)is not dict or set(d)!=DIAG_NUMS|DIAG_FLAGS:raise ValueError('diagnostic_schema')
 for k in DIAG_NUMS:
  if type(d[k])is not int or not 0<=d[k]<=2**64-1:raise ValueError('diagnostic_number')
 for k in DIAG_FLAGS:
  if type(d[k])is not bool:raise ValueError('diagnostic_boolean')
 if any(d[k]>max(0,d['samples']-1)for k in ('interface_set_changes','counter_reset_intervals')):raise ValueError('diagnostic_intervals')
 if d['last_sample_gap_ms']>d['max_sample_gap_ms'] or d['last_sample_delta_bytes']>d['max_sample_delta_bytes']:raise ValueError('diagnostic_max')
 if d['phase_boundary_observed']:
  if d['samples']<2 or d['phase_boundary_gap_ms']>d['max_sample_gap_ms'] or d['phase_boundary_delta_bytes']>d['max_sample_delta_bytes']:raise ValueError('diagnostic_boundary')
  if d['phase_boundary_interfaces_changed'] and not d['interface_set_changes']:raise ValueError('diagnostic_change')
  if d['phase_boundary_counter_reset'] and not d['counter_reset_intervals']:raise ValueError('diagnostic_reset')
 elif any(d[k]for k in ('phase_boundary_gap_ms','phase_boundary_delta_bytes','phase_boundary_interfaces_changed','phase_boundary_counter_reset')):raise ValueError('diagnostic_no_boundary')
 if d['samples']<2 and any(d[k]for k in DIAG_NUMS-{'samples'}):raise ValueError('diagnostic_no_interval')
 return d

def receipt(r):
 keys={'schema','source_commit','run_id','mode','status','root_exit_code','network_scope'}|FLAGS|NUMS
 if type(r)is dict and r.get('schema')=='bnet-retail-supervisor-3':keys=keys|{'network_diagnostics'}
 if type(r)is not dict or set(r)!=keys or r['schema']not in {'bnet-retail-supervisor-2','bnet-retail-supervisor-3'} or r['mode']not in MODES or r['status']not in STATUSES:raise ValueError('receipt_schema')
 identity(r)
 if r['schema']=='bnet-retail-supervisor-3':
  d=validate_diagnostics(r['network_diagnostics'])
  if d['phase_boundary_observed'] and (not r['transfer_phase_signal_seen'] or r['mode']!='observe'):raise ValueError('diagnostic_phase_scope')
 for k in FLAGS:
  if type(r[k])is not bool:raise ValueError('flag')
 for k in NUMS:
  if type(r[k])is not int or not 0<=r[k]<=2**64-1:raise ValueError('number')
 if r['root_exit_code']is not None and(type(r['root_exit_code'])is not int or not 0<=r['root_exit_code']<2**32):raise ValueError('exit')
 fixture=r['mode']!='observe'
 if r['network_scope']!=('synthetic_fixture' if fixture else 'hostwide_adapter_counters') or r['poll_interval_ms']!=250 or r['time_limit_ms']!=(3000 if fixture else 240000) or r['network_threshold_bytes']!=(2 if r['mode']=='fixture_network' else 1073741824) or r['disk_reserve_bytes']!=10737418240:raise ValueError('limits')
 if r['hard_network_byte_cap']is not False or r['game_transfer_request_proven_by_supervisor']is not False:raise ValueError('fixed')
 if r['phase_time_limit_ms']!=30000 or r['phase_network_threshold_bytes']!=67108864:raise ValueError('phase_limits')
 if not r['transfer_phase_signal_seen'] and (r['phase_elapsed_ms'] or r['phase_network_delta_bytes']):raise ValueError('phase_unobserved')
 if r['child_resumed'] and not(r['child_assigned_before_resume'] and r['job_kill_on_close_configured']):raise ValueError('resume')
 if r['job_drained'] and (not r['termination_requested'] or r['final_active_processes']!=0):raise ValueError('drain')
 if r['status']=='worker_completed' and not(r['child_resumed'] and r['job_drained'] and r['metrics_available'] and r['root_exit_code']==0):raise ValueError('completed')
 return r
def fixture_passed(r):
 receipt(r);expected={'fixture_timeout':'time_limit','fixture_network':'network_limit','fixture_disk':'disk_limit','fixture_phase_timeout':'phase_time_limit','fixture_phase_network':'phase_network_limit'}
 return r['mode']in expected and r['status']==expected[r['mode']] and r['child_resumed'] and r['max_active_processes']>=2 and r['job_drained'] and r['termination_requested']
def blank_build():return dict(stage='not_started',vswhere_exit_code=None,installation_found=False,devcmd_found=False,compiler_exit_code=None,compiler_error_codes=[],source_error_lines=[])
def validate_build(b):
 if type(b)is not dict or set(b)!=set(blank_build()) or b['stage']not in {'not_started','vswhere_query','vswhere_refused','devcmd_missing','compile','compiled'}:raise ValueError('build_schema')
 for k in ('vswhere_exit_code','compiler_exit_code'):
  if b[k]is not None and(type(b[k])is not int or not -2**31<=b[k]<2**32):raise ValueError('build_exit')
 for k in ('installation_found','devcmd_found'):
  if type(b[k])is not bool:raise ValueError('build_bool')
 if type(b['compiler_error_codes'])is not list or len(b['compiler_error_codes'])>8 or any(type(x)is not str or not re.fullmatch(r'(?:C|D)[0-9]{4}|LNK[0-9]{4}',x)for x in b['compiler_error_codes']):raise ValueError('build_codes')
 if type(b['source_error_lines'])is not list or len(b['source_error_lines'])>8 or any(type(x)is not int or not 1<=x<=10000 for x in b['source_error_lines']):raise ValueError('build_lines')
 if b['stage']=='compiled' and not(b['installation_found'] and b['devcmd_found'] and b['compiler_exit_code']==0):raise ValueError('compiled_evidence')
 return b
def blank(source,run):return dict(build=blank_build(),schema='bnet-retail-supervision-gate-3',source_commit=source,run_id=run,status='not_started',error_kind=None,fixtures={},observation=None)
def validate(r):
 if type(r)is not dict or set(r)!=set(blank('a'*40,'1')) or r['schema']!='bnet-retail-supervision-gate-3' or r['status']not in {'not_started','refused','completed'} or r['error_kind']not in {None,'build_failed','fixture_failed','native_failed','validation_failed','other'}:raise ValueError('gate_schema')
 identity(r)
 validate_build(r['build'])
 if type(r['fixtures'])is not dict or not set(r['fixtures'])<=MODES-{'observe'}:raise ValueError('fixtures')
 for k,v in r['fixtures'].items():
  receipt(v)
  if v['mode']!=k or any(v[x]!=r[x]for x in ('source_commit','run_id')):raise ValueError('fixture_identity')
 o=r['observation']
 if o is not None:
  if r['build']['stage']!='compiled':raise ValueError('build_prerequisite')
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
