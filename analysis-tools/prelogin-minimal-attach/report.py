"""Typed minimal-attach control; no raw paths, IDs, UUIDs or UI text."""
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT/'analysis-tools'/'prelogin-registry-stack'))
from bootstrap_readiness import blank as ready_blank,validate as ready_validate,fold as ready_fold
from attach_session import blank as attach_blank,ERRORS
EXIT={'not_launched','running','exited_zero','exited_nonzero','unknown'}
GCOUNTS={'same_session_processes':24,'different_session_processes':24,'unknown_session_processes':24,'owned_windows':8,'visible_owned_windows':8,'probe_errors':200}
def gui(g):
 observer=g.get('observer_session_id');same=diff=unknown=0
 for p in g.get('process_sessions',[]):
  s=p.get('session_id')
  if type(observer) is not int or type(s) is not int:unknown+=1
  elif s==observer:same+=1
  else:diff+=1
 windows=g.get('windows',[])
 r=dict(window_station_visible=g.get('window_station_visible') if type(g.get('window_station_visible')) is bool else None,input_desktop_accessible=g.get('input_desktop_accessible') is True,same_session_processes=same,different_session_processes=diff,unknown_session_processes=unknown,owned_windows=len(windows),visible_owned_windows=sum(w.get('visible') is True for w in windows),enumeration_truncated=g.get('enumeration_truncated') is True,probe_errors=g.get('probe_errors',0))
 return valid_gui(r)
def valid_gui(g):
 if type(g) is not dict or set(g)!={*GCOUNTS,'window_station_visible','input_desktop_accessible','enumeration_truncated'}:raise ValueError('gui_fields')
 if g['window_station_visible'] is not None and type(g['window_station_visible']) is not bool:raise ValueError('station')
 if any(type(g[k]) is not bool for k in ('input_desktop_accessible','enumeration_truncated')):raise ValueError('gui_bool')
 for k,cap in GCOUNTS.items():
  if type(g[k]) is not int or not 0<=g[k]<=cap:raise ValueError('gui_count')
 if g['visible_owned_windows']>g['owned_windows'] or sum(g[k] for k in ('same_session_processes','different_session_processes','unknown_session_processes'))>24:raise ValueError('gui_relation')
 return g
def blank(source,run):
 return dict(schema='bnet-minimal-attach-control-1',source_commit=source,run_id=run,status='not_started',native_gate=[],bootstrap_pin_match=None,target_launched=False,error_kind=None,readiness=ready_blank(source,run),desktop_observations=[],root_samples=dict(running=0,exited_zero=0,exited_nonzero=0,unknown=0),root_state_before_cleanup='not_launched',target_attach=attach_blank(),limits=dict(target_scope='bootstrap_only',ordinary_popen_launch=True,frida_attach_requested=True,registry_hook_requested=False,network_hook_requested=False,child_gating_requested=False,suspended_spawn_requested=False,process_birth_coverage=False,account_login_requested=False,install_action_requested=False,game_download_requested=False,remote_access_enabled=False,raw_values_exported=False,network_payload_observed=False,observer_causality_proven=False,same_host_as_b2=False))
def valid_attach(a):
 if type(a) is not dict or set(a)!=set(attach_blank()):raise ValueError('attach_fields')
 if a['status'] not in {'not_started','ready','failed'} or a['error_kind'] not in ERRORS:raise ValueError('attach_label')
 for k in ('attach_returned','image_verified_before_and_after','ready','bitness_confirmed'):
  if type(a[k]) is not bool:raise ValueError('attach_bool')
 if a['pointer_bits'] is not None and (type(a['pointer_bits']) is not int or a['pointer_bits'] not in (32,64)):raise ValueError('attach_bits')
 if type(a['message_errors']) is not int or not 0<=a['message_errors']<=128:raise ValueError('attach_errors')
 if a['ready'] and (not a['attach_returned'] or a['pointer_bits'] not in (32,64)):raise ValueError('attach_ready')
 if a['status']=='ready' and (a['error_kind'] is not None or a['message_errors']!=0 or not all(a[k] for k in ('attach_returned','image_verified_before_and_after','ready','bitness_confirmed'))):raise ValueError('attach_clean')
 if a['status']=='not_started' and a!=attach_blank():raise ValueError('attach_unstarted')
 return a

def native_passed(rows):return len(rows)==2 and {x['architecture'] for x in rows}=={'x86','x64'} and all(x['passed'] for x in rows)
def fold(base,r):
 r['readiness']=ready_fold(base,r['source_commit'],r['run_id']);r['desktop_observations']=[gui(g) for g in base.get('gui_observations',[])];return r

def validate(r):
 if type(r) is not dict or set(r)!=set(blank('a'*40,'1')) or r['schema']!='bnet-minimal-attach-control-1':raise ValueError('fields')
 ready_validate(r['readiness'])
 if r['source_commit']!=r['readiness']['source_commit'] or r['run_id']!=r['readiness']['run_id']:raise ValueError('identity')
 if r['status'] not in {'not_started','native_gate_failed_no_target','observation_complete','stopped'} or r['error_kind'] not in ERRORS:raise ValueError('label')
 if type(r['native_gate']) is not list or len(r['native_gate'])>2:raise ValueError('native_count')
 seen=set()
 for n in r['native_gate']:
  if type(n) is not dict or set(n)!={'architecture','passed','exit_code','attach','error_kind'} or n['architecture'] not in {'x86','x64'} or n['architecture'] in seen:raise ValueError('native_schema')
  seen.add(n['architecture'])
  if type(n['passed']) is not bool or n['error_kind'] not in ERRORS:raise ValueError('native_types')
  if n['exit_code'] is not None and (type(n['exit_code']) is not int or not -2**31<=n['exit_code']<2**32):raise ValueError('native_exit')
  if n['attach'] is not None:valid_attach(n['attach'])
  good=n['attach'] is not None and n['attach']['status']=='ready' and n['attach']['pointer_bits']==(32 if n['architecture']=='x86' else 64) and n['exit_code']==0 and n['error_kind'] is None
  if n['passed']!=good:raise ValueError('native_claim')
 if r['bootstrap_pin_match'] is not None and type(r['bootstrap_pin_match']) is not bool:raise ValueError('pin')
 if type(r['target_launched']) is not bool or (r['target_launched'] and (r['bootstrap_pin_match'] is not True or not native_passed(r['native_gate']))):raise ValueError('launch')
 valid_attach(r['target_attach'])
 if r['target_attach']['status']=='ready' and r['target_attach']['pointer_bits']!=32:raise ValueError('target_bitness')
 if not r['target_launched'] and r['target_attach']!=attach_blank():raise ValueError('unlaunched_attach')
 if r['root_state_before_cleanup'] not in EXIT:raise ValueError('root_state')
 if type(r['desktop_observations']) is not list or len(r['desktop_observations'])>3:raise ValueError('gui_count')
 for g in r['desktop_observations']:valid_gui(g)
 if type(r['root_samples']) is not dict or set(r['root_samples'])!={'running','exited_zero','exited_nonzero','unknown'} or any(type(v) is not int or not 0<=v<=128 for v in r['root_samples'].values()) or sum(r['root_samples'].values())>128:raise ValueError('root_samples')
 if not r['target_launched'] and (r['root_state_before_cleanup']!='not_launched' or sum(r['root_samples'].values())):raise ValueError('unlaunched')
 expected=blank('a'*40,'1')['limits']
 if type(r['limits']) is not dict or set(r['limits'])!=set(expected) or any(type(r['limits'][k]) is not type(v) or r['limits'][k]!=v for k,v in expected.items()):raise ValueError('limits')
 if r['status']=='native_gate_failed_no_target' and (r['target_launched'] or native_passed(r['native_gate'])):raise ValueError('gate_claim')
 if r['status']=='observation_complete' and (not r['target_launched'] or not native_passed(r['native_gate']) or r['error_kind'] is not None or r['readiness']['status'] in {'not_observed','stopped'}):raise ValueError('complete')
 return r

def load(raw):
 if len(raw)>24576:raise ValueError('size')
 def unique(pairs):
  d={}
  for k,v in pairs:
   if k in d:raise ValueError('duplicate')
   d[k]=v
  return d
 return validate(json.loads(raw,object_pairs_hook=unique))
if __name__=='__main__':
 r=load(Path(sys.argv[1]).read_bytes());p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
