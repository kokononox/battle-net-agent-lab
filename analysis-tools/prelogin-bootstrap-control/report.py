"""Counts and fixed labels only. Session IDs/PIDs/paths/UI text are private."""
import json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT/'analysis-tools'/'prelogin-registry-stack'))
from bootstrap_readiness import blank as ready_blank,validate as ready_validate,fold as ready_fold
EXIT={'not_launched','running','exited_zero','exited_nonzero','unknown'}
ERROR={None,'pin_mismatch','frida_present','OSError','ValueError','RuntimeError','LabError','other'}
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
 return dict(schema='bnet-bootstrap-control-1',source_commit=source,run_id=run,bootstrap_pin_match=None,target_launched=False,error_kind=None,readiness=ready_blank(source,run),desktop_observations=[],root_samples=dict(running=0,exited_zero=0,exited_nonzero=0,unknown=0),root_state_before_cleanup='not_launched',limits=dict(frida_imported=False,injection_requested=False,account_login_requested=False,install_action_requested=False,game_download_requested=False,remote_access_enabled=False,raw_values_exported=False,network_payload_observed=False,observer_causality_proven=False,same_host_as_a12d=False))
def fold(base,r):
 r['readiness']=ready_fold(base,r['source_commit'],r['run_id']);r['desktop_observations']=[gui(g) for g in base.get('gui_observations',[])]
 return validate(r)
def validate(r):
 if type(r) is not dict or set(r)!=set(blank('a'*40,'1')):raise ValueError('fields')
 if r['schema']!='bnet-bootstrap-control-1':raise ValueError('schema')
 ready_validate(r['readiness'])
 if r['source_commit']!=r['readiness']['source_commit'] or r['run_id']!=r['readiness']['run_id']:raise ValueError('identity')
 if r['bootstrap_pin_match'] is not None and type(r['bootstrap_pin_match']) is not bool:raise ValueError('pin')
 if type(r['target_launched']) is not bool or (r['target_launched'] and r['bootstrap_pin_match'] is not True):raise ValueError('launch')
 if r['error_kind'] not in ERROR or r['root_state_before_cleanup'] not in EXIT:raise ValueError('label')
 if type(r['desktop_observations']) is not list or len(r['desktop_observations'])>3:raise ValueError('gui_count')
 for g in r['desktop_observations']:valid_gui(g)
 if type(r['root_samples']) is not dict or set(r['root_samples'])!={'running','exited_zero','exited_nonzero','unknown'}:raise ValueError('states')
 if any(type(v) is not int or not 0<=v<=128 for v in r['root_samples'].values()) or sum(r['root_samples'].values())>128:raise ValueError('sample_count')
 if type(r['limits']) is not dict or r['limits']!=blank('a'*40,'1')['limits'] or any(v is not False for v in r['limits'].values()):raise ValueError('limits')
 if not r['target_launched'] and (r['root_state_before_cleanup']!='not_launched' or sum(r['root_samples'].values())):raise ValueError('unlaunched')
 return r
def load(raw):
 if len(raw)>16384:raise ValueError('size')
 def unique(pairs):
  d={}
  for k,v in pairs:
   if k in d:raise ValueError('duplicate')
   d[k]=v
  return d
 return validate(json.loads(raw,object_pairs_hook=unique))
if __name__=='__main__':
 r=load(Path(sys.argv[1]).read_bytes());p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
