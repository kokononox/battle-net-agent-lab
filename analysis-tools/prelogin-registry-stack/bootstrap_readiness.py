"""Allowlisted counts/labels only; never raw UI, UUID, address or path."""
import json,re,sys
from pathlib import Path
STATUS={'not_observed','stopped','agent_process_observed','bootstrapper_observed_agent_not_observed','other'}
LANG={'not_observed','pending','no_targets','continued','page_not_language','ambiguous_window','process_mismatch','window_mismatch','timeout','helper_failed','other'}
NAMES={'agent.exe','battle.net.exe','battle.net launcher.exe','battle.net-setup.exe','battle.net helper.exe','blizzarderror.exe'}
FLAGS=('helper_started','selection_attempted','selection_confirmed','continue_attempted','continue_returned','outcome_uncertain')
def blank(source,run):
 return dict(schema='bnet-bootstrap-readiness-1',source_commit=source,run_id=run,status='not_observed',language_status='not_observed',sample_count=0,gui_snapshot_count=0,observed_names=[],language_flags={k:False for k in FLAGS},bounded_wait_seconds=150,no_target_only_polling=True,install_action_requested=False,login_performed=False,raw_values_exported=False)
def fold(base,source,run):
 r=blank(source,run);r['status']=base.get('status') if base.get('status') in STATUS else 'other'
 l=base.get('language_step',{});r['language_status']=l.get('status') if l.get('status') in LANG else 'other'
 r['language_flags']={k:l.get(k) is True for k in FLAGS}
 samples=base.get('samples',[]);r['sample_count']=len(samples);r['gui_snapshot_count']=len(base.get('gui_observations',[]))
 r['observed_names']=sorted({p['name'] for s in samples for p in s.get('processes',[]) if p.get('name') in NAMES})
 return validate(r)
def validate(r):
 if type(r) is not dict or set(r)!=set(blank('a'*40,'1')):raise ValueError('schema')
 if r['schema']!='bnet-bootstrap-readiness-1' or type(r['source_commit']) is not str or not re.fullmatch('[0-9a-f]{40}',r['source_commit']) or type(r['run_id']) is not str or not re.fullmatch('[0-9]{1,24}',r['run_id']):raise ValueError('identity')
 if r['status'] not in STATUS or r['language_status'] not in LANG:raise ValueError('label')
 for k,cap in [('sample_count',30),('gui_snapshot_count',3)]:
  if type(r[k]) is not int or not 0<=r[k]<=cap:raise ValueError('count')
 if type(r['observed_names']) is not list or len(r['observed_names'])>6 or any(type(n) is not str or n not in NAMES for n in r['observed_names']) or len(set(r['observed_names']))!=len(r['observed_names']):raise ValueError('names')
 if type(r['language_flags']) is not dict or set(r['language_flags'])!=set(FLAGS) or any(type(v) is not bool for v in r['language_flags'].values()):raise ValueError('flags')
 if type(r['bounded_wait_seconds']) is not int or r['bounded_wait_seconds']!=150 or r['no_target_only_polling'] is not True:raise ValueError('policy')
 if any(r[k] is not False for k in ('install_action_requested','login_performed','raw_values_exported')):raise ValueError('scope')
 return r
def load(raw):
 if len(raw)>8192:raise ValueError('size')
 def unique(pairs):
  d={}
  for k,v in pairs:
   if k in d:raise ValueError('duplicate')
   d[k]=v
  return d
 return validate(json.loads(raw,object_pairs_hook=unique))
if __name__=='__main__':
 r=load(Path(sys.argv[1]).read_bytes());p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
