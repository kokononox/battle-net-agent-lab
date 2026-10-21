"""Bounded, local-only history baseline and recovery of manual live labels. No DNS or rule writes."""
import re
from capture_store import MAX_HISTORY,STAGES
MAX_HISTORY_KEYS=20000

def destination_key(row):return row['ip'].lower()+'|'+str(row['port'])+'|TCP'
def history_baseline(store):
 paths=[p for p in store.output.glob('destinations-*.json') if re.fullmatch(r'destinations-[a-f0-9]{32}\.json',p.name)]
 paths.sort(key=lambda p:p.stat().st_mtime,reverse=True);seen=set();invalid=0;examined=0;complete=len(paths)<=MAX_HISTORY;source_truncated=False
 for path in paths[:MAX_HISTORY]:
  try:
   c=store.read(path.name[13:-5]);examined+=1
   if c['truncated']:complete=False;source_truncated=True
   prior_rows=c['endpoints']+[e for e in c.get('event_evidence',{}).get('events',[]) if e['kind']=='wfp_connection_block' and e.get('protocol')=='TCP']
   for row in prior_rows:
    key=destination_key(row)
    if len(seen)>=MAX_HISTORY_KEYS and key not in seen:complete=False;break
    seen.add(key)
   if len(seen)>=MAX_HISTORY_KEYS:complete=False;break
  except (OSError,ValueError,TypeError,KeyError):invalid+=1;complete=False
 return dict(keys=sorted(seen),complete=complete,files_total=len(paths),files_examined=examined,invalid_files=invalid,source_truncated=source_truncated,max_files=MAX_HISTORY,max_keys=MAX_HISTORY_KEYS,scope='local_saved_Wow_TCP_and_WFP_attempts_IP_port_not_process',not_global_history=True)

def clean_baseline(raw):
 if not isinstance(raw,dict):return dict(complete=False,scope='not_recorded')
 out={k:raw[k] for k in ('files_total','files_examined','invalid_files','max_files','max_keys') if type(raw.get(k)) is int and raw[k]>=0}
 return dict(**out,complete=raw.get('complete') is True,source_truncated=raw.get('source_truncated') is True,scope='local_saved_Wow_TCP_and_WFP_attempts_IP_port_not_process',not_global_history=True)

def recover_live_labels(manager,ident):
 path=manager.private/('job-'+ident+'.live-labels.json')
 if not path.exists():return dict(state='no_live_labels',saved=0)
 import json
 try:
  with path.open('rb') as f:data=f.read(1024*1024+1)
  if len(data)>1024*1024:raise ValueError('large')
  raw=json.loads(data.decode('utf-8-sig'))
  if raw.get('schema')!='wow-live-labels-1' or raw.get('capture_id')!=ident or not isinstance(raw.get('entries'),dict):raise ValueError('invalid')
  deleted=raw.get('deleted_record_ids',[])
  if deleted:manager.captures.delete_records(ident,deleted,True)
  entries={k:v for k,v in raw['entries'].items() if k not in deleted}
  result=manager.captures.save_annotations(ident,entries);return dict(state='saved',saved=result['changed'],deleted=len(deleted))
 except (OSError,ValueError,TypeError,KeyError,AttributeError):return dict(state='unavailable_or_invalid_journal_retained',saved=0)
