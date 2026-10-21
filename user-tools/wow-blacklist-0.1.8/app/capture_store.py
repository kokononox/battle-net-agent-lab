"""Local capture history and manual context annotations. Original recordings stay unchanged."""
import datetime,hashlib,json,re,time,math
from pathlib import Path
from observation_model import normalize_rows,timestamp,classify_rows
STAGES={'unknown':'نامشخص','launch':'لانچ برنامه','login':'ورود','dashboard':'داشبورد','in_game':'محیط بازی','multi_stage':'چند مرحله'}
CAPTURE_ID=re.compile(r'^[a-f0-9]{32}$')
MAX_CAPTURE_BYTES=16*1024*1024
MAX_HISTORY=200

def utc_now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def finite_number(value):return value if type(value) in (int,float) and math.isfinite(value) else None
def row_key(row):return str(row['pid'])+'|'+row['process_started_utc']+'|'+row['ip'].lower()+'|'+str(row['port'])+'|TCP'

def stage_codes(value):
 if isinstance(value,str):value=[] if value=='unknown' else [value]
 if not isinstance(value,list) or len(value)>30 or any(not isinstance(x,str) or x not in STAGES for x in value):raise ValueError('invalid_stage_annotation_target_or_value')
 return [x for x in STAGES if x!='unknown' and x in value]
def legacy_stage(codes):return codes[0] if len(codes)==1 else ('multi_stage' if codes else 'unknown')
def stage_identity(row):
 if row.get('kind')=='dns_query':return 'dns|'+row['domain'].lower()
 return row['ip'].lower()+'|'+str(row['port'])+'|'+row.get('protocol','TCP')

def clean_snapshot(raw,parse_entries):
 if not isinstance(raw,dict) or raw.get('available') is not True:return dict(available=False,entries=[],reason='not_recorded_or_unverified',packet_drop_verified=False)
 entries=[];rejected=0
 for item in raw.get('entries',[])[:1000]:
  try:entries.extend(parse_entries([item]))
  except (ValueError,KeyError,TypeError):rejected+=1
 return dict(available=True,entries=entries,checked_utc=timestamp(raw.get('checked_utc')),checked_utc_epoch=finite_number(raw.get('checked_utc_epoch')),unverified_owned_count=max(0,int(raw.get('unverified_owned_count',0)))+rejected,scope='this_installation_selected_program_only',packet_drop_verified=False,source='saved_capture_snapshot_not_live_reverified')

class CaptureStore:
 def __init__(self,root,atomic,parse_entries):
  self.root=Path(root);self.output=self.root/'output';self.private=self.root/'private-state';self.atomic=atomic;self.parse_entries=parse_entries
 def capture_path(self,ident):
  if not isinstance(ident,str) or not CAPTURE_ID.fullmatch(ident):raise ValueError('invalid_capture_id')
  return self.output/('destinations-'+ident+'.json')
 def read(self,ident,include_history=True):
  path=self.capture_path(ident)
  with path.open('rb') as f:raw_bytes=f.read(MAX_CAPTURE_BYTES+1)
  if len(raw_bytes)>MAX_CAPTURE_BYTES:raise ValueError('capture_too_large')
  raw=json.loads(raw_bytes.decode('utf-8-sig'))
  if not isinstance(raw,dict) or raw.get('schema') not in {'wow-blacklist-destinations-1','wow-blacklist-destinations-2'} or raw.get('classification_only') is True:raise ValueError('invalid_capture_schema')
  sha=raw.get('program_sha256')
  if not isinstance(sha,str) or not re.fullmatch('[a-f0-9]{64}',sha):raise ValueError('invalid_capture_program_hash')
  snapshot=clean_snapshot(raw.get('block_snapshot'),self.parse_entries);start=clean_snapshot(raw.get('block_snapshot_start'),self.parse_entries)
  rows=classify_rows(normalize_rows(raw.get('endpoints',[])),snapshot)
  from live_recording import clean_baseline
  from event_evidence import normalize_evidence
  info=dict(event_evidence=normalize_evidence(raw.get('event_evidence')),history_baseline=clean_baseline(raw.get('history_baseline')),capture_id=ident,source_sha256=hashlib.sha256(raw_bytes).hexdigest(),recorded_version=raw.get('version') if isinstance(raw.get('version'),str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',raw['version']) else 'unknown',program_sha256=sha,capture_started_utc=timestamp(raw.get('capture_started_utc')),capture_ended_utc=timestamp(raw.get('capture_ended_utc')),recorded_utc_epoch=finite_number(raw.get('utc_epoch')),seconds=finite_number(raw.get('seconds')),query_errors=raw.get('query_errors') if type(raw.get('query_errors')) is int else None,truncated=raw.get('truncated') is True,block_snapshot_start=start,block_snapshot=snapshot,endpoints=rows,firewall_changed_by_observe=False,packet_drop_verified=False,scope='saved_TCP_observation_not_live_monitor')
  from phase_context import clean_recording,attach_phases
  info['phase_recording']=clean_recording(raw.get('phase_recording'),info['capture_started_utc'],info['capture_ended_utc'])
  attach_phases(info)
  return self.with_annotations(self.filter_deleted(info),include_history=include_history)
 def annotation_path(self,ident):self.capture_path(ident);return self.private/'capture-annotations'/(ident+'.json')
 def annotations(self,ident):
  path=self.annotation_path(ident)
  if not path.exists():return {}
  with path.open('rb') as f:data=f.read(1024*1024+1)
  if len(data)>1024*1024:raise ValueError('capture_annotations_too_large')
  raw=json.loads(data.decode('utf-8'))
  if not isinstance(raw,dict) or raw.get('schema') not in {'wow-capture-annotations-1','wow-capture-annotations-2'} or raw.get('capture_id')!=ident or not isinstance(raw.get('entries'),dict):raise ValueError('capture_annotations_invalid')
  out={}
  for key,item in list(raw['entries'].items())[:3000]:
   if isinstance(key,str) and isinstance(item,dict) and timestamp(item.get('annotated_utc')):
    codes=stage_codes(item.get('stages',item.get('stage','unknown')))
    out[key]=dict(stage=legacy_stage(codes),stages=codes,annotated_utc=timestamp(item['annotated_utc']))
  return out
 def with_annotations(self,capture,overrides=None,include_history=True,history_override=None):
  try:annotations=self.annotations(capture['capture_id']) if overrides is None else overrides;capture['annotation_state']='available'
  except (OSError,ValueError,TypeError):annotations={};capture['annotation_state']='unavailable_or_invalid'
  for row in capture['endpoints']:
   row['record_id']=row.get('record_id') or hashlib.sha256((capture['capture_id']+'|'+row_key(row)).encode()).hexdigest()[:32]
  history=(self.stage_history() if history_override is None else history_override) if include_history else {}
  for row in capture['endpoints']+capture.get('event_evidence',{}).get('events',[]):
   value=annotations.get(row['record_id']);codes=stage_codes(value.get('stages',value.get('stage','unknown'))) if value else []
   prior=[x for x in history.get(stage_identity(row),[]) if x['capture_id']!=capture['capture_id']]
   remembered=stage_codes([c for x in prior for c in x['stages']]);effective=stage_codes(codes+remembered)
   code=legacy_stage(codes)
   row['context']=dict(stage=code,stages=codes,history_stages=remembered,effective_stages=effective,history_sources=prior[:20],history_source_count=len(prior),history_sources_truncated=len(prior)>20,
    label='، '.join(STAGES[c] for c in effective) or STAGES['unknown'],current_label='، '.join(STAGES[c] for c in codes) or STAGES['unknown'],
    source='user_annotation' if value else ('previous_captures_only' if remembered else 'not_set'),annotated_utc=value['annotated_utc'] if value else '',event_time_verified=False)
  capture['stage_history_scope']='up_to_200_saved_captures_exact_IP_port_protocol_or_DNS_name_no_inferred_domain_link'
  return capture
 def stage_history(self):
  if hasattr(self,'_stage_cache'):return self._stage_cache
  out={};paths=sorted(self.output.glob('destinations-*.json'),key=lambda p:p.stat().st_mtime,reverse=True)
  for path in [p for p in paths if re.fullmatch(r'destinations-[a-f0-9]{32}\.json',p.name)][:MAX_HISTORY]:
   try:
    c=self.read(path.name[13:-5],include_history=False)
    for row in c['endpoints']+c['event_evidence']['events']:
     codes=stage_codes(row['context']['stages']+row.get('phase_context',{}).get('stages',[]));key=stage_identity(row)
     if codes and (key in out or len(out)<20000):
      # Aggregate a capture's repeated process/event records under the exact destination.
      matches=out.setdefault(key,[]);existing=next((x for x in matches if x['capture_id']==c['capture_id']),None)
      if existing:
       existing['stages']=stage_codes(existing['stages']+codes)
       existing['manual_stages']=stage_codes(existing.get('manual_stages',[])+row['context']['stages'])
       existing['session_stages']=stage_codes(existing.get('session_stages',[])+row.get('phase_context',{}).get('stages',[]))
      elif len(matches)<MAX_HISTORY:matches.append(dict(capture_id=c['capture_id'],stages=codes,manual_stages=row['context']['stages'],session_stages=row.get('phase_context',{}).get('stages',[]),annotated_utc=row['context']['annotated_utc']))
   except (OSError,ValueError,KeyError,TypeError):continue
  self._stage_cache=out;return out
 def deletion_path(self,ident):
  self.capture_path(ident);return self.private/'capture-deletions'/(ident+'.json')
 def deleted_ids(self,ident):
  path=self.deletion_path(ident)
  if not path.exists():return set()
  if path.stat().st_size>200000:raise ValueError('deletion_index_too_large')
  raw=json.loads(path.read_text('utf-8'))
  if raw.get('schema')!='wow-capture-deletions-1' or raw.get('capture_id')!=ident or not isinstance(raw.get('record_ids'),list) or len(raw['record_ids'])>3000 or any(not isinstance(x,str) or not CAPTURE_ID.fullmatch(x) for x in raw['record_ids']):raise ValueError('invalid_deletion_index')
  return set(raw['record_ids'])
 def filter_deleted(self,capture):
  for row in capture['endpoints']:row['record_id']=row.get('record_id') or hashlib.sha256((capture['capture_id']+'|'+row_key(row)).encode()).hexdigest()[:32]
  ids=self.deleted_ids(capture['capture_id']);capture['deleted_record_count']=len(ids)
  capture['endpoints']=[r for r in capture['endpoints'] if r['record_id'] not in ids]
  capture['event_evidence']['events']=[r for r in capture['event_evidence']['events'] if r['record_id'] not in ids]
  return capture
 def delete_records(self,ident,ids,consent=False):
  if consent is not True:raise ValueError('explicit_record_deletion_consent_required')
  capture=self.read(ident,include_history=False);old=self.deleted_ids(ident)
  allowed={r['record_id'] for r in capture['endpoints']+capture['event_evidence']['events']}|old
  if not isinstance(ids,list) or not ids or len(ids)>3000 or any(not isinstance(x,str) or x not in allowed for x in ids):raise ValueError('invalid_record_deletion_target')
  path=self.deletion_path(ident);path.parent.mkdir(exist_ok=True)
  self.atomic(path,dict(schema='wow-capture-deletions-1',capture_id=ident,record_ids=sorted(old|set(ids)),deleted_utc=utc_now()))
  self.__dict__.pop('_stage_cache',None)
  return dict(capture_id=ident,deleted=len(set(ids)-old),raw_retained_locally=True)
 def delete_captures(self,ids,consent=False):
  if consent is not True:raise ValueError('explicit_capture_deletion_consent_required')
  if not isinstance(ids,list) or not ids or len(ids)>200 or len(set(ids))!=len(ids):raise ValueError('invalid_capture_deletion_selection')
  # Validate all before moving. Only exact capture paths and their sidecars, never rules/settings.
  paths=[self.capture_path(x) for x in ids]
  if any(not x.is_file() for x in paths):raise ValueError('capture_deletion_target_missing')
  trash=self.private/'deleted-captures';trash.mkdir(exist_ok=True)
  if any((trash/x).exists() for x in ids):raise ValueError('capture_already_in_local_trash')
  moved=[];created=[]
  try:
   for ident,path in zip(ids,paths):
    group=trash/ident;group.mkdir();created.append(group)
    path.rename(group/path.name);moved.append((group/path.name,path))
    for side in (self.annotation_path(ident),self.deletion_path(ident)):
     if side.exists():
      target=group/side.parent.name;target.mkdir();created.append(target);side.rename(target/side.name);moved.append((target/side.name,side))
  except OSError:
   try:
    for source,dest in reversed(moved):source.rename(dest)
    for folder in reversed(created):folder.rmdir()
   except OSError:raise ValueError('capture_move_incomplete_check_local_trash_no_files_erased')
   raise
  self.__dict__.pop('_stage_cache',None)
  return dict(deleted=len(ids),local_trash=True,previous_exports_unchanged=True)
 def prepared_annotations(self,ident,edits):
  capture=self.read(ident);allowed={row['record_id'] for row in capture['endpoints']+capture.get('event_evidence',{}).get('events',[])}
  if not isinstance(edits,dict) or len(edits)>3000:raise ValueError('invalid_stage_annotations')
  before=self.annotations(ident);out={k:v for k,v in before.items() if k in allowed};changed=0;now=utc_now()
  for key,code in edits.items():
   if key not in allowed:raise ValueError('invalid_stage_annotation_target_or_value')
   codes=stage_codes(code);code=legacy_stage(codes)
   previous=out.get(key)
   if previous and stage_codes(previous.get('stages',previous.get('stage')))==codes:continue
   if previous is None and code=='unknown':continue
   out[key]=dict(stage=code,stages=codes,annotated_utc=now);changed+=1
  return out,changed
 def save_annotations(self,ident,edits):
  entries,changed=self.prepared_annotations(ident,edits);path=self.annotation_path(ident);path.parent.mkdir(exist_ok=True)
  self.atomic(path,dict(schema='wow-capture-annotations-2',capture_id=ident,entries=entries))
  self.__dict__.pop('_stage_cache',None)
  return dict(capture_id=ident,changed=changed,saved=True)
 def history(self):
  paths=[p for p in self.output.glob('destinations-*.json') if re.fullmatch(r'destinations-[a-f0-9]{32}\.json',p.name)]
  paths.sort(key=lambda p:p.stat().st_mtime,reverse=True);rows=[];invalid=0
  for path in paths[:MAX_HISTORY]:
   ident=path.name[len('destinations-'):-5]
   try:
    capture=self.read(ident);rows.append(dict(capture_id=ident,started_utc=capture['capture_started_utc'],ended_utc=capture['capture_ended_utc'],recorded_utc_epoch=capture['recorded_utc_epoch'],records=len(capture['endpoints'])+len(capture['event_evidence']['events']),evidence_records=len(capture['event_evidence']['events']),annotated_records=sum(r['context']['stage']!='unknown' or bool(r.get('phase_context',{}).get('stages')) for r in capture['endpoints']+capture['event_evidence']['events']),program_sha256=capture['program_sha256'],truncated=capture['truncated'],annotation_state=capture['annotation_state']))
   except (OSError,ValueError,TypeError,KeyError):invalid+=1
  return dict(entries=rows,total_files=len(paths),limit=MAX_HISTORY,truncated=len(paths)>MAX_HISTORY,invalid_files=invalid)
