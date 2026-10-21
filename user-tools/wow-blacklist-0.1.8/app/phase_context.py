"""User-selected session phases, separate from manual row labels and prior-capture memory."""
import datetime
PHASES=('unknown','launch','login','dashboard','in_game')
MAX_TRANSITIONS=500

def stamp(value):
 if not isinstance(value,str) or len(value)>50:return ''
 try:
  dt=datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
  return dt.astimezone(datetime.timezone.utc).isoformat() if dt.tzinfo else ''
 except (ValueError,OverflowError):return ''
def instant(value):
 text=stamp(value);return datetime.datetime.fromisoformat(text) if text else None

def clean_recording(raw,started='',ended=''):
 unavailable=dict(schema='wow-stage-recording-1',status='not_recorded',transitions=[],read_errors=0,truncated=False,source='user_selected_global_stage_not_game_detection')
 if not isinstance(raw,dict):return unavailable
 if raw.get('status')=='invalid':return {**unavailable,'status':'invalid'}
 if raw.get('schema')!='wow-stage-recording-1' or not isinstance(raw.get('transitions'),list):return {**unavailable,'status':'invalid'}
 items=raw['transitions'];out=[];previous=None;lo=instant(started);hi=instant(ended)
 try:
  if len(items)>MAX_TRANSITIONS:raise ValueError()
  for i,e in enumerate(items,1):
   when=stamp(e.get('selected_utc'));dt=instant(when)
   if e.get('sequence')!=i or e.get('stage') not in PHASES or not dt or (previous and dt<previous) or (lo and dt<lo-datetime.timedelta(hours=1)) or (hi and dt>hi):raise ValueError()
   out.append(dict(sequence=i,stage=e['stage'],selected_utc=when));previous=dt
  errors=raw.get('read_errors',0)
  if type(errors) is not int or not 0<=errors<=2000000:errors=0
 except (ValueError,TypeError,AttributeError):return {**unavailable,'status':'invalid'}
 return {**unavailable,'status':'read_errors' if errors else ('available' if out else 'not_recorded'),'transitions':out,'read_errors':errors,'truncated':raw.get('truncated') is True}

def clean_hits(raw,first='',last='',samples=0):
 if not isinstance(raw,dict) or len(raw)>len(PHASES):return {}
 out={};total=0;lo=instant(first);hi=instant(last)
 for code,value in raw.items():
  if code not in PHASES or not isinstance(value,dict):return {}
  count=value.get('samples');begin=stamp(value.get('first_seen_utc'));end=stamp(value.get('last_seen_utc'));a=instant(begin);b=instant(end)
  if type(count) is not int or not 0<count<=2000000 or not a or not b or a>b or not lo or not hi or a<lo or b>hi:return {}
  out[code]=dict(samples=count,first_seen_utc=begin,last_seen_utc=end);total+=count
 if total>samples:return {}
 return out

def phase_at(transitions,when):
 at=instant(when)
 if not at:return 'unknown'
 code='unknown'
 for row in transitions:
  if instant(row['selected_utc'])>at:break
  code=row['stage']
 return code

def phase_stages(row):
 return [code for code in PHASES if code!='unknown' and code in row.get('phase_context',{}).get('stages',[])]

def attach_phases(capture):
 recording=capture.get('phase_recording',{})
 timeline=recording.get('transitions',[]);start=instant(capture.get('capture_started_utc'));end=instant(capture.get('capture_ended_utc'))
 for row in capture.get('endpoints',[]):
  hits=row.get('phase_hits',{}) if recording.get('status') in {'available','read_errors'} else {}
  # A TCP label requires a real sample hit in that phase; do not infer it from a first-last span.
  row['phase_context']=dict(stages=[code for code in PHASES if code!='unknown' and code in hits],sample_hits=hits,source='TCP_sample_under_user_selected_stage' if hits else 'not_recorded',association_complete=(recording.get('status')=='available'),game_stage_verified=False,continuous_presence_verified=False)
 for row in capture.get('event_evidence',{}).get('events',[]):
  when=instant(row.get('observed_utc'));inside=bool(when and start and end and start<=when<=end)
  code=phase_at(timeline,row.get('observed_utc')) if inside and recording.get('status')=='available' else 'unknown'
  row['phase_context']=dict(stages=[code] if code!='unknown' else [],source='event_timestamp_under_user_selected_stage' if code!='unknown' else 'not_recorded',event_utc=row['observed_utc'],game_stage_verified=False)
 return capture
