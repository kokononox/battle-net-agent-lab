"""Local, observation-only new-process sessions. Never register EXEs or mutate native policy."""
import datetime,ipaddress,json,os,re,subprocess,time,uuid,zipfile
from pathlib import Path
from policy import PolicyError,path_key,windows_path
from state import assert_local_tree,atomic_json,locked
from live_ops import read_json,valid_id,DURATIONS,BASE
from monitor_evidence import instant,utc_ticks,enrich

def validate(raw):
 if not isinstance(raw,dict) or raw.get('schema')!='unified-new-process-monitor-1' or raw.get('observation_mode')!='new_processes' or not valid_id(raw.get('capture_id')):raise PolicyError('baseline_schema')
 if raw.get('status') not in ('starting','recording','finished') or raw.get('baseline_ready') is not True or raw.get('firewall_changed') is not False or raw.get('hosts_changed') is not False or raw.get('packet_drop_verified') is not False:raise PolicyError('baseline_scope')
 for key in ('ready','last_sample_ok','truncated'):
  if type(raw.get(key)) is not bool:raise PolicyError('baseline_flags')
 for key in ('revision','successful_samples','query_errors','publication_errors','unreadable_process_instances','baseline_existing_count','baseline_unreadable_count'):
  if type(raw.get(key)) is not int or not 0<=raw[key]<=0x7fffffffffffffff:raise PolicyError('baseline_counters')
 for key in ('started_utc','published_utc','baseline_utc'):instant(raw.get(key))
 if raw['status']=='finished':instant(raw.get('ended_utc'))
 cut=raw.get('baseline_cutoff_ticks')
 if not isinstance(cut,str) or not re.fullmatch('[0-9]{1,20}',cut) or not 0<int(cut)<=3155378975999999999:raise PolicyError('baseline_cutoff')
 if abs(int(cut)-utc_ticks(instant(raw['baseline_utc'])))>9:raise PolicyError('baseline_cutoff_time_mismatch')
 programs=raw.get('programs');processes=raw.get('processes');rows=raw.get('endpoints')
 if not isinstance(programs,list) or len(programs)>512 or not isinstance(processes,list) or len(processes)>2000 or not isinstance(rows,list) or len(rows)>5000:raise PolicyError('baseline_limits')
 byid={};paths=set()
 for p in programs:
  if not isinstance(p,dict) or not valid_id(p.get('id'),24) or p['id'] in byid or p.get('registered_for_firewall') is not False or p.get('hash_verified') is not False:raise PolicyError('baseline_program')
  path=windows_path(p.get('path',''))
  if not path.lower().endswith('.exe') or path_key(path) in paths:raise PolicyError('baseline_program_path')
  paths.add(path_key(path));byid[p['id']]=p
 def identity(row):
  if not isinstance(row,dict) or row.get('program_id') not in byid:raise PolicyError('baseline_process_program')
  if path_key(row.get('program_path',''))!=path_key(byid[row['program_id']]['path']):raise PolicyError('baseline_process_path')
  pid=row.get('pid');birth=row.get('process_start_ticks')
  if type(pid) is not int or not 0<pid<=0xffffffff or not isinstance(birth,str) or not re.fullmatch('[0-9]{1,20}',birth) or not int(cut)<int(birth)<=3155378975999999999:raise PolicyError('baseline_process_birth')
  return row['program_id'],pid,birth
 seen=set();identities=set()
 for p in processes:
  key=identity(p)
  if key in identities or not valid_id(p.get('record_id')) or p['record_id'] in seen or p.get('registered_for_firewall') is not False or p.get('hash_verified') is not False or p.get('presence') not in ('present','not_in_latest_snapshot','unknown'):raise PolicyError('baseline_process_record')
  first=instant(p.get('first_seen_utc'));last=instant(p.get('last_seen_utc'))
  if first>last or int(p['process_start_ticks'])>utc_ticks(last)+9:raise PolicyError('baseline_process_time')
  seen.add(p['record_id']);identities.add(key)
 for row in rows:
  if identity(row) not in identities or not valid_id(row.get('record_id')) or row['record_id'] in seen or row.get('protocol')!='TCP' or row.get('presence') not in ('present','absent','unknown'):raise PolicyError('baseline_endpoint_identity')
  seen.add(row['record_id'])
  for key in ('remote_ip','local_ip'):ipaddress.ip_address(row.get(key,''))
  for key in ('local_port','remote_port'):
   if type(row.get(key)) is not int or not 0<=row[key]<=65535:raise PolicyError('baseline_port')
  if row['remote_port']==0 or type(row.get('samples')) is not int or row['samples']<1:raise PolicyError('baseline_samples')
  if instant(row.get('first_seen_utc'))>instant(row.get('last_seen_utc')):raise PolicyError('baseline_endpoint_time')
  states=row.get('states')
  if not isinstance(states,dict) or len(states)>20 or any(not isinstance(k,str) or len(k)>32 or type(v) is not int or v<1 for k,v in states.items()):raise PolicyError('baseline_states')
 # Never trust supplied native-rule states. Unregistered discovery has no native apply bridge.
 raw['block_inventory']={};enrich(raw)
 valid=[]
 for event in raw['event_evidence']['events']:
  key=(event['program_id'],event['pid'],event.get('process_start_ticks',''))
  scoped=((event['kind']=='dns_query' and event['source']=='DNSClient_ETW') or (event['kind']=='wfp_connection_block' and event['source']=='Security_5157'))
  if scoped and key in identities and instant(raw['started_utc'])<=instant(event['observed_utc'])<=instant(raw['published_utc']):valid.append(event)
  else:raw['event_evidence']['truncated']=True;raw['event_evidence']['invalid_events']+=1
 raw['event_evidence']['events']=valid
 # Recompute links after discarding any out-of-scope event.
 enrich(raw);return raw

class Archive:
 def __init__(self,root):
  self.root=assert_local_tree(Path(root)/'monitor/baseline-captures');self.root.mkdir(parents=True,exist_ok=True)
 def path(self,cid):
  if not valid_id(cid):raise PolicyError('baseline_capture_id')
  return assert_local_tree(self.root/(cid+'.json'))
 def load(self,cid):
  c=validate(read_json(self.path(cid)))
  if c['capture_id']!=cid or c['status']!='finished':raise PolicyError('baseline_stored_identity')
  return c
 def save(self,c):
  c=validate(c);p=self.path(c['capture_id'])
  if c['status']!='finished':raise PolicyError('baseline_final_only')
  with locked(self.root/'archive.lock'):
   if p.exists():raise PolicyError('baseline_capture_exists')
   atomic_json(p,c)
  return p
 def history(self):
  paths=sorted(self.root.glob('*.json'),key=lambda p:p.stat().st_mtime,reverse=True);rows=[];errors=0
  for path in paths[:200]:
   try:
    c=self.load(path.stem);rows.append(dict(capture_id=c['capture_id'],started_utc=c['started_utc'],program_count=len(c['programs']),records=len(c['processes']),successful_samples=c['successful_samples'],query_errors=c['query_errors'],truncated=c['truncated']))
   except (OSError,ValueError,KeyError,TypeError):errors+=1
  return dict(captures=rows,invalid_or_unreadable=errors,older_not_listed=max(0,len(paths)-200),limit=200)

def record(store,payload,job):
 seconds=payload.get('seconds',60);consent=payload.get('dns_etw_consent',False)
 if type(seconds) is not int or seconds not in DURATIONS or type(consent) is not bool:raise PolicyError('baseline_duration_or_consent')
 if os.name!='nt':raise PolicyError('baseline_requires_Windows')
 state=store.read();cid=uuid.uuid4().hex;request=job/'baseline-request.json';final=job/'capture.json'
 atomic_json(request,dict(owner=state['owner'],observation_mode='new_processes',programs=[],event_programs=[],hosts_baseline=__import__('hosts_view').monitor_snapshot(),inventory_path=str(job/'not-requested-inventory.json'),dns_etw_requested=consent,dns_session_guid=str(uuid.uuid4()),dns_receipt_path=str(job/'dns-session.json'),seconds=seconds,capture_id=cid,stop_path=str(job/'stop.txt'),live_path=str(job/'live.json'),parent_pid=os.getpid()))
 ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
 with (job/'collector-stdout.txt').open('wb') as out,(job/'collector-error.txt').open('wb') as err:
  code=subprocess.run([str(ps),'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(BASE/'app/baseline.ps1'),'-Request',str(request),'-Output',str(final)],stdout=out,stderr=err,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)).returncode
 if code or not final.is_file():raise PolicyError('baseline_collector_failed_partial_live_retained')
 capture=validate(read_json(final))
 if capture['capture_id']!=cid:raise PolicyError('baseline_collector_identity')
 path=Archive(store.root).save(capture)
 return dict(capture=capture,capture_file=str(path),firewall_changed=False,hosts_changed=False,settings_changed=False)

def export(store,payload,job):
 c=Archive(store.root).load(payload.get('capture_id'));clean=json.loads(json.dumps(c))
 for p in clean['programs']:p.pop('path',None)
 for section in ('processes','endpoints'):
  for row in clean[section]:row.pop('program_path',None)
 for e in clean['event_evidence']['events']:e.pop('program_path',None)
 path=assert_local_tree(job/'baseline-export.zip')
 with zipfile.ZipFile(path,'x',zipfile.ZIP_DEFLATED) as z:
  z.writestr('capture.json',json.dumps(clean,ensure_ascii=False,indent=2));z.writestr('README.txt','Private new-process observations: PID, birth times, IP and DNS remain. Not all starts are guaranteed observed. No EXE hash verification, automatic registration or firewall changes. Full EXE paths removed.')
 with zipfile.ZipFile(path) as z:
  if z.testzip() is not None:raise PolicyError('baseline_export_verification')
 return dict(export_file=str(path),firewall_changed=False,settings_changed=False)

def handle(store,action,payload,job):
 if action=='baseline_record':return record(store,payload,job)
 if action=='baseline_history':return dict(history=Archive(store.root).history(),firewall_changed=False)
 if action=='baseline_open':return dict(capture=Archive(store.root).load(payload.get('capture_id')),firewall_changed=False)
 if action=='baseline_export':return export(store,payload,job)
 raise PolicyError('unknown_baseline_action')
