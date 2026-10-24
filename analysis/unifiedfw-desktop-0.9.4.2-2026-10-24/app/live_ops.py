"""Read-only multi-EXE monitoring, bounded local captures. No native/firewall/hosts mutation."""
import datetime,hashlib,ipaddress,json,os,re,subprocess,uuid,zipfile,io,time
from pathlib import Path
from state import assert_local_tree,atomic_json,locked
from policy import PolicyError,path_key,program_id
BASE=Path(__file__).resolve().parents[1]
LIMIT=16*1024*1024
DURATIONS=(0,30,60,120,300)
def read_json(path):
 path=assert_local_tree(path)
 with path.open('rb') as f:data=f.read(LIMIT+1)
 if len(data)>LIMIT:raise PolicyError('monitor_file_too_large')
 return json.loads(data.decode('utf-8-sig'))
def valid_id(v,n=32):return isinstance(v,str) and re.fullmatch('[a-f0-9]{%s}'%n,v) is not None
def validate(raw):
 if not isinstance(raw,dict) or raw.get('schema')!='unified-live-monitor-1' or not valid_id(raw.get('capture_id')):raise PolicyError('monitor_schema')
 programs=raw.get('programs');rows=raw.get('endpoints')
 if not isinstance(programs,list) or not 1<=len(programs)<=32 or not isinstance(rows,list) or len(rows)>5000:raise PolicyError('monitor_limits')
 for key in ('revision','successful_samples','query_errors','publication_errors','unreadable_process_instances'):
  if type(raw.get(key)) is not int or raw[key]<0:raise PolicyError('monitor_counters')
 for key in ('ready','last_sample_ok','truncated'):
  if type(raw.get(key)) is not bool:raise PolicyError('monitor_flags')
 if raw.get('status') not in ('starting','recording','finished') or raw.get('firewall_changed') is not False or raw.get('packet_drop_verified') is not False:raise PolicyError('monitor_scope')
 for key in ('started_utc','published_utc'):
  value=raw.get(key)
  if not isinstance(value,str) or len(value)>64:raise PolicyError('monitor_time')
  if datetime.datetime.fromisoformat(value.replace('Z','+00:00')).tzinfo is None:raise PolicyError('monitor_time_zone')
 if raw.get('status')=='finished':
  value=raw.get('ended_utc')
  if not isinstance(value,str) or len(value)>64 or datetime.datetime.fromisoformat(value.replace('Z','+00:00')).tzinfo is None:raise PolicyError('monitor_end_time')
 byid={}
 for p in programs:
  if not isinstance(p,dict) or not valid_id(p.get('id'),24) or not valid_id(p.get('sha256'),64) or not isinstance(p.get('path'),str) or len(p['path'])>32767 or not p['path'].lower().endswith('.exe') or p['id'] in byid:raise PolicyError('monitor_program')
  if program_id(p['path'])!=p['id']:raise PolicyError('monitor_program_path_id')
  byid[p['id']]=p
 seen=set()
 for row in rows:
  if not isinstance(row,dict) or not valid_id(row.get('record_id')) or row['record_id'] in seen or row.get('program_id') not in byid:raise PolicyError('monitor_record')
  seen.add(row['record_id']);p=byid[row['program_id']]
  if path_key(row.get('program_path',''))!=path_key(p['path']) or row.get('protocol')!='TCP':raise PolicyError('monitor_record_identity')
  for name in ('remote_ip','local_ip'):
   if not isinstance(row.get(name),str) or len(row[name])>128:raise PolicyError('monitor_IP')
   ipaddress.ip_address(row[name])
  for name in ('local_port','remote_port'):
   if type(row.get(name)) is not int or not 0<=row[name]<=65535:raise PolicyError('monitor_port')
  if row['remote_port']==0 or type(row.get('pid')) is not int or row['pid']<=0 or type(row.get('samples')) is not int or row['samples']<1:raise PolicyError('monitor_record_values')
  if row.get('presence') not in ('present','absent','unknown'):raise PolicyError('monitor_presence')
  for name in ('first_seen_utc','last_seen_utc'):
   if not isinstance(row.get(name),str) or len(row[name])>64:raise PolicyError('monitor_time')
   datetime.datetime.fromisoformat(row[name].replace('Z','+00:00'))
  if not isinstance(row.get('states'),dict) or len(row['states'])>20 or any(not isinstance(k,str) or len(k)>32 or type(v) is not int or v<1 for k,v in row['states'].items()):raise PolicyError('monitor_states')
  if not isinstance(row.get('process_start_ticks'),str) or not re.fullmatch('[0-9]{1,20}',row['process_start_ticks']):raise PolicyError('monitor_process_start')
 from monitor_evidence import enrich
 return enrich(raw)
class Archive:
 def __init__(self,root):
  self.root=assert_local_tree(Path(root)/'monitor/captures');self.root.mkdir(parents=True,exist_ok=True)
 def path(self,cid):
  if not valid_id(cid):raise PolicyError('monitor_capture_id')
  return assert_local_tree(self.root/(cid+'.json'))
 def load(self,cid):
  value=validate(read_json(self.path(cid)))
  if value['capture_id']!=cid or value['status']!='finished':raise PolicyError('monitor_stored_identity_or_status')
  return value
 def save(self,capture):
  validate(capture);p=self.path(capture['capture_id'])
  if capture.get('status')!='finished':raise PolicyError('monitor_final_only')
  with locked(self.root/'archive.lock'):
   if p.exists():raise PolicyError('monitor_capture_exists')
   atomic_json(p,capture)
  return p
 def history(self):
  paths=sorted(self.root.glob('*.json'),key=lambda p:p.stat().st_mtime,reverse=True)
  rows=[];errors=0
  for path in paths[:200]:
   try:
    c=self.load(path.stem);rows.append(dict(capture_id=c['capture_id'],started_utc=c['started_utc'],ended_utc=c.get('ended_utc'),program_count=len(c['programs']),records=len(c['endpoints']),query_errors=c.get('query_errors'),truncated=c.get('truncated'),successful_samples=c.get('successful_samples'),event_records=len(c.get('event_evidence',{}).get('events',[]))))
   except (OSError,ValueError,TypeError,KeyError):errors+=1
  return dict(captures=rows,invalid_or_unreadable=errors,older_not_listed=max(0,len(paths)-200),limit=200)
def record(store,payload,job):
 seconds=payload.get('seconds',60)
 dns_requested=payload.get('dns_etw_consent',False)
 if type(dns_requested) is not bool:raise PolicyError('DNS_ETW_requires_explicit_boolean_consent')
 if type(seconds) is not int or seconds not in DURATIONS:raise PolicyError('monitor_duration_0_30_60_120_300')
 if os.name!='nt':raise PolicyError('live_observation_requires_windows')
 state,programs=store.verified_programs(payload.get('program_ids'));cid=uuid.uuid4().hex
 request=job/'live-request.json';final=job/'capture.json'
 from monitor_evidence import device_path
 from hosts_view import read_windows_hosts
 try:
  hosts=read_windows_hosts();baseline=dict(available=True,truncated=hosts['truncated'],entries=[{k:e[k] for k in ('domain','addresses','mapping_kind')} for e in hosts['entries']])
 except Exception:baseline=dict(available=False,truncated=False,entries=[])
 baseline['checked_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
 events=[dict(id=p['id'],path=p['path'],device_path=device_path(p['path'])) for p in programs]
 atomic_json(request,dict(owner=state['owner'],dns_etw_requested=dns_requested,dns_session_guid=str(uuid.uuid4()),dns_receipt_path=str(job/'dns-session.json'),event_programs=events,hosts_baseline=baseline,inventory_path=str(job/'inventory.json'),programs=programs,seconds=seconds,capture_id=cid,stop_path=str(job/'stop.txt'),live_path=str(job/'live.json'),parent_pid=os.getpid()))
 ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
 with (job/'collector-stdout.txt').open('wb') as out,(job/'collector-error.txt').open('wb') as err:
  proc=subprocess.Popen([str(ps),'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(BASE/'app/live.ps1'),'-Request',str(request),'-Output',str(final)],stdout=out,stderr=err,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
  # Native mutations NEVER time out. This separate child only reads rules/journal.
  inventory_request=job/'inventory-request.json';atomic_json(inventory_request,dict(owner=state['owner'],programs=programs))
  reader=None;reader_started=time.monotonic();reader_stop='completed'
  with (job/'inventory-stdout.txt').open('wb') as reader_out,(job/'inventory-error.txt').open('wb') as reader_err:
   try:
    reader=subprocess.Popen([str(ps),'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(BASE/'app/inventory-read.ps1'),'-Request',str(inventory_request),'-Output',str(job/'inventory.json')],stdout=reader_out,stderr=reader_err,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
   except OSError:reader_stop='reader_launch_failed'
   while proc.poll() is None:
    if reader is not None and reader.poll() is None and time.monotonic()-reader_started>45:
     reader.kill();reader.wait();reader_stop='readonly_snapshot_timeout_no_firewall_or_journal_writes'
    time.sleep(.2)
   if reader is not None and reader.poll() is None:
    reader.kill();reader.wait();reader_stop='readonly_snapshot_stopped_at_capture_end'
  atomic_json(job/'inventory-reader-status.json',dict(status=reader_stop,reader_exit=reader.returncode if reader else None,firewall_changed=False,journal_changed=False))
 if proc.returncode or not final.is_file():raise PolicyError('monitor_collector_failed_partial_live_retained_see_collector_error')
 capture=read_json(final)
 if (job/'inventory.json').is_file():
  try:capture['block_inventory']=read_json(job/'inventory.json')
  except (OSError,ValueError):pass
 capture=validate(capture)
 if capture['capture_id']!=cid or capture['programs']!=programs:raise PolicyError('monitor_output_identity')
 path=Archive(store.root).save(capture)
 return dict(capture=capture,capture_file=str(path),state=state,firewall_changed=False,packet_drop_verified=False)
def export_capture(store,payload,job):
 c=Archive(store.root).load(payload.get('capture_id'))
 # Explicit local export. Full executable paths excluded, IPs/times/hash remain private.
 clean=json.loads(json.dumps(c))
 for p in clean['programs']:p.pop('path',None)
 for row in clean['endpoints']:row.pop('program_path',None)
 for e in clean.get('event_evidence',{}).get('events',[]):e.pop('program_path',None)
 for rule in clean.get('block_inventory',{}).get('rules',[]):rule.pop('program',None)
 text=['Unified Firewall — local TCP samples (not packet capture)', 'Private: domains, DNS results, hosts mapping context, IPs, ports, process identifiers, binary hashes and times included.', 'No proof of firewall protection. DNS log/temporary ETW evidence is not packet capture or HTTP; query-called and query-completed are separate events.', 'capture_id: '+c['capture_id'], '']
 for row in c['endpoints']:text.append(f"{row['program_id']} | PID {row['pid']} | {row['remote_ip']}:{row['remote_port']} | samples={row['samples']} | {row['last_seen_utc']}")
 for e in c.get('event_evidence',{}).get('events',[]):
  text.append(f"{e['source']} | {e.get('domain',e.get('ip',''))} | {e['observed_utc']} | PID {e['pid']}")
 path=assert_local_tree(job/'monitor-export.zip')
 with zipfile.ZipFile(path,'x',zipfile.ZIP_DEFLATED) as z:
  z.writestr('capture.json',json.dumps(clean,ensure_ascii=False,indent=2));z.writestr('README.txt','\n'.join(text))
 with zipfile.ZipFile(path) as z:
  if z.testzip() is not None:raise PolicyError('monitor_export_verification')
 return dict(export_file=str(path),privacy='domains_DNS_hosts_context_IPs_ports_process_identifiers_hashes_times_included; review_before_sharing',firewall_changed=False)
def ptr_lookup(store,payload,job):
 from dns_lookup import Resolver
 ips=payload.get('ips');force=payload.get('force',False)
 if not isinstance(ips,list) or not 1<=len(ips)<=100 or type(force) is not bool:raise PolicyError('PTR_select_1_to_100_public_IPs')
 cleaned=[];skipped=[]
 for value in ips:
  if not isinstance(value,str):raise PolicyError('PTR_literal_public_IP_required')
  ip=ipaddress.ip_address(value)
  if not ip.is_global or ip.is_reserved or ip.is_multicast:skipped.append(str(ip));continue
  if str(ip) not in cleaned:cleaned.append(str(ip))
 folder=assert_local_tree(store.root/'monitor');folder.mkdir(exist_ok=True)
 cache=assert_local_tree(folder/'ptr-cache.json')
 with locked(folder/'ptr-cache.lock'):
  result=Resolver(cache,BASE/'app',atomic_json).lookup([dict(ip=ip) for ip in cleaned],force=force,stop=lambda:(job/'stop.txt').exists(),progress=lambda p:atomic_json(job/'progress.json',p))
 result['skipped_non_public_ips']=list(dict.fromkeys(skipped))
 return dict(ptr=result,firewall_changed=False,hosts_changed=False,actual_connection_hostname_verified=False)
def dns_cleanup(store,payload,job):
 if payload.get('consent') is not True:raise PolicyError('DNS_cleanup_explicit_consent_required')
 if os.name!='nt':raise PolicyError('DNS_cleanup_requires_Windows')
 owner=store.read()['owner'];receipts=[];jobs=assert_local_tree(store.root/'jobs')
 for path in sorted(jobs.glob('*/dns-session.json'),key=lambda p:p.stat().st_mtime,reverse=True)[:200]:
  try:
   v=read_json(path)
   if v.get('schema')!='unified-dns-session-1' or v.get('owner')!=owner or v.get('ended') is True:continue
   cid=v.get('capture_id','')
   if not re.fullmatch('[a-f0-9]{32}',cid) or v.get('session_name')!='UnifiedFW-DNS-'+owner+'-'+cid:continue
   uuid.UUID(v['session_guid']);int(v['collector_pid']);int(v['collector_birth_ticks']);receipts.append(v)
  except (OSError,ValueError,TypeError,KeyError):continue
 request=job/'dns-cleanup-request.json';output=job/'dns-cleanup-result.json';atomic_json(request,dict(owner=owner,receipts=receipts))
 ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
 with (job/'cleanup-out.txt').open('wb') as out,(job/'cleanup-error.txt').open('wb') as err:
  code=subprocess.run([str(ps),'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(BASE/'app/dns-cleanup.ps1'),'-Request',str(request),'-Output',str(output)],stdout=out,stderr=err,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)).returncode
 if code or not output.is_file():raise PolicyError('DNS_cleanup_failed_see_job')
 return dict(dns_cleanup=read_json(output),firewall_changed=False,hosts_changed=False)

def handle(store,action,payload,job):
 if action=='monitor_dns_cleanup':return dns_cleanup(store,payload,job)
 if action=='monitor_ptr':return ptr_lookup(store,payload,job)
 if action=='monitor_record':return record(store,payload,job)
 if action=='monitor_history':return dict(history=Archive(store.root).history(),firewall_changed=False)
 if action=='monitor_open':return dict(capture=Archive(store.root).load(payload.get('capture_id')),firewall_changed=False)
 if action=='monitor_export':return export_capture(store,payload,job)
 if action=='monitor_stage':
  c=Archive(store.root).load(payload.get('capture_id'))
  row=next((x for x in c['endpoints'] if x['record_id']==payload.get('record_id')),None)
  if row is None:
   event=next((e for e in c.get('event_evidence',{}).get('events',[]) if e['record_id']==payload.get('record_id') and e['kind']=='wfp_connection_block'),None)
   if event:row=dict(event,remote_ip=event['ip'],remote_port=event['port'])
  if row is None:raise PolicyError('monitor_record_selection')
  s=store.read();old=next(p for p in c['programs'] if p['id']==row['program_id']);p=next((p for p in s['config']['programs'] if p['id']==old['id']),None)
  if not p or p['sha256']!=old['sha256'] or path_key(p['path'])!=path_key(old['path']):raise PolicyError('monitor_program_changed_reselect')
  # Existing validator rejects non-public / unsupported targets; desired config only.
  return dict(state=store.add_blacklist([p['id']],row['remote_ip'],row['protocol'],row['remote_port'],payload.get('generation')),firewall_changed=False,saved_only=True)
 raise PolicyError('unknown_monitor_action')
