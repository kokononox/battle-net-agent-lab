"""Persistent, app-scoped blacklist manager. No HTTP listener or packet interception."""
import base64,hashlib,ipaddress,json,os,re,secrets,subprocess,sys,time,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from dns_lookup import Resolver
from range_builder import build_range
from observation_model import normalize_rows,classify_rows,timestamp
from hosts_view import read_windows_hosts
from capture_store import CaptureStore
from analysis_export import export_bundle
from live_recording import history_baseline,recover_live_labels
from event_evidence import device_program_path,hosts_baseline,normalize_evidence
BASE=Path(__file__).resolve().parents[1]
VERSION='0.1.8'
MAX_ENTRIES=100
class BlacklistError(Exception):pass

def atomic(path,obj):
 path=Path(path);tmp=path.with_name(path.name+'.tmp')
 with tmp.open('w',encoding='utf-8') as f:json.dump(obj,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
 os.replace(tmp,path)
def atomic_text(path,text):
 path=Path(path);tmp=path.with_name(path.name+'.tmp')
 with tmp.open('w',encoding='utf-8',newline='') as f:f.write(text);f.flush();os.fsync(f.fileno())
 os.replace(tmp,path)

# Conservative exclusions for networks: never admit a subnet spanning special-use space.
V4_SPECIAL=tuple(ipaddress.ip_network(x) for x in ('0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.0.0.0/24','192.0.2.0/24','192.88.99.0/24','192.168.0.0/16','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/3'))
V6_SPECIAL=tuple(ipaddress.ip_network(x) for x in ('2001::/23','2001:db8::/32','2002::/16','3fff::/20'))
def parse_target(value):
 if '/' not in value:
  ip=ipaddress.ip_address(value)
  if not ip.is_global or ip.is_multicast or ip.is_unspecified or ip.is_reserved:raise ValueError('not_public')
  return str(ip)
 # Require a network boundary: do not silently broaden a mistyped host/prefix.
 net=ipaddress.ip_network(value,strict=True)
 if net.prefixlen==net.max_prefixlen:return parse_target(str(net.network_address))
 if net.version==4:
  if any(net.overlaps(x) for x in V4_SPECIAL):raise ValueError('special_use_overlap')
 else:
  if not net.subnet_of(ipaddress.ip_network('2000::/3')) or any(net.overlaps(x) for x in V6_SPECIAL):raise ValueError('special_use_overlap')
 if not net.is_global:raise ValueError('not_public')
 return str(net)
def covers(entry,address):
 return ipaddress.ip_address(address) in ipaddress.ip_network(entry['ip'])

def digest(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def parse_list(text):
 if not isinstance(text,str) or len(text)>30000:raise BlacklistError('invalid_list')
 out=[];seen=set()
 for line_no,line in enumerate(text.splitlines(),1):
  line=line.split('#',1)[0].strip()
  if not line:continue
  match=re.fullmatch(r'(\[[0-9a-fA-F:]+(?:/[0-9]{1,3})?\]|[0-9.]+(?:/[0-9]{1,2})?):([0-9]{1,5})\s+(TCP|UDP)',line,re.I)
  if not match:raise BlacklistError('invalid_line_'+str(line_no))
  try:ip=parse_target(match[1].strip('[]'))
  except ValueError:raise BlacklistError('invalid_ip_line_'+str(line_no))
  port=int(match[2]);protocol=match[3].upper()
  if not 1<=port<=65535:raise BlacklistError('invalid_port_line_'+str(line_no))
  item=(str(ip),port,protocol)
  if item in seen:continue
  seen.add(item);out.append(dict(ip=str(ip),port=port,protocol=protocol))
  if len(out)>MAX_ENTRIES:raise BlacklistError('too_many_entries')
 return out

def format_list(entries):
 return '\n'.join(('['+e['ip']+']' if ':' in e['ip'] else e['ip'])+':'+str(e['port'])+' '+e['protocol'] for e in entries)
def verify_program(path):
 p=Path(path or '').resolve()
 if p.name.lower()!='wow.exe' or not p.is_file():raise BlacklistError('select_existing_Wow_exe')
 return str(p),digest(p)
def spec(owner,program,entry):
 key=program.casefold()+'|'+entry['ip']+'|'+str(entry['port'])+'|'+entry['protocol']
 ident=hashlib.sha256(key.encode()).hexdigest()[:24]
 return {**entry,'name':'WoWBlacklist-'+owner+'-'+ident}
def powershell(script,plan,private,job):
 path=private/('job-'+job+'.firewall.json');atomic(path,plan)
 env=os.environ.copy();env['WOW_BL_REQUEST']=str(path);env['WOW_BL_APP']=str(BASE/'app')
 code="& ([scriptblock]::Create([IO.File]::ReadAllText('"+str(BASE/'app'/script).replace("'","''")+"')))"
 ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
 # No mutation timeout that could race an outstanding firewall operation.
 r=subprocess.run([str(ps),'-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(code.encode('utf-16le')).decode()],env=env,capture_output=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
 try:result=json.loads(r.stdout.decode('utf-8-sig'))
 except (ValueError,UnicodeError):raise BlacklistError('powershell_invalid_result_keep_state')
 if r.returncode or not isinstance(result,dict) or result.get('ok') is not True:
  stage=result.get('stage','operation') if isinstance(result,dict) else 'operation'
  if not re.fullmatch('[a-z_]{1,60}',stage):stage='operation'
  raise BlacklistError('firewall_'+stage+'_failed_Restore_or_retry')
 return result
class Manager:
 def __init__(self,root=BASE,fw=None,collector=None,resolver_query=None,hosts_reader=None):
  self.root=Path(root);self.private=self.root/'private-state';self.private.mkdir(exist_ok=True);self.output=self.root/'output';self.output.mkdir(exist_ok=True)
  self.fw=fw or (lambda plan,job:powershell('firewall.ps1',plan,self.private,job));self.collector=collector or (lambda plan,job:powershell('observe.ps1',plan,self.private,job))
  self.hosts_reader=hosts_reader or read_windows_hosts
  self.config_path=self.private/'settings.json';self.text_path=self.private/'blacklist.txt'
  self.version=VERSION;self.atomic_json=atomic;self.verify_program=verify_program;self.parse_entries_from_text=parse_list;self.format_entries=format_list
  self.captures=CaptureStore(self.root,atomic,self.parse_capture_entries)
  self.resolver=Resolver(self.private/'ptr-cache.json',self.root/'app',atomic,query=resolver_query)
 def owner(self,create=False):
  paths=[self.private/'owner-id.json',self.private/'owner-id.backup.json'];valid=[]
  for p in paths:
   if p.exists():
    try:
     x=json.loads(p.read_text('utf-8'))['owner']
     if re.fullmatch('[a-f0-9]{32}',x):valid.append(x)
    except (ValueError,TypeError,KeyError):pass
  if len(set(valid))>1:raise BlacklistError('owner_backups_disagree_keep_folder')
  if valid:return valid[0]
  if any(p.exists() for p in paths) or self.config_path.exists() or self.text_path.exists() or not create:raise BlacklistError('owner_id_missing_or_invalid_keep_folder')
  owner=uuid.uuid4().hex
  for p in paths:atomic(p,{'schema':'wow-blacklist-owner-1','owner':owner})
  return owner
 def config(self):
  if self.config_path.exists():
   try:
    c=json.loads(self.config_path.read_text('utf-8'));assert c['phase'] in {'never_applied','saved','applying','applied','needs_restore','restored'}
   except Exception:raise BlacklistError('settings_invalid_Restore_still_available')
  else:
   seeds=json.loads((self.root/'app/defaults.json').read_text('utf-8'))
   c=dict(program='',program_sha256=None,text=format_list(seeds),phase='never_applied')
  try:
   # TXT is the editable list; JSON retains program, ownership-independent operation state.
   if self.text_path.exists():
    if self.text_path.stat().st_size>30000:raise ValueError('too_large')
    c['text']=format_list(parse_list(self.text_path.read_text('utf-8-sig')))
   else:parse_list(c['text'])
  except Exception:raise BlacklistError('blacklist_txt_invalid_fix_or_import_valid_list_Restore_available')
  return c
 def persist(self,c):
  if self.config_path.exists():
   try:atomic(self.private/'settings.previous.json',json.loads(self.config_path.read_text('utf-8')))
   except (ValueError,OSError):pass
  if self.text_path.exists():
   previous=self.text_path.read_text('utf-8-sig')
   if previous.rstrip('\r\n')!=c['text']:atomic_text(self.private/'blacklist.previous.txt',previous)
  # Complete both writes before allowing any firewall mutation. Fail closed on I/O error.
  atomic_text(self.text_path,c['text']+('\n' if c['text'] else ''))
  atomic(self.config_path,c)
 def plan(self,owner,action,program='',entries=()):
  return dict(schema='wow-blacklist-plan-1',owner=owner,action=action,program=program,entries=[spec(owner,program,e) for e in entries])
 def report(self,action,entries,result,job,sha=None):
  safe={k:result[k] for k in ('persistent_count','active_count','config_verified','absence_verified','removed_count') if k in result}
  atomic(self.output/('blacklist-result-'+job+'.json'),dict(schema='wow-blacklist-result-1',version=VERSION,action=action,utc_epoch=time.time(),program_sha256=sha,endpoints=entries,**safe,persistent_until_explicit_restore=True,packet_block_verified=False,credentials_collected=False))
 def parse_capture_entries(self,items):
  try:return parse_list(format_list(items))
  except (BlacklistError,KeyError,TypeError,ValueError):raise ValueError('invalid_saved_capture_spec')
 def block_snapshot(self,owner,program,job):
  checked=time.time()
  try:
   raw=self.fw(self.plan(owner,'inventory',program),job)
   if raw.get('inventory_verified') is not True:raise BlacklistError('inventory_not_verified')
   entries=[];rejected=0
   for item in raw.get('entries',[])[:1000]:
    try:
     canonical=parse_list(format_list([item]))
     if len(canonical)!=1 or item.get('name')!=spec(owner,program,canonical[0])['name']:raise ValueError('identity')
     entries.append(canonical[0])
    except (BlacklistError,ValueError,KeyError,TypeError):rejected+=1
   return dict(available=True,entries=entries,checked_utc=timestamp(raw.get('checked_utc')),checked_utc_epoch=checked,unverified_owned_count=max(0,int(raw.get('unverified_owned_count',0)))+rejected,scope='this_installation_selected_program_only',packet_drop_verified=False)
  except Exception:
   return dict(available=False,entries=[],checked_utc_epoch=checked,checked_utc='',reason='inventory_readback_unavailable',packet_drop_verified=False)
 def run(self,action,payload=None,job=None):
  payload=payload or {};job=job or uuid.uuid4().hex
  if action=='preview_range':
   try:return dict(range_preview=build_range(payload,parse_target,format_list))
   except ValueError as e:
    code=str(e);raise BlacklistError(code if re.fullmatch('[A-Za-z0-9_]{1,100}',code) else 'invalid_range_input')
  if action=='hosts_apply':
   from hosts_edit import apply_hosts
   try:return dict(hosts_edit=apply_hosts(self.private,payload),hosts=self.hosts_reader())
   except (OSError,ValueError,UnicodeError) as e:
    code=str(e);raise BlacklistError(code if re.fullmatch('[a-zA-Z0-9_]{1,120}',code) else 'hosts_edit_failed_check_backup')
  if action=='hosts':
   try:return dict(hosts=self.hosts_reader())
   except (OSError,ValueError,UnicodeError) as e:
    code=str(e);raise BlacklistError(code if code in {'hosts_view_requires_Windows','hosts_windows_root_unavailable','hosts_file_too_large'} else 'hosts_read_failed_no_changes')
  if action in ('history','load_observation','annotate_observation','export_analysis','delete_records','delete_captures','compare_captures'):
   try:
    if action=='delete_records':
     if payload.get('entries') is not None:self.captures.save_annotations(payload.get('capture_id'),payload.get('entries'))
     result=self.captures.delete_records(payload.get('capture_id'),payload.get('record_ids'),payload.get('deletion_consent'));return dict(deletion=result,observation=self.captures.read(payload.get('capture_id')))
    if action=='delete_captures':return dict(deletion=self.captures.delete_captures(payload.get('capture_ids'),payload.get('deletion_consent')),history=self.captures.history())
    if action=='compare_captures':
     from capture_compare import compare,readable
     ids=payload.get('capture_ids')
     if not isinstance(ids,list) or len(ids)!=2:raise ValueError('select_exactly_two_distinct_captures')
     comparison=compare([self.captures.read(ident) for ident in ids]);return dict(comparison=comparison,comparison_text=readable(comparison))
    if action=='history':return dict(history=self.captures.history())
    if action=='load_observation':return dict(observation=self.captures.read(payload.get('capture_id')))
    if action=='annotate_observation':return dict(annotation=self.captures.save_annotations(payload.get('capture_id'),payload.get('entries')))
    return dict(export=export_bundle(self,payload,job))
   except (OSError,ValueError,KeyError,TypeError) as e:
    code=str(e);raise BlacklistError(code if re.fullmatch('[A-Za-z0-9_]{1,100}',code) else 'capture_history_annotation_or_export_failed_no_firewall_changes')
  owner=self.owner(create=action=='load')
  if action=='classify_observation':
   program,sha=verify_program(payload.get('program'));rows=normalize_rows(payload.get('endpoints',[]));snapshot=self.block_snapshot(owner,program,job)
   report=dict(schema='wow-blacklist-destinations-2',version=VERSION,program_sha256=sha,endpoints=classify_rows(rows,snapshot),block_snapshot=snapshot,classification_only=True,firewall_changed_by_observe=False,utc_epoch=time.time())
   atomic(self.output/('destinations-classification-'+job+'.json'),report);return dict(observation=report)

  if action=='lookup':
   entries=parse_list(payload.get('text',''));stop=self.private/('job-'+job+'.stop');progress=self.private/('job-'+job+'.progress.json')
   try:result=self.resolver.lookup(entries,force=payload.get('force') is True,stop=stop.exists,progress=lambda x:atomic(progress,x))
   except ValueError as e:raise BlacklistError(str(e))
   return dict(lookup=result)

  if action=='load':
   c=self.config()
   if not self.text_path.exists():self.persist(c)
   actual=self.fw(self.plan(owner,'status',c.get('program',''),parse_list(c['text'])),job);return dict(config=c,actual=actual,lookup_cache=self.resolver.rows())
  if action=='status':
   entries=parse_list(payload.get('text',''));program=payload.get('program','')
   if program:program,_=verify_program(program)
   return dict(actual=self.fw(self.plan(owner,'status',program,entries),job))
  if action=='restore':
   result=self.fw(self.plan(owner,'restore'),job)
   if result.get('absence_verified') is not True:raise BlacklistError('restore_not_verified_keep_folder')
   try:c=self.config()
   except BlacklistError:
    # Restoration must work even with invalid settings/TXT, without destroying the user's list.
    self.report(action,[],result,job);return dict(actual=result,settings_preserved=True)
   c['phase']='restored';self.persist(c);self.report(action,[],result,job);return dict(config=c,actual=result)
  if action=='observe':
   program,sha=verify_program(payload.get('program'));seconds=payload.get('seconds',120)
   if type(seconds) is not int or seconds not in (0,60,120,300):raise BlacklistError('invalid_observe_duration')
   stop=self.private/('job-'+job+'.stop');ready=self.private/('job-'+job+'.ready')
   baseline=history_baseline(self.captures)
   plan=dict(program=program,program_sha256=sha,seconds=seconds,parent_pid=os.getpid(),stop_path=str(stop),ready_path=str(ready),capture_id=job,phase_path=str(self.private/('job-'+job+'.phase.json')),event_evidence_enabled=True,program_device_path=device_program_path(program),hosts_baseline=hosts_baseline(self.hosts_reader),live_path=str(self.private/('job-'+job+'.live.json')),history_baseline=baseline,public_exclusions_v4=[str(x) for x in V4_SPECIAL],public_exclusions_v6=[str(x) for x in V6_SPECIAL])
   start_snapshot=self.block_snapshot(owner,program,job);plan['block_snapshot_start']=start_snapshot;plan['stage_baseline']={k:sorted({code for source in values for code in source['stages']}) for k,values in self.captures.stage_history().items()}
   raw=self.collector(plan,job);evidence=normalize_evidence(raw.get('event_evidence'));rows=normalize_rows(raw.get('endpoints',[]));snapshot=self.block_snapshot(owner,program,job)
   from phase_context import clean_recording
   report=dict(schema='wow-blacklist-destinations-2',version=VERSION,capture_id=job,phase_recording=clean_recording(raw.get('phase_recording'),raw.get('capture_started_utc'),raw.get('capture_ended_utc')),event_evidence=evidence,history_baseline={k:v for k,v in baseline.items() if k!='keys'},program_sha256=sha,endpoints=classify_rows(rows,snapshot),block_snapshot_start=start_snapshot,block_snapshot=snapshot,seconds=raw.get('seconds'),query_errors=raw.get('query_errors'),capture_started_utc=timestamp(raw.get('capture_started_utc')),capture_ended_utc=timestamp(raw.get('capture_ended_utc')),truncated=raw.get('truncated') is True,scope='sampled_TCP_state_metadata_selected_executable_per_process',UDP_remote_destinations_collected=False,DNS_requests_collected=any(e['kind']=='dns_query' for e in evidence['events']),payload_collected=False,firewall_changed_by_observe=False,packet_drop_verified=False,utc_epoch=time.time())
   atomic(self.output/('destinations-'+job+'.json'),report);labels=recover_live_labels(self,job);result=self.captures.read(job);result['live_annotation_recovery']=labels;return dict(observation=result)
  if action not in ('save','apply'):raise BlacklistError('invalid_action')
  c=self.config();entries=parse_list(payload.get('text',''));program=payload.get('program','')
  sha=None
  if program:program,sha=verify_program(program)
  if c.get('program')==program and c.get('program_sha256') and sha!=c['program_sha256'] and payload.get('program_reselected') is not True:raise BlacklistError('game_changed_select_Wow_exe_again')
  if action=='apply':
   if c['phase'] in ('applying','needs_restore'):raise BlacklistError('previous_operation_unverified_Restore_first')
   if not program:raise BlacklistError('select_existing_Wow_exe')
   if not entries and payload.get('empty_restore_consent') is not True:raise BlacklistError('empty_list_use_Restore')
   if payload.get('persistent_consent') is not True:raise BlacklistError('explicit_persistent_consent_required')
   if any('/' in e['ip'] for e in entries) and payload.get('range_consent') is not True:raise BlacklistError('network_range_requires_extra_confirmation')
   if any(covers(e,'37.244.29.11') and e['port']==3724 and e['protocol']=='TCP' for e in entries) and payload.get('critical_consent') is not True:raise BlacklistError('known_login_endpoint_requires_extra_confirmation')
  c.update(program=program,program_sha256=sha,text=format_list(entries))
  if action=='save':self.persist(c);return dict(config=c,saved_only=True)
  c['phase']='applying';self.persist(c)
  try:
   result=self.fw(self.plan(owner,'apply' if entries else 'restore',program,entries),job)
   if entries:
    if result.get('config_verified') is not True or result.get('persistent_count')!=len(entries) or result.get('active_count')!=len(entries):raise BlacklistError('apply_readback_incomplete_Restore_required')
   elif result.get('absence_verified') is not True:raise BlacklistError('restore_not_verified_keep_folder')
  except Exception:
   c['phase']='needs_restore';self.persist(c);raise
  c['phase']='applied' if entries else 'restored';c['applied_utc_epoch']=time.time();self.persist(c);self.report(action,entries,result,job,sha);return dict(config=c,actual=result)

def cli():
 p=Path(sys.argv[1]).resolve();private=(BASE/'private-state').resolve()
 if p.parent!=private or not re.fullmatch(r'job-[a-f0-9]{32}\.request\.json',p.name):raise BlacklistError('invalid_request_location')
 job=p.name[4:36];out=p.with_name('job-'+job+'.result.json')
 try:
  request=json.loads(p.read_text('utf-8-sig'));result=Manager().run(request['action'],request.get('payload'),job);result={'ok':True,**result}
 except Exception as e:
  code=str(e);code=code if re.fullmatch('[A-Za-z0-9_]{1,140}',code) else 'operation_failed_keep_folder_use_Restore'
  result=dict(ok=False,error=code)
 atomic(out,result)
if __name__=='__main__':cli()
