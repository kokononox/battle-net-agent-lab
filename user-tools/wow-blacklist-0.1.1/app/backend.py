"""Persistent, app-scoped blacklist manager. No HTTP listener or packet interception."""
import base64,hashlib,ipaddress,json,os,re,secrets,subprocess,sys,time,uuid
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
VERSION='0.1.1'
MAX_ENTRIES=100
class BlacklistError(Exception):pass

def atomic(path,obj):
 path=Path(path);tmp=path.with_name(path.name+'.tmp')
 with tmp.open('w',encoding='utf-8') as f:json.dump(obj,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
 os.replace(tmp,path)
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
  match=re.fullmatch(r'(\[[0-9a-fA-F:]+\]|[0-9.]+):([0-9]{1,5})\s+(TCP|UDP)',line,re.I)
  if not match:raise BlacklistError('invalid_line_'+str(line_no))
  try:ip=ipaddress.ip_address(match[1].strip('[]'))
  except ValueError:raise BlacklistError('invalid_ip_line_'+str(line_no))
  if not ip.is_global or ip.is_multicast or ip.is_unspecified or ip.is_reserved:raise BlacklistError('public_unicast_required_line_'+str(line_no))
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
 env=os.environ.copy();env['WOW_BL_REQUEST']=str(path)
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
 def __init__(self,root=BASE,fw=None,collector=None):
  self.root=Path(root);self.private=self.root/'private-state';self.private.mkdir(exist_ok=True);self.output=self.root/'output';self.output.mkdir(exist_ok=True)
  self.fw=fw or (lambda plan,job:powershell('firewall.ps1',plan,self.private,job));self.collector=collector or (lambda plan,job:powershell('observe.ps1',plan,self.private,job))
  self.config_path=self.private/'settings.json'
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
  if any(p.exists() for p in paths) or self.config_path.exists() or not create:raise BlacklistError('owner_id_missing_or_invalid_keep_folder')
  owner=uuid.uuid4().hex
  for p in paths:atomic(p,{'schema':'wow-blacklist-owner-1','owner':owner})
  return owner
 def config(self):
  if self.config_path.exists():
   try:
    c=json.loads(self.config_path.read_text('utf-8'));parse_list(c['text']);assert c['phase'] in {'never_applied','saved','applying','applied','needs_restore','restored'};return c
   except Exception:raise BlacklistError('settings_invalid_Restore_still_available')
  seeds=json.loads((self.root/'app/defaults.json').read_text('utf-8'))
  return dict(program='',program_sha256=None,text=format_list(seeds),phase='never_applied')
 def persist(self,c):
  if self.config_path.exists():
   try:atomic(self.private/'settings.previous.json',json.loads(self.config_path.read_text('utf-8')))
   except (ValueError,OSError):pass
  atomic(self.config_path,c)
 def plan(self,owner,action,program='',entries=()):
  return dict(schema='wow-blacklist-plan-1',owner=owner,action=action,program=program,entries=[spec(owner,program,e) for e in entries])
 def report(self,action,entries,result,job,sha=None):
  safe={k:result[k] for k in ('persistent_count','active_count','config_verified','absence_verified','removed_count') if k in result}
  atomic(self.output/('blacklist-result-'+job+'.json'),dict(schema='wow-blacklist-result-1',version=VERSION,action=action,utc_epoch=time.time(),program_sha256=sha,endpoints=entries,**safe,persistent_until_explicit_restore=True,packet_block_verified=False,credentials_collected=False))
 def run(self,action,payload=None,job=None):
  payload=payload or {};job=job or uuid.uuid4().hex;owner=self.owner(create=action=='load')
  if action=='load':
   c=self.config();actual=self.fw(self.plan(owner,'status',c.get('program',''),parse_list(c['text'])),job);return dict(config=c,actual=actual)
  if action=='status':
   entries=parse_list(payload.get('text',''));program=payload.get('program','')
   if program:program,_=verify_program(program)
   return dict(actual=self.fw(self.plan(owner,'status',program,entries),job))
  if action=='restore':
   result=self.fw(self.plan(owner,'restore'),job)
   if result.get('absence_verified') is not True:raise BlacklistError('restore_not_verified_keep_folder')
   try:c=self.config()
   except BlacklistError:c=dict(program='',program_sha256=None,text='',phase='needs_restore')
   c['phase']='restored';self.persist(c);self.report(action,[],result,job);return dict(config=c,actual=result)
  if action=='observe':
   program,sha=verify_program(payload.get('program'));seconds=payload.get('seconds',120)
   if type(seconds) is not int or seconds not in (60,120,300):raise BlacklistError('invalid_observe_duration')
   stop=self.private/('job-'+job+'.stop');ready=self.private/('job-'+job+'.ready')
   plan=dict(program=program,program_sha256=sha,seconds=seconds,parent_pid=os.getpid(),stop_path=str(stop),ready_path=str(ready))
   raw=self.collector(plan,job);rows=[];seen=set()
   for item in raw.get('endpoints',[])[:2000]:
    try:
     ip=ipaddress.ip_address(item['ip']);port=item['port']
     if not ip.is_global or ip.is_multicast or ip.is_reserved or type(port) is not int or not 1<=port<=65535:continue
     key=(str(ip),port)
     if key in seen:continue
     seen.add(key);rows.append(dict(ip=str(ip),port=port,protocol='TCP',samples=max(0,int(item.get('samples',0))),fresh_process_seen=item.get('fresh_process_seen') is True))
    except (KeyError,TypeError,ValueError):continue
   report=dict(schema='wow-blacklist-destinations-1',version=VERSION,program_sha256=sha,endpoints=rows,seconds=raw.get('seconds'),query_errors=raw.get('query_errors'),scope='sampled_TCP_metadata_selected_executable_only',UDP_remote_destinations_collected=False,payload_collected=False,firewall_changed_by_observe=False,utc_epoch=time.time())
   atomic(self.output/('destinations-'+job+'.json'),report);return dict(observation=report)
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
   if any(e['ip']=='37.244.29.11' and e['port']==3724 and e['protocol']=='TCP' for e in entries) and payload.get('critical_consent') is not True:raise BlacklistError('known_login_endpoint_requires_extra_confirmation')
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
