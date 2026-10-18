import collections
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
from body_meta import analyze_body
from native_identity import identity

APIS={'WinHttpConnect','WinHttpOpenRequest','WinHttpSendRequest','WinHttpWriteData','WinHttpCloseHandle','InternetConnectA','InternetConnectW','HttpOpenRequestA','HttpOpenRequestW','HttpSendRequestA','HttpSendRequestW','InternetWriteFile','InternetCloseHandle','EncryptMessage','SSL_write','SSL_write_ex'}
BUFFER_APIS={'WinHttpSendRequest','WinHttpWriteData','HttpSendRequestA','HttpSendRequestW','InternetWriteFile','EncryptMessage','SSL_write','SSL_write_ex'}
MODULE_NAMES={'secur32.dll','sspicli.dll','schannel.dll','winhttp.dll','wininet.dll','crypt32.dll','cryptnet.dll','ncrypt.dll','bcrypt.dll','ws2_32.dll','dnsapi.dll'}

def module_category(name):
 s=Path(name).name.lower()
 if s in MODULE_NAMES:return s
 if re.fullmatch('libssl[^/\\\\]*\\.dll',s):return 'openssl_ssl_module'
 if re.fullmatch('libcrypto[^/\\\\]*\\.dll',s):return 'openssl_crypto_module'
 if re.fullmatch('libcurl[^/\\\\]*\\.dll',s):return 'libcurl_module'
 return None

def path_category(path):
 parts=[p.lower() for p in Path(path).parts]
 if 'agent' in parts and 'battle.net' in parts:return 'battle_net_agent_tree'
 if any(p.startswith('agent.') for p in parts):return 'agent_version_tree'
 if 'temp' in parts or '_temp' in parts:return 'temporary_tree'
 if any(p.startswith('program files') for p in parts):return 'program_files_tree'
 return 'other'

class Monitor:
 def __init__(self,obs,api,frida,host_sanitizer):
  self.obs=obs;self.api=api;self.frida=frida;self.host_sanitizer=host_sanitizer;self.stop=threading.Event()
  self.rows=[];self.sessions=[];self.attempted=set();self.events=[];self.lock=threading.Lock();self.error_count=0;self.dropped=0;self.snapshots=0;self.limit=False
  self.device=frida.get_local_device();self.verify_signature=obs.signature
 def bounded(self,fn):
  c=self.frida.Cancellable();timer=threading.Timer(8,c.cancel);timer.daemon=True;timer.start()
  try:return fn(c)
  finally:timer.cancel()
 def message(self,row,msg,data):
  with self.lock:
   if msg.get('type')!='send':row['script_error_count']+=1;return
   d=msg.get('payload')
   if not isinstance(d,dict):row['script_error_count']+=1;return
   if d.get('kind')=='installed' and d.get('api') in APIS:
    if d['api'] not in row['installed_hooks']:row['installed_hooks'].append(d['api'])
    return
   if d.get('kind')!='buffer' or d.get('api') not in BUFFER_APIS:return
   if len(self.events)>=512:self.dropped+=1;return
   n=d.get('declared_length')
   if type(n) is not int or not 0<=n<=67108864:return
   raw=bytes(data or b'')[:16384]
   meta=analyze_body(raw,n,d.get('readable') is True)
   meta['http_host']=self.host_sanitizer(meta['http_host']) if meta['http_host'] else None
   h=self.host_sanitizer(d.get('host')) if d.get('host') else None
   method=d.get('method') if d.get('method') in ('GET','POST','PUT','HEAD','OPTIONS','CONNECT','DELETE','PATCH') else None
   event={'pid':row['pid'],'process_sha256':row['sha256'],'api':d['api'],'declared_length':n,'sample_bytes':len(raw),'buffer_truncated':d.get('truncated') is True,'api_success':d.get('api_success') is True,'request_host_hint':h,'request_method_hint':method,**meta}
   self.events.append(event);row['buffer_events']+=1
 def attach(self,p):
  pid=p['ProcessId'];name=p['Name'].lower()
  row={'pid':pid,'process_name':name,'image_basename_match':False,'sha256':None,'image_bytes':0,'path_category':'other','agent_directory_version':None,'signature_accepted':False,'authenticode_valid':False,'expected_blizzard_publisher':False,'module_status':'not_tested','network_module_categories':[],'attach_status':'not_attempted','failure_phase':None,'error_kind':None,'numeric_error_code':None,'installed_hooks':[],'buffer_events':0,'script_error_count':0}
  self.rows.append(row)
  session=None;phase='identity'
  try:
   first=identity(pid);path=Path(first['path']);row['image_basename_match']=path.name.lower()==name
   if not row['image_basename_match'] or self.obs.is_reparse(path) or not 0<path.stat().st_size<=128*1024*1024:row['attach_status']='image_refused';return
   row['image_bytes']=path.stat().st_size;row['path_category']=path_category(path)
   for part in path.parts:
    m=re.fullmatch('Agent\\.([0-9]{1,10})',part,re.I)
    if m:row['agent_directory_version']=int(m.group(1))
   phase='hash';sha=hashlib.sha256()
   with path.open('rb') as f:
    while True:
     b=f.read(1024*1024)
     if not b:break
     sha.update(b)
   row['sha256']=sha.hexdigest()
   phase='signature'
   sig=self.verify_signature(path,self.obs.clean_environment(os.environ))
   for key in ('authenticode_valid','expected_blizzard_publisher'):row[key]=sig[key] is True
   row['signature_accepted']=sig['accepted_for_execution'] is True
   row['module_status']=first['module_status'];row['network_module_categories']=sorted({x for x in map(module_category,first['modules']) if x})
   if not row['signature_accepted']:row['attach_status']='signature_refused';return
   phase='frida_attach'
   session=self.bounded(lambda c:self.device.attach(pid,cancellable=c))
   phase='identity_recheck'
   second=identity(pid)
   if second['path'].lower()!=first['path'].lower() or second['creation']!=first['creation']:row['attach_status']='identity_changed';session.detach();return
   phase='script_load'
   script=session.create_script(Path(__file__).with_name('hook.js').read_text(encoding='utf-8'))
   script.on('message',lambda msg,data:self.message(row,msg,data))
   self.bounded(lambda c:script.load(cancellable=c));self.sessions.append((session,script,row));row['attach_status']='attached'
   row['module_status']=second['module_status'];row['network_module_categories']=sorted(set(row['network_module_categories'])|{x for x in map(module_category,second['modules']) if x})
  except Exception as exc:
   row['attach_status']='process_gone_or_probe_failed';row['failure_phase']=phase
   kind=type(exc).__name__;row['error_kind']=kind if kind in {'ProcessNotFoundError','PermissionDeniedError','TimedOutError','OperationCancelledError','ProcessNotRespondingError','InvalidOperationError','OSError','FileNotFoundError','Exception','TypeError','NotSupportedError','TransportError'} else 'other'
   code=getattr(exc,'winerror',None);row['numeric_error_code']=code if type(code) is int and -2**31<=code<2**31 else None
   if session is not None:
    try:session.detach()
    except Exception:pass
 def run(self):
  start=time.monotonic()
  while not self.stop.is_set() and time.monotonic()-start<300:
   try:
    snapshot=self.api(self.obs.NAMES);self.snapshots+=1
    for p in snapshot['processes']:
     pid=p['ProcessId']
     if pid in self.attempted:continue
     if len(self.attempted)>=8:self.limit=True;continue
     self.attempted.add(pid);self.attach(p)
   except Exception:self.error_count+=1
   self.stop.wait(.2)
  if not self.stop.is_set():self.error_count+=1
 def finish(self):
  self.stop.set()
  for session,script,row in self.sessions:
   try:self.bounded(lambda c:session.detach(cancellable=c))
   except Exception:pass
 def result(self):
  # Process/module paths and binary buffer data were never stored in this result.
  return {'processes':self.rows,'events':self.events,'monitor_stats':{'snapshots':self.snapshots,'errors':self.error_count,'process_limit_hit':self.limit,'dropped_events':self.dropped}}
