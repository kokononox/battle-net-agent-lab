"""One explicitly approved Classic baseline installation on a fresh hosted Windows VM.
Not an updater, not a policy oracle. No game execution/account/country/legal bypass.
"""
import ctypes
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
import probe

APPROVAL='lab: approved disposable Classic baseline install 2026-10-18 73ca6e92'
PRODUCT='wow_classic_era'
SCHEMA='classic-baseline-install-2'
DIAGNOSTIC_APPROVAL='lab: approved Classic initialization protocol diagnostic 2026-10-18 d2097c4e'
MIN_FREE=40*1024**3
RESERVE=10*1024**3
MAX_POLLS=120
STATUSES={'not_started','environment_refused','disk_refused','target_refused','discovery_failed',
 'handshake_not_ready','identity_changed','request_refused','response_refused','agent_error',
 'existing_products_refused','initialization_form_unknown','authentication_required',
 'legal_consent_required','minimum_spec_refused','game_dir_refused','installation_queued',
 'install_observation_timeout','agent_installed_build_unverified','baseline_agent_complete',
 'stopped_safely','initialization_inspected'}
FORM_FIELDS={'authentication','game_dir','min_spec','language','eula'}

def blank():
 return dict(schema=SCHEMA,source_commit=os.environ.get('GITHUB_SHA',''),
  run_id=os.environ.get('GITHUB_RUN_ID',''),run_attempt=os.environ.get('GITHUB_RUN_ATTEMPT',''),
  status='not_started',handshake=probe.blank(),scope='fresh_disposable_windows_classic_only',
  approval_present=False,product=PRODUCT,region='eu',locale='enUS',architecture='x86_64',
  observed_version=None,observed_build_config=None,versions_sha256=None,
  destination_fixed_drive=False,destination_new_empty=False,
  destination_free_before_bytes=0,system_free_before_bytes=0,
  destination_free_after_bytes=0,system_free_after_bytes=0,
  minimum_free_before_bytes=MIN_FREE,reserve_free_bytes=RESERVE,
  min_destination_free_observed_bytes=0,min_system_free_observed_bytes=0,
  protocol_diagnostic_only=False,identity_check_count=0,last_identity_state=None,
  last_identity_stage=None,identity_failure_state=None,identity_failure_stage=None,
  initialization_http_status=None,initialization_response_bytes=0,
  initialization_json_object=False,initialization_form_present=False,initialization_form_field_count=0,
  total_local_requests=0,initialization_attempted=False,finalization_attempted=False,
  initial_game_summary_empty=False,initialization_response_accepted=False,
  form_fields_observed=[],unknown_form_fields=False,
  auth_error_code=None,min_spec_error_code=None,game_dir_error_code=None,
  last_local_http_status=None,last_agent_error_code=None,polls=0,
  agent_installed=None,agent_download_complete=None,agent_build_identity_matches=False,
  owned_build_info_read=False,owned_build_info_bytes_read=0,
  game_update_requested=False,repair_requested=False,uninstall_requested=False,
  account_login_attempted=False,country_fabricated=False,legal_terms_accepted=False,
  game_executed=False,user_files_accessed=False,raw_response_exported=False,
  token_exported=False,game_payload_exported=False,retail_policy_proven=False,
  version_to_version_update_proven=False,child_network_hard_byte_cap=False,
  process_cleanup_scope='disposable_job_and_existing_probe_cleanup',
  initialization_may_trigger_network=True,elapsed_seconds=0)

MUTABLE_FLAGS={'approval_present','destination_fixed_drive','destination_new_empty',
 'initialization_attempted','finalization_attempted','initial_game_summary_empty',
 'initialization_response_accepted','unknown_form_fields','agent_build_identity_matches',
 'owned_build_info_read','protocol_diagnostic_only','initialization_json_object','initialization_form_present'}
def validate(r):
 t=blank()
 if type(r)is not dict or set(r)!=set(t):raise ValueError('install_schema')
 for k,v in t.items():
  if type(v)is bool and (type(r[k])is not bool or k not in MUTABLE_FLAGS and r[k]!=v):raise ValueError('install_flag')
 if r['schema']!=SCHEMA or r['status']not in STATUSES or r['product']!=PRODUCT:raise ValueError('install_enum')
 for k in ('scope','region','locale','architecture','process_cleanup_scope','minimum_free_before_bytes','reserve_free_bytes'):
  if r[k]!=t[k]:raise ValueError('install_fixed')
 probe.validate(r['handshake'])
 for k in ('source_commit','run_id','run_attempt'):
  if r[k]!=r['handshake'][k]:raise ValueError('install_identity')
 for k,cap in [('total_local_requests',124),('polls',MAX_POLLS),('owned_build_info_bytes_read',65537),('elapsed_seconds',1800)]+[(x,2**60)for x in t if x.endswith('_bytes') and ('free' in x or 'observed' in x)]:
  if type(r[k])is not int or not 0<=r[k]<=cap:raise ValueError('install_count')
 if type(r['form_fields_observed'])is not list or len(r['form_fields_observed'])>5 or len(set(r['form_fields_observed']))!=len(r['form_fields_observed'])or not set(r['form_fields_observed'])<=FORM_FIELDS:raise ValueError('form_fields')
 for k in ('auth_error_code','min_spec_error_code','game_dir_error_code','last_agent_error_code'):
  if r[k]is not None and(type(r[k])not in(int,float)or not 0<=r[k]<=2**32):raise ValueError('error_code')
 for k in ('agent_installed','agent_download_complete'):
  if r[k]is not None and type(r[k])is not bool:raise ValueError('install_boolean')
 if r['last_local_http_status']is not None and(type(r['last_local_http_status'])is not int or not 100<=r['last_local_http_status']<=599):raise ValueError('http_status')
 if r['observed_version']is not None and re.fullmatch(r'\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,10}',r['observed_version'])is None:raise ValueError('version')
 for k,n in [('observed_build_config',32),('versions_sha256',64)]:
  if r[k]is not None and re.fullmatch('[0-9a-f]{'+str(n)+'}',r[k])is None:raise ValueError('hash')
 for k,cap in [('identity_check_count',256),('initialization_response_bytes',probe.MAX_BODY),('initialization_form_field_count',32)]:
  if type(r[k])is not int or not 0<=r[k]<=cap:raise ValueError('protocol_count')
 if r['initialization_http_status']is not None and(type(r['initialization_http_status'])is not int or not 100<=r['initialization_http_status']<=599):raise ValueError('protocol_http')
 for k in ('last_identity_state','identity_failure_state'):
  if r[k]is not None and r[k]not in probe.IDENTITY_STATES:raise ValueError('identity_state')
 for k in ('last_identity_stage','identity_failure_stage'):
  if r[k]is not None and r[k]not in probe.IDENTITY_STAGES:raise ValueError('identity_stage')
 if r['identity_failure_state']=='verified':raise ValueError('identity_false_failure')
 if (r['last_identity_state']is None)!=(r['last_identity_stage']is None):raise ValueError('identity_state_stage')
 if (r['identity_failure_state']is None)!=(r['identity_failure_stage']is None):raise ValueError('identity_failure_pair')
 if r['protocol_diagnostic_only']and(r['finalization_attempted']or r['total_local_requests']>2):raise ValueError('diagnostic_mutation')
 if r['status']=='initialization_inspected'and not(r['protocol_diagnostic_only']and r['initialization_response_accepted']and r['initialization_json_object']and r['identity_failure_state']is None and r['identity_check_count']>0 and r['last_identity_state']=='verified'):raise ValueError('diagnostic_evidence')
 if r['initialization_attempted'] and not all(r[k]for k in ('approval_present','destination_fixed_drive','destination_new_empty','initial_game_summary_empty')):raise ValueError('unsafe_initialization')
 if r['finalization_attempted'] and (not r['initialization_response_accepted']or not r['initialization_attempted']):raise ValueError('unsafe_finalization')
 if r['status']=='baseline_agent_complete' and not(r['finalization_attempted']and r['agent_installed']is True and r['agent_download_complete']is True and r['agent_build_identity_matches']and r['owned_build_info_read']):raise ValueError('completion_evidence')
 return r

def fresh_environment(env,platform):
 return probe.fresh_environment(env,platform) and env.get('CLASSIC_INSTALL_ONCE')==APPROVAL

def error_code(data):
 value=data.get('error',0)
 if type(value)not in (int,float) or not 0<=value<=2**32:raise probe.Stop('response_refused')
 return value

class Session:
 def __init__(self,port,token,verify,r,connection_factory=http.client.HTTPConnection):
  if type(port)is not int or not 1<=port<=65535 or type(token)is not str or re.fullmatch('[!-~]{1,8192}',token)is None:raise probe.Stop('request_refused')
  self.port=port;self.token=token;self.verify=verify;self.r=r;self.factory=connection_factory;self.init=False;self.final=False
 def request(self,method,path,payload=None):
  allowed=(method=='GET' and path in('/game','/game/'+PRODUCT))or(method=='POST'and path in('/install','/install/'+PRODUCT))
  if not allowed or (method=='GET'and payload is not None) or(method=='POST'and type(payload)is not dict)or self.r['total_local_requests']>=124:raise probe.Stop('request_refused')
  if self.r['protocol_diagnostic_only']and(path=='/install/'+PRODUCT or self.r['total_local_requests']>=2):raise probe.Stop('request_refused')
  if path=='/install':
   if self.init:raise probe.Stop('request_refused')
   self.init=True
  if path=='/install/'+PRODUCT:
   if self.final or not self.init or not self.r['initialization_response_accepted']:raise probe.Stop('request_refused')
   self.final=True
  if self.verify()is not True:raise probe.Stop('identity_changed')
  self.r['total_local_requests']+=1
  if method=='POST':self.r['initialization_attempted'if path=='/install'else'finalization_attempted']=True
  body=None if payload is None else json.dumps(payload,separators=(',',':')).encode('ascii')
  if body is not None and len(body)>4096:raise probe.Stop('request_refused')
  headers={'Authorization':self.token,'User-Agent':'phoenix-agent/1.0','Accept':'application/json','Accept-Encoding':'identity','Connection':'close'}
  if body is not None:headers['Content-Type']='application/json'
  conn=self.factory('127.0.0.1',self.port,timeout=10)
  try:
   conn.request(method,path,body=body,headers=headers);response=conn.getresponse();self.r['last_local_http_status']=response.status
   if method=='POST'and path=='/install':self.r['initialization_http_status']=response.status
   accepted=(200,201)if method=='POST'and path=='/install'else(200,)
   if response.status not in accepted or response.getheader('Content-Encoding','identity').lower()not in('','identity'):raise probe.Stop('response_refused')
   n=response.getheader('Content-Length')
   if n is not None and(re.fullmatch('[0-9]{1,10}',n)is None or int(n)>probe.MAX_BODY):raise probe.Stop('response_refused')
   raw=response.read(probe.MAX_BODY+1)
   if len(raw)>probe.MAX_BODY or n is not None and len(raw)!=int(n):raise probe.Stop('response_refused')
   if path=='/install':self.r['initialization_response_bytes']=len(raw)
   try:data=probe.unique_json(raw)
   except Exception:raise probe.Stop('response_refused')from None
   if path=='/install':
    self.r['initialization_json_object']=True
    form=data.get('form');self.r['initialization_form_present']=type(form)is dict
    if type(form)is dict and len(form)<=32:
     self.r['initialization_form_field_count']=len(form)
     self.r['form_fields_observed']=sorted(set(form)&FORM_FIELDS)
     self.r['unknown_form_fields']=bool(set(form)-FORM_FIELDS)
   if self.verify()is not True:raise probe.Stop('identity_changed')
   code=error_code(data);self.r['last_agent_error_code']=code
   # Initialization forms may carry a global error about an unfilled game directory.
   if code>0 and path!='/install':raise probe.Stop('agent_error')
   return data
  finally:conn.close()

def inspect_form(data,r):
 form=data.get('form')
 if type(form)is not dict or len(form)>32:raise probe.Stop('initialization_form_unknown')
 r['form_fields_observed']=sorted(set(form)&FORM_FIELDS);r['unknown_form_fields']=bool(set(form)-FORM_FIELDS)
 # Never auto-accept any legal checkbox, even when a third-party wrapper does.
 if 'eula'in form:raise probe.Stop('legal_consent_required')
 for name,out,stop in [('authentication','auth_error_code','authentication_required'),('min_spec','min_spec_error_code','minimum_spec_refused'),('game_dir','game_dir_error_code','game_dir_refused')]:
  part=form.get(name)
  if type(part)is not dict or 'error'not in part:raise probe.Stop('initialization_form_unknown')
  code=error_code(part);r[out]=code
  if code>0:raise probe.Stop(stop)
 if r['unknown_form_fields']or error_code(data)>0:raise probe.Stop('initialization_form_unknown')
 r['initialization_response_accepted']=True

def initialized_payload():
 return dict(instructions_dataset=['torrent','win',PRODUCT,'enUS'],
  instructions_patch_url='http://eu.patch.battle.net:1119/'+PRODUCT,
  instructions_product='NGDP',monitor_pid=0,priority={'insert_at_head':True,'value':900},uid=PRODUCT)

def finalized_payload(target):
 # Do not invent account_country/geo_ip_country or silently accept EULA.
 return dict(finalized=True,game_dir=str(target),language=['enUS'],selected_asset_locale='enUS',selected_locale='enUS')

def disk_pair(target,system):return shutil.disk_usage(target).free,shutil.disk_usage(system).free

def sample_disk(target,system,r,first=False):
 d,s=disk_pair(target,system)
 if first:
  r['destination_free_before_bytes']=d;r['system_free_before_bytes']=s
  r['min_destination_free_observed_bytes']=d;r['min_system_free_observed_bytes']=s
 else:
  r['min_destination_free_observed_bytes']=min(d,r['min_destination_free_observed_bytes']);r['min_system_free_observed_bytes']=min(s,r['min_system_free_observed_bytes'])
 if min(d,s)<(MIN_FREE if first else RESERVE):raise probe.Stop('disk_refused')
 return d,s

def make_target(r,is_reparse):
 temp=Path(os.environ['RUNNER_TEMP']).resolve();system=Path(os.environ['SystemDrive']+'\\')
 drive_type=ctypes.windll.kernel32.GetDriveTypeW;drive_type.argtypes=[ctypes.c_wchar_p];drive_type.restype=ctypes.c_uint
 if not temp.is_absolute()or is_reparse(temp)or drive_type(str(Path(temp.anchor)))!=3:raise probe.Stop('target_refused')
 for path in (temp,*temp.parents):
  if is_reparse(path):raise probe.Stop('target_refused')
 r['destination_fixed_drive']=True;sample_disk(temp,system,r,first=True)
 target=temp/('classic-baseline-'+r['run_id']);target.mkdir(exist_ok=False)
 if is_reparse(target)or any(target.iterdir()):raise probe.Stop('target_refused')
 r['destination_new_empty']=True
 return target,system

def discover(r):
 sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'classic-metadata-lab'))
 from preflight import Client,table,one,key
 raw=Client().fetch('https://eu.version.battle.net/v2/products/'+PRODUCT+'/versions',1024**2)
 row=one(table(raw),'Region','eu');version=row['VersionsName'];build=key(row['BuildConfig'])
 if re.fullmatch(r'\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,10}',version)is None:raise probe.Stop('discovery_failed')
 r['observed_version']=version;r['observed_build_config']=build;r['versions_sha256']=hashlib.sha256(raw).hexdigest()

def build_identity(target,r,is_reparse):
 path=target/'.build.info'
 if not path.is_file()or is_reparse(path)or is_reparse(target)or path.stat().st_size>65536:return False
 with path.open('rb')as f:raw=f.read(65537)
 r['owned_build_info_read']=True;r['owned_build_info_bytes_read']=len(raw)
 if len(raw)>65536:return False
 try:
  sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'classic-metadata-lab'))
  from preflight import table
  rows=table(raw)
  matches=[x for x in rows if x.get('Active')=='1'and x.get('Build Key')==r['observed_build_config']and x.get('Version')==r['observed_version']]
  return len(matches)==1
 except Exception:return False

def observe(token,port,verify,r,target,system,is_reparse,sleep=time.sleep,clock=time.monotonic):
 session=Session(port,token,verify,r)
 summary=session.request('GET','/game')
 if summary not in ({},{'error':0}):raise probe.Stop('existing_products_refused')
 r['initial_game_summary_empty']=True
 sample_disk(target,system,r)
 data=session.request('POST','/install',initialized_payload());inspect_form(data,r)
 if r['protocol_diagnostic_only']:
  r['status']='initialization_inspected';return
 sample_disk(target,system,r)
 session.request('POST','/install/'+PRODUCT,finalized_payload(target));r['status']='installation_queued'
 end=clock()+20*60
 for i in range(MAX_POLLS):
  if clock()>=end:break
  sample_disk(target,system,r)
  data=session.request('GET','/game/'+PRODUCT);r['polls']+=1
  installed=data.get('installed');complete=data.get('download_complete')
  if type(installed)is not bool or type(complete)is not bool:raise probe.Stop('response_refused')
  r['agent_installed']=installed;r['agent_download_complete']=complete
  if installed and complete:
   r['agent_build_identity_matches']=build_identity(target,r,is_reparse)
   r['status']='baseline_agent_complete'if r['agent_build_identity_matches']else'agent_installed_build_unverified';return
  sleep(10)
 r['status']='install_observation_timeout'

def record_identity(r,state,stage):
 if state not in probe.IDENTITY_STATES or stage not in probe.IDENTITY_STAGES:raise ValueError('identity_enum')
 r['identity_check_count']+=1;r['last_identity_state']=state;r['last_identity_stage']=stage
 if state!='verified'and r['identity_failure_state']is None:
  r['identity_failure_state']=state;r['identity_failure_stage']=stage

def run(out,diagnostic_only=False):
 if type(diagnostic_only)is not bool:raise ValueError('diagnostic_mode')
 r=blank();r['protocol_diagnostic_only']=diagnostic_only;start=time.monotonic();target=system=None
 try:
  if not fresh_environment(os.environ,sys.platform):raise probe.Stop('environment_refused')
  if diagnostic_only and os.environ.get('CLASSIC_PROTOCOL_ONCE')!=DIAGNOSTIC_APPROVAL:raise probe.Stop('environment_refused')
  r['approval_present']=True
  # New identity is read before any installation request. No use of a stale pinned build.
  try:discover(r)
  except Exception:raise probe.Stop('discovery_failed')from None
  def observer(token,port,verify):
   nonlocal target,system
   try:
    import observe_agent as lab
    target,system=make_target(r,lab.is_reparse)
    observe(token,port,verify,r,target,system,lab.is_reparse)
   except probe.Stop as e:r['status']=str(e)if str(e)in STATUSES else'stopped_safely'
   except Exception:r['status']='stopped_safely'
   finally:
    if target is not None:
     try:r['destination_free_after_bytes'],r['system_free_after_bytes']=disk_pair(target,system)
     except OSError:pass
  def identity_observer(state,stage):record_identity(r,state,stage)
  r['handshake']=probe.run(out,after_handshake=observer,report_sink=r['handshake'],identity_observer=identity_observer)
  if r['status']=='not_started':r['status']='handshake_not_ready'
  if r['handshake']['status']!='handshake_token_observed'and r['status']in('baseline_agent_complete','initialization_inspected'):r['status']='identity_changed'
 except probe.Stop as e:r['status']=str(e)if str(e)in STATUSES else'stopped_safely'
 except Exception:r['status']='stopped_safely'
 finally:
  r['elapsed_seconds']=min(1800,int(time.monotonic()-start));validate(r)
  out.mkdir(exist_ok=True,parents=True);(out/'classic-install-to-share.json').write_text(json.dumps(r,indent=2),encoding='utf-8')
  print(json.dumps({'status':r['status'],'initialization_attempted':r['initialization_attempted'],'finalization_attempted':r['finalization_attempted'],'report_written':True}))
 return r
if __name__=='__main__':
 sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
 if len(sys.argv)>2 or len(sys.argv)==2 and sys.argv[1]!='--protocol-diagnostic':raise ValueError('arguments')
 run(Path('output'),diagnostic_only=len(sys.argv)==2)
