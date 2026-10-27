"""One non-finalizing form update; no account/country/legal/update endpoint."""
import ctypes,json,os,re,shutil
from pathlib import Path
import probe
from retail_protocol import summarize,CODES
STATUSES={'not_started','prerequisite_refused','request_failed','response_observed','unexpected_finalized','identity_changed'}

def blank():
 return dict(status='not_started',attempted=False,destination_guard_passed=False,minimum_free_required_bytes=0,free_before_bytes=0,http_status=None,response_bytes=0,response_has_form=False,response_schema_valid=False,response_finalized=None,response_eula_flag=None,response_game_dir_matches_requested=None,response_error_codes={k:None for k in ('agent',*CODES)},unknown_response_fields=False)

def validate(r):
 if type(r)is not dict or set(r)!=set(blank()) or r['status']not in STATUSES:raise ValueError('update_schema')
 for k in ('attempted','destination_guard_passed','response_has_form','response_schema_valid','unknown_response_fields'):
  if type(r[k])is not bool:raise ValueError('update_bool')
 for k in ('response_finalized','response_eula_flag','response_game_dir_matches_requested'):
  if r[k]is not None and type(r[k])is not bool:raise ValueError('update_nullable_bool')
 for k,cap in [('minimum_free_required_bytes',2**60),('free_before_bytes',2**60),('response_bytes',65536)]:
  if type(r[k])is not int or not 0<=r[k]<=cap:raise ValueError('update_count')
 if r['http_status']is not None and(type(r['http_status'])is not int or not 100<=r['http_status']<=599):raise ValueError('update_http')
 if type(r['response_error_codes'])is not dict or set(r['response_error_codes'])!=set(blank()['response_error_codes']):raise ValueError('update_codes')
 for v in r['response_error_codes'].values():
  if v is not None and(type(v)is not int or not 0<=v<=2**32):raise ValueError('update_code')
 if r['destination_guard_passed'] and not(r['minimum_free_required_bytes']>=10*1024**3 and r['free_before_bytes']>=r['minimum_free_required_bytes']):raise ValueError('update_space_guard')
 if r['attempted']and not r['destination_guard_passed']:raise ValueError('update_destination')
 if not r['attempted'] and any(r[k]!=v for k,v in blank().items() if k not in {'status','destination_guard_passed','minimum_free_required_bytes','free_before_bytes'}):raise ValueError('update_without_request')
 if r['status']in {'response_observed','unexpected_finalized'} and not(r['attempted'] and r['http_status']in(200,201) and r['response_bytes']>0):raise ValueError('update_evidence')
 if r['status']=='unexpected_finalized' and r['response_finalized']is not True:raise ValueError('unexpected_finalized')
 if r['status']=='response_observed' and r['response_finalized']is True:raise ValueError('finalized_downgrade')
 return r

def prerequisites(data):
 s=summarize(data);f=data.get('form',{})
 if not s['form_schema_valid'] or s['error_codes']['agent']!=0 or any(s['error_codes'][k]!=0 for k in ('authentication','min_spec')):raise ValueError('form_prerequisite')
 lang=f.get('language',{})
 if type(lang)is not dict or any(type(lang.get(k))is not list or 'enUS'not in lang[k] for k in ('list','text','speech')):raise ValueError('locale_prerequisite')
 if f.get('finalized')is not False:raise ValueError('already_finalized')
 space=f.get('game_dir',{}).get('required_space')
 if type(space)is not int or not 0<=space<=2**50:raise ValueError('required_space')
 return space

def owned_target(required,is_reparse,r):
 root=Path(os.environ['RUNNER_TEMP'])
 if not root.is_absolute() or '..'in root.parts or any(is_reparse(p) for p in (root,*root.parents)):raise ValueError('temp_root')
 drive=ctypes.windll.kernel32.GetDriveTypeW;drive.argtypes=[ctypes.c_wchar_p];drive.restype=ctypes.c_uint
 if drive(str(Path(root.anchor)))!=3:raise ValueError('fixed_drive')
 required+=10*1024**3;r['minimum_free_required_bytes']=required;r['free_before_bytes']=shutil.disk_usage(root).free
 if r['free_before_bytes']<required:raise ValueError('disk')
 target=root/'retail-form-c4';target.mkdir(exist_ok=False)
 if is_reparse(target) or any(target.iterdir()):raise ValueError('new_empty_directory')
 r['destination_guard_passed']=True
 return target

def payload(target):
 return dict(finalized=False,game_dir=str(target),language=['enUS'],selected_asset_locale='enUS',selected_locale='enUS')

def execute(session,initial_data,r,is_reparse,make_target=owned_target):
 u=r['form_update']
 if u['status']!='not_started' or u['attempted'] or r['local_requests']!=2 or not r['initialization_attempted']:raise ValueError('update_once')
 try:
  required=prerequisites(initial_data);target=make_target(required,is_reparse,u)
  if not u['destination_guard_passed']:raise ValueError('destination')
 except Exception:u['status']='prerequisite_refused';return
 u['status']='request_failed'
 if session.verify()is not True:u['status']='identity_changed';return
 body=json.dumps(payload(target),separators=(',',':')).encode('ascii')
 if len(body)>4096:raise ValueError('payload_size')
 r['local_requests']+=1;u['attempted']=True
 conn=session.factory('127.0.0.1',session.port,timeout=10)
 try:
  conn.request('POST','/install/wow',body=body,headers={'Authorization':session.token,'User-Agent':'phoenix-agent/1.0','Content-Type':'application/json','Accept':'application/json','Accept-Encoding':'identity','Connection':'close'})
  response=conn.getresponse();u['http_status']=response.status;r['last_http_status']=response.status
  if response.status not in (200,201) or response.getheader('Content-Encoding','identity').lower()not in ('','identity'):raise ValueError('response')
  n=response.getheader('Content-Length')
  if n is not None and(re.fullmatch('[0-9]{1,10}',n)is None or int(n)>65536):raise ValueError('length')
  raw=response.read(65537)
  if len(raw)>65536 or n is not None and len(raw)!=int(n):raise ValueError('body')
  u['response_bytes']=len(raw);data=probe.unique_json(raw)
  if session.verify()is not True:u['status']='identity_changed';return
  f=data.get('form');u['response_has_form']=type(f)is dict
  s=summarize(data);u['response_schema_valid']=s['form_schema_valid'];u['response_error_codes']=s['error_codes'];u['unknown_response_fields']=s['unknown_fields']
  if type(f)is dict:
   if type(f.get('finalized'))is bool:u['response_finalized']=f['finalized']
   eu=f.get('eula',{})
   if type(eu)is dict and type(eu.get('eula'))is bool:u['response_eula_flag']=eu['eula']
   gd=f.get('game_dir',{})
   if type(gd)is dict and type(gd.get('game_dir'))is str:u['response_game_dir_matches_requested']=gd['game_dir']==str(target)
  u['status']='unexpected_finalized' if u['response_finalized']is True else 'response_observed'
 finally:conn.close()
