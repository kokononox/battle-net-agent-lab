"""Small owned Retail transfer attempt; no account/country/consent fields."""
import ctypes,ipaddress,json,os,re,socket,struct,time
from ctypes import wintypes as w
from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]/'agent-interface-lab'))
import probe,path_guard,path_relation
import finalization_shape
import response_diagnostic
from retail_protocol import summarize,CODES
STATES={'operation_state_observed','operation_start_observed','final_form_state_observed','read_only_status_observed','identity_control_observed','not_started','prerequisite_refused','pending','request_failed','finalization_refused','start_refused','observed','identity_changed','collection_refused','canonical_game_link_observed','response_schema_unrecognized','product_state_observed'}
FIELDS={'installed','download_complete','playable','downloaded_bytes','bytes_downloaded','downloaded','total_bytes','bytes_total','download_size','download_progress','progress'}
NUMERIC={'downloaded_bytes','bytes_downloaded','downloaded','total_bytes','bytes_total','download_size'}
PORTS={'80','443','1119','3724','other'}
def counts():return {k:0 for k in sorted(PORTS)}
def blank(source,run):
 return dict(schema='bnet-retail-transfer-6',source_commit=source,run_id=run,status='not_started',start_authorization='not_observed',error_kind=None,finalization_attempted=False,start_attempted=False,local_requests=0,polls=0,phase_signal_created=False,phase_acknowledged=False,finalization_response_shape=finalization_shape.blank(),response_diagnostic=response_diagnostic.blank(),preflight_path_guard=path_guard.blank(),finalization_http_status=None,start_http_status=None,status_query_http_status=None,finalization_response_bytes=0,start_response_bytes=0,status_query_response_bytes=0,finalized_returned=None,finalization_error_codes={k:None for k in ('agent',*CODES)},start_agent_error=None,final_path_guard=path_guard.blank(),final_path_relation=path_relation.blank(),baseline_progress=None,last_progress=None,baseline_files=None,last_files=None,baseline_connections=None,last_connections=None,account_parameter_sent=False,country_parameter_sent=False,legal_acceptance_parameter_sent=False,payload_exported=False,raw_paths_exported=False,complete_installation_proven=False,hardware_upload_proven=False)
def validate(r):
 keys=set(blank('a'*40,'1'))
 if type(r)is dict and r.get('schema')!='bnet-retail-transfer-6':keys=keys-{'start_authorization'}
 if type(r)is dict and r.get('schema')in {'bnet-retail-transfer-1','bnet-retail-transfer-2','bnet-retail-transfer-3','bnet-retail-transfer-4'}:keys=keys-{'status_query_http_status','status_query_response_bytes'}
 if type(r)is dict and r.get('schema')in {'bnet-retail-transfer-1','bnet-retail-transfer-2','bnet-retail-transfer-3'}:keys=keys-{'response_diagnostic'}
 if type(r)is dict and r.get('schema')in {'bnet-retail-transfer-1','bnet-retail-transfer-2'}:keys=keys-{'finalization_response_shape'}
 if type(r)is dict and r.get('schema')=='bnet-retail-transfer-1':keys=keys-{'phase_acknowledged'}
 if type(r)is not dict or set(r)!=keys or r['schema']not in {'bnet-retail-transfer-1','bnet-retail-transfer-2','bnet-retail-transfer-3','bnet-retail-transfer-4','bnet-retail-transfer-5','bnet-retail-transfer-6'} or r['status']not in STATES or r['error_kind']not in {None,'OSError','ValueError','Stop','other'}:raise ValueError('transfer_schema')
 if type(r['source_commit'])is not str or not re.fullmatch('[0-9a-f]{40}',r['source_commit']) or type(r['run_id'])is not str or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('transfer_identity')
 if r['schema']in {'bnet-retail-transfer-4','bnet-retail-transfer-5','bnet-retail-transfer-6'}:response_diagnostic.validate(r['response_diagnostic'])
 if r['schema']in {'bnet-retail-transfer-3','bnet-retail-transfer-4','bnet-retail-transfer-5','bnet-retail-transfer-6'}:
  if r['status']=='product_state_observed' and(r['finalization_response_shape']['kind']!='product_state' or r['finalization_http_status']not in (200,201) or not r['finalization_response_bytes']):raise ValueError('product_state_evidence')
  finalization_shape.validate(r['finalization_response_shape'])
  if r['status']=='canonical_game_link_observed' and(r['finalization_response_shape']['kind']!='canonical_game_link' or r['finalization_http_status']not in (200,201) or not r['finalization_response_bytes']):raise ValueError('canonical_evidence')
 if r['schema']in {'bnet-retail-transfer-2','bnet-retail-transfer-3','bnet-retail-transfer-4','bnet-retail-transfer-5','bnet-retail-transfer-6'}:
  if type(r['phase_acknowledged'])is not bool:raise ValueError('ack_boolean')
  if r['phase_acknowledged'] and not r['phase_signal_created']:raise ValueError('ack_signal')
  if r['finalization_attempted'] and not r['phase_acknowledged']:raise ValueError('request_before_arm')
 for k in ('finalization_attempted','start_attempted','phase_signal_created'):
  if type(r[k])is not bool:raise ValueError('transfer_bool')
 for k in ('account_parameter_sent','country_parameter_sent','legal_acceptance_parameter_sent','payload_exported','raw_paths_exported','complete_installation_proven','hardware_upload_proven'):
  if r[k]is not False:raise ValueError('transfer_fixed')
 for k,cap in [('local_requests',7),('polls',4),('finalization_response_bytes',65536),('start_response_bytes',65536)]:
  if type(r[k])is not int or not 0<=r[k]<=cap:raise ValueError('transfer_count')
 if r['schema']in {'bnet-retail-transfer-5','bnet-retail-transfer-6'}:
  h=r['status_query_http_status'];b=r['status_query_response_bytes']
  if h is not None and(type(h)is not int or not 100<=h<=599):raise ValueError('status_query_http')
  if type(b)is not int or not 0<=b<=65536:raise ValueError('status_query_bytes')
 for k in ('finalization_http_status','start_http_status'):
  if r[k]is not None and(type(r[k])is not int or not 100<=r[k]<=599):raise ValueError('transfer_http')
 if r['finalized_returned']is not None and type(r['finalized_returned'])is not bool:raise ValueError('finalized')
 if type(r['finalization_error_codes'])is not dict or set(r['finalization_error_codes'])!={'agent',*CODES}:raise ValueError('transfer_codes')
 for v in [*r['finalization_error_codes'].values(),r['start_agent_error']]:
  if v is not None and(type(v)is not int or not 0<=v<=2**32):raise ValueError('transfer_code')
 for k in ('preflight_path_guard','final_path_guard'):path_guard.validate(r[k])
 path_relation.validate(r['final_path_relation'])
 for k in ('baseline_files','last_files'):
  d=r[k]
  if d is not None and(type(d)is not dict or set(d)!={'files','directories','bytes'} or any(type(d[x])is not int or not 0<=d[x]<=(2**50 if x=='bytes'else 512)for x in d)):raise ValueError('files')
 for k in ('baseline_connections','last_connections'):
  d=r[k]
  if d is not None and(type(d)is not dict or set(d)!=PORTS or any(type(v)is not int or not 0<=v<=4096 for v in d.values())):raise ValueError('connections')
 for k in ('baseline_progress','last_progress'):
  d=r[k]
  if d is not None:
   if type(d)is not dict or set(d)!={'recognized_fields','installed','download_complete','playable','counters','unknown_top_fields'}:raise ValueError('progress')
   if type(d['recognized_fields'])is not list or any(type(x)is not str or x not in FIELDS for x in d['recognized_fields']):raise ValueError('progress_fields')
   for x in ('installed','download_complete','playable'):
    if d[x]is not None and type(d[x])is not bool:raise ValueError('progress_bool')
   if type(d['unknown_top_fields'])is not int or not 0<=d['unknown_top_fields']<=128 or type(d['counters'])is not dict or len(d['counters'])>18:raise ValueError('progress_count')
   for key,v in d['counters'].items():
    parts=key.split('.')
    if len(parts)not in (1,2) or parts[-1]not in NUMERIC or len(parts)==2 and parts[0]not in {'progress','download_progress'} or type(v)is not int or not 0<=v<=2**50:raise ValueError('progress_counter')
 if r['finalization_attempted']and(not r['phase_signal_created'] or r['local_requests']<1 or r['preflight_path_guard']['status']!='verified_existing_chain'):raise ValueError('finalize_guard')
 if r['schema']=='bnet-retail-transfer-6'and r['start_authorization']not in {'not_observed','finalized_form','owned_install_operation'}:raise ValueError('start_authorization')
 operation_start=r['schema']=='bnet-retail-transfer-6'and r['start_authorization']=='owned_install_operation'
 if operation_start and not r['finalization_response_shape'].get('owned_install_link'):raise ValueError('operation_handoff')
 if r['start_attempted']and(not r['finalization_attempted'] or (r['finalized_returned']is not True and not operation_start) or r['local_requests']<3 or r['final_path_guard']['status']!='verified_existing_chain'):raise ValueError('start_guard')
 if r['status']=='identity_control_observed'and(not r['phase_acknowledged']or r['finalization_attempted']or r['start_attempted']or r['local_requests']or r['polls']):raise ValueError('control_evidence')
 if r['status']=='operation_start_observed'and(not operation_start or not r['start_attempted']or r['start_http_status']not in (200,201)or r['polls']<1):raise ValueError('operation_start_evidence')
 if r['status']=='observed' and(not r['start_attempted'] or r['start_http_status']not in (200,201) or r['start_agent_error']!=0 or r['polls']<1):raise ValueError('observed_guard')
 return r

def write(r):
 validate(r);p=Path('output/retail-transfer.json');p.parent.mkdir(exist_ok=True);tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps(r,indent=2)+'\n');tmp.replace(p)
def progress(d):
 if type(d)is not dict or len(d)>128:raise ValueError('progress_object')
 out=dict(recognized_fields=sorted(set(d)&FIELDS),installed=None,download_complete=None,playable=None,counters={},unknown_top_fields=len(set(d)-FIELDS))
 for k in ('installed','download_complete','playable'):
  if type(d.get(k))is bool:out[k]=d[k]
 for key in NUMERIC:
  if type(d.get(key))is int and 0<=d[key]<=2**50:out['counters'][key]=d[key]
 for parent in ('progress','download_progress'):
  x=d.get(parent)
  if type(x)is dict:
   for key in NUMERIC:
    if type(x.get(key))is int and 0<=x[key]<=2**50:out['counters'][parent+'.'+key]=x[key]
 return out

def file_snapshot(target):
 # Metadata only, bounded, owned directory; no contents/filenames exported.
 out=dict(files=0,directories=0,bytes=0);stack=[(Path(target),0)];seen=0
 while stack:
  folder,depth=stack.pop()
  if depth>8:raise ValueError('tree_depth')
  with os.scandir(folder)as entries:
   for entry in entries:
    seen+=1
    if seen>512:raise ValueError('tree_limit')
    s=entry.stat(follow_symlinks=False)
    if getattr(s,'st_file_attributes',0)&0x400 or entry.is_symlink():raise ValueError('tree_reparse')
    if entry.is_dir(follow_symlinks=False):out['directories']+=1;stack.append((Path(entry.path),depth+1))
    elif entry.is_file(follow_symlinks=False):out['files']+=1;out['bytes']+=s.st_size
    else:raise ValueError('tree_type')
    if out['bytes']>2**50:raise ValueError('tree_bytes')
 return out

def tcp_rows():
 api=ctypes.WinDLL('iphlpapi',use_last_error=True).GetExtendedTcpTable;api.argtypes=[ctypes.c_void_p,ctypes.POINTER(w.DWORD),w.BOOL,w.ULONG,ctypes.c_int,w.ULONG];api.restype=w.DWORD
 size=w.DWORD(0);code=api(None,ctypes.byref(size),False,socket.AF_INET,5,0)
 if code not in (0,122):raise ValueError('tcp_table')
 for _ in range(3):
  if not 4<=size.value<=16*1024**2:raise ValueError('tcp_size')
  allocated=size.value;buf=ctypes.create_string_buffer(allocated);code=api(buf,ctypes.byref(size),False,socket.AF_INET,5,0)
  if code==0:break
  if code!=122:raise ValueError('tcp_table')
 if code:raise ValueError('tcp_table')
 n=struct.unpack_from('<I',buf.raw)[0]
 if n>65536 or 4+n*24>allocated:raise ValueError('tcp_rows')
 return [struct.unpack_from('=6I',buf.raw,4+i*24)for i in range(n)]
def owner_at(port,rows):
 matches=[x[5]for x in rows if x[0]==2 and socket.ntohs(x[2]&65535)==port and socket.inet_ntoa(struct.pack('=I',x[1]))in {'127.0.0.1','0.0.0.0'}]
 if len(matches)!=1:raise ValueError('owner')
 return matches[0]
def connection_counts(port,owner,rows):
 if owner_at(port,rows)!=owner:raise ValueError('owner_changed')
 out=counts()
 for state,_,_,remote,rport,pid in rows:
  if pid!=owner or state!=5:continue
  ip=ipaddress.ip_address(socket.inet_ntoa(struct.pack('=I',remote)))
  if ip.is_loopback or ip.is_unspecified:continue
  p=str(socket.ntohs(rport&65535));out[p if p in PORTS else 'other']+=1
 return out

def await_arm():
 deadline=time.monotonic()+3
 p=Path('output/retail-transfer-ready.signal')
 while time.monotonic()<deadline:
  try:
   if p.is_symlink():raise ValueError('ack_reparse')
   with p.open('rb')as f:
    if f.read(7)==b'ready\n':return True
    raise ValueError('ack_contents')
  except FileNotFoundError:time.sleep(.025)
 raise ValueError('arm_timeout')

def execute(session,target,configured,r):
 meter=None
 t=r['transfer'];write(t)
 try:
  u=r['form_update'];f=configured.get('form',{})
  if u['status']!='response_observed' or u['response_finalized']is not False or not u['response_schema_valid'] or any(v!=0 for v in u['response_error_codes'].values()) or u['path_relation']['relation']not in {'exact_string','normalized_equal'}:t['status']='prerequisite_refused';return
  returned=f.get('game_dir',{}).get('game_dir');t['preflight_path_guard']=path_guard.inspect(target,returned)
  if t['preflight_path_guard']['status']!='verified_existing_chain':t['status']='prerequisite_refused';return
  if session.verify()is not True:raise probe.Stop('identity_changed')
  rows=tcp_rows();owner=owner_at(session.port,rows);t['baseline_connections']=connection_counts(session.port,owner,rows);t['baseline_files']=file_snapshot(target)
  meter_scope=os.environ.get('RETAIL_TCP_METER')
  if meter_scope=='owned-baseline-t2':
   import sys
   sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'prelogin-tcp-attribution'))
   import meter_control
   meter=meter_control.start(owner,session.port)
  elif meter_scope not in (None,''):raise ValueError('meter_scope')
  # Signal is an intent marker, not proof of transfer or permission to reset global limits.
  with Path('output/retail-transfer-active.signal').open('x')as signal:signal.write('active\n')
  t['phase_signal_created']=True;t['status']='pending';write(t)
  if await_arm()is not True:raise ValueError('arm_refused')
  t['phase_acknowledged']=True;write(t)
  def request(method,path,payload=None,stage=None):
   allowed={('POST','/install/wow'),('POST','/update'),('GET','/game/wow'),('GET','/install/wow'),('GET','/update/wow')}
   if os.environ.get('RETAIL_READ_ONLY_STATUS')=='response-uri-t3'and(method,path)==('POST','/update'):raise ValueError('readonly_scope')
   if (method,path)not in allowed or t['local_requests']>=7:raise ValueError('transfer_scope')
   if session.verify()is not True:raise probe.Stop('identity_changed')
   t['local_requests']+=1;r['local_requests']+=1
   if stage=='finalization':t['finalization_attempted']=True
   if stage=='start':t['start_attempted']=True
   write(t)
   conn=session.factory('127.0.0.1',session.port,timeout=3)
   body=None if payload is None else json.dumps(payload,separators=(',',':')).encode('ascii')
   if body is not None and len(body)>4096:raise ValueError('body')
   try:
    conn.request(method,path,body=body,headers={'Authorization':session.token,'User-Agent':'phoenix-agent/1.0','Content-Type':'application/json','Accept':'application/json','Accept-Encoding':'identity','Connection':'close'})
    response=conn.getresponse()
    if stage is not None:
     t[stage+'_http_status']=response.status;write(t)
    if response.status not in (200,201) or response.getheader('Content-Encoding','identity').lower()not in ('','identity'):raise ValueError('http')
    n=response.getheader('Content-Length')
    if n is not None and(re.fullmatch('[0-9]{1,10}',n)is None or int(n)>65536):raise ValueError('length')
    raw=response.read(65537)
    if len(raw)>65536 or n is not None and len(raw)!=int(n):raise ValueError('body_limit')
    if stage is not None:
     t[stage+'_response_bytes']=len(raw);write(t)
    data=probe.unique_json(raw)
    if stage=='finalization':
     t['finalization_response_shape']=finalization_shape.classify(data,session.port);t['response_diagnostic']=response_diagnostic.describe(data);write(t)
    if session.verify()is not True:raise probe.Stop('identity_changed')
    return data
   finally:conn.close()
  if os.environ.get('RETAIL_PHASE_CONTROL')=='identity-only-d20':
   # Negative control: same post-arm identity check, zero phase HTTP requests.
   if session.verify()is not True:raise probe.Stop('identity_changed')
   t['status']='identity_control_observed';write(t)
   t['last_connections']=connection_counts(session.port,owner,tcp_rows());t['last_files']=file_snapshot(target);write(t)
   return
  if os.environ.get('RETAIL_PHASE_CONTROL')not in (None,''):raise ValueError('control_scope')
  data=request('POST','/install/wow',dict(finalized=True,game_dir=str(target),language=['enUS'],selected_asset_locale='enUS',selected_locale='enUS'),stage='finalization')
  if t['finalization_response_shape'].get('owned_install_link')is True:
   # Exact owned form resource from the documented response_uri contract. Read only.
   import final_form
   state=request('GET','/install/wow',stage='status_query')
   if type(state.get('form'))is dict:final_form.write(final_form.describe(state,target,t['source_commit'],t['run_id']))
   import operation_state
   states=[operation_state.describe(state,'install')]
   def save_states():operation_state.write(operation_state.receipt(t['source_commit'],t['run_id'],states))
   save_states();t['status']='operation_state_observed';write(t)
   t['last_connections']=connection_counts(session.port,owner,tcp_rows());t['last_files']=file_snapshot(target);write(t)
   if os.environ.get('RETAIL_START_OPERATION')!='owned-install-t5' or not operation_state.eligible(states[0]):return
   t['final_path_guard']=path_guard.inspect(target,str(target));write(t)
   if t['final_path_guard']['status']!='verified_existing_chain':return
   t['start_authorization']='owned_install_operation';write(t)
   started=request('POST','/update',{'uid':'wow'},stage='start')
   code=started.get('error')
   if type(code)is int and 0<=code<=2**32:t['start_agent_error']=code
   if 'error'in started and t['start_agent_error']!=0:t['status']='start_refused';return
   uri=started.get('response_uri');resource=None
   for label in ('install','update'):
    if uri in ('/'+label+'/wow','http://127.0.0.1:'+str(session.port)+'/'+label+'/wow'):resource=label
   if resource is None and t['start_agent_error']==0:resource='install'
   if resource is None:t['status']='start_refused';return
   for _ in range(4):
    result=request('GET','/'+resource+'/wow',stage='status_query');states.append(operation_state.describe(result,resource));save_states()
    t['last_progress']=progress(result);t['polls']+=1;t['status']='operation_start_observed';write(t)
    t['last_connections']=connection_counts(session.port,owner,tcp_rows());t['last_files']=file_snapshot(target);write(t)
    if states[-1]['refusal_observed']:return
    time.sleep(.25)
   return
  if t['finalization_response_shape']['kind']in {'canonical_game_link','product_state'}:
   # No /update after a different response shape. Read the exact owned endpoint only.
   t['status']='product_state_observed'if t['finalization_response_shape']['kind']=='product_state'else'canonical_game_link_observed'
   if t['finalization_response_shape']['kind']=='product_state':t['baseline_progress']=progress(data);t['last_progress']=t['baseline_progress']
   write(t)
   t['final_path_guard']=path_guard.inspect(target,str(target));write(t)
   if t['final_path_guard']['status']!='verified_existing_chain':return
   for _ in range(4):
    observed=progress(request('GET','/game/wow',stage='status_query'));t['polls']+=1
    if t['baseline_progress']is None:t['baseline_progress']=observed
    t['last_progress']=observed;write(t)
    t['last_connections']=connection_counts(session.port,owner,tcp_rows());t['last_files']=file_snapshot(target);write(t)
    time.sleep(1)
   return
  if t['finalization_response_shape']['kind']!='form':
   t['status']='response_schema_unrecognized';write(t)
   diagnostic=t['response_diagnostic']
   refused=bool(set(diagnostic['message_markers'])&{'authentication','legal','license','failure'}) or any(n['numeric_code']not in (None,0)for n in diagnostic['nodes'])
   if refused:return
   # A single read of the known, owned product status is not acceptance of this schema.
   # Never /update, never follow an unknown URL, never retry finalization.
   t['final_path_guard']=path_guard.inspect(target,str(target));write(t)
   if t['final_path_guard']['status']!='verified_existing_chain':return
   observed=progress(request('GET','/game/wow',stage='status_query'))
   t['polls']=1;t['baseline_progress']=observed;t['last_progress']=observed;write(t)
   t['last_connections']=connection_counts(session.port,owner,tcp_rows());t['last_files']=file_snapshot(target);write(t)
   return
  s=summarize(data);t['finalization_error_codes']=s['error_codes'];f=data.get('form',{})
  if type(f)is not dict:t['status']='finalization_refused';return
  if type(f.get('finalized'))is bool:t['finalized_returned']=f['finalized']
  returned=f.get('game_dir',{}).get('game_dir') if type(f.get('game_dir'))is dict else None
  t['final_path_relation']=path_relation.classify(str(target),returned);t['final_path_guard']=path_guard.inspect(target,returned);write(t)
  if not s['form_schema_valid'] or t['finalized_returned']is not True or any(v!=0 for v in s['error_codes'].values()) or t['final_path_relation']['relation']not in {'exact_string','normalized_equal'} or t['final_path_guard']['status']!='verified_existing_chain':t['status']='finalization_refused';return
  t['baseline_progress']=progress(request('GET','/game/wow',stage='status_query'));write(t)
  if os.environ.get('RETAIL_READ_ONLY_STATUS')=='response-uri-t3':t['status']='read_only_status_observed';return
  t['start_authorization']='finalized_form';write(t)
  data=request('POST','/update',{'uid':'wow'},stage='start');v=data.get('error')
  if type(v)is int and 0<=v<=2**32:t['start_agent_error']=v
  if t['start_agent_error']!=0:t['status']='start_refused';return
  for _ in range(4):
   t['last_progress']=progress(request('GET','/game/wow',stage='status_query'));t['polls']+=1
   t['last_connections']=connection_counts(session.port,owner,tcp_rows());t['last_files']=file_snapshot(target);write(t)
   time.sleep(1)
  t['status']='observed'
 except Exception as exc:
  name=type(exc).__name__;t['error_kind']=name if name in {'OSError','ValueError','Stop'}else 'other';t['status']='identity_changed'if name=='Stop'else'request_failed'
 finally:
  write(t)
  if meter is not None:meter_control.stop(meter)
