"""Selected-program mitmproxy addon. No replay, edits, key export or protection bypass.
Private outbound HTTP samples stay local; shared metadata deliberately excludes values.
"""
import asyncio,base64,datetime,hashlib,json,os,re,time,urllib.parse,zlib
from pathlib import Path
from mitmproxy import ctx
FIXTURE_HOST='wow.ingest.gdp.blizzard.com'
MAX_BODY=262144
ALIASES={'cpu':'cpu','cpumodel':'cpu_model','cpuname':'cpu_name','processor':'processor','cpuid':'cpu_id',
 'bios':'bios','biosversion':'bios_version','biosvendor':'bios_vendor','biosreleasedate':'bios_release_date',
 'gpu':'gpu','gpuname':'gpu_name','gpumodel':'gpu_model','videocard':'video_card',
 'ram':'ram','memory':'memory','totalmemory':'total_memory','systemmemory':'system_memory',
 'motherboard':'motherboard','baseboard':'baseboard','baseboardproduct':'board_model',
 'systemproductname':'system_model','systemmodel':'system_model','systemmanufacturer':'system_manufacturer',
 'serialnumber':'serial_number','deviceid':'device_id','hardwareid':'hardware_id','machineid':'machine_id',
 'os':'os','osversion':'os_version','operatingsystem':'operating_system','architecture':'architecture',
 'event':'event','events':'events','eventname':'event_name','eventtype':'event_type','timestamp':'timestamp',
 'sessionid':'session_id','application':'application','version':'version','platform':'platform','locale':'locale'}


def refs_local():
 import winreg
 result={}
 for key,name,category in [(r'HARDWARE\DESCRIPTION\System\CentralProcessor\0','ProcessorNameString','cpu_model'),
  (r'HARDWARE\DESCRIPTION\System\BIOS','BIOSVersion','bios_version'),(r'HARDWARE\DESCRIPTION\System\BIOS','BIOSReleaseDate','bios_release_date'),
  (r'HARDWARE\DESCRIPTION\System\BIOS','SystemProductName','system_model'),(r'HARDWARE\DESCRIPTION\System\BIOS','BaseBoardProduct','board_model')]:
  try:
   with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,key) as k:v=winreg.QueryValueEx(k,name)[0]
   values=v if isinstance(v,list) else [v]
   good=[x.strip() for x in values if isinstance(x,str) and 4<=len(x.strip())<=160 and x.strip().lower() not in {'default string','unknown','to be filled by o.e.m.','system product name'}]
   if good:result[category]=good
  except OSError:pass
 return result


def decode_body(raw,encoding):
 if len(raw)>MAX_BODY:return b'',False,'body_over_limit'
 encoding=encoding.strip().lower()
 if encoding in ('','identity'):return raw,True,'identity'
 if encoding not in ('gzip','deflate'):return b'',False,'unsupported_content_encoding'
 try:
  d=zlib.decompressobj(31 if encoding=='gzip' else 15);out=d.decompress(raw,MAX_BODY+1)
  if len(out)>MAX_BODY or not d.eof or d.unused_data:return b'',False,'compressed_body_incomplete_or_limit'
  return out,True,encoding
 except zlib.error:return b'',False,'decompression_failed'


def body_summary(raw,encoding,refs,head=b''):
 body,complete,status=decode_body(raw,encoding);texts=[]
 if complete:
  for codec in ('utf-8','utf-16-le'):
   try:texts.append(body.decode(codec))
   except UnicodeError:pass
 markers=set();key_count=0;format_hint='empty' if not raw else 'unparsed_or_binary'
 def key(s):
  nonlocal key_count
  key_count+=1
  alias=ALIASES.get(re.sub('[^a-z0-9]','',str(s).lower()))
  if alias:markers.add(alias)
 def walk(v,depth=0):
  if depth>12 or key_count>=2048:return
  if isinstance(v,dict):
   for k,x in v.items():
    if key_count>=2048:break
    key(k);walk(x,depth+1)
  elif isinstance(v,list):
   for x in v[:2048]:walk(x,depth+1)
 if complete and body:
  for text in texts:
   try:walk(json.loads(text));format_hint='json';break
   except (ValueError,RecursionError):pass
  if format_hint=='unparsed_or_binary' and texts and re.fullmatch(r'[A-Za-z0-9_.%+\-]+=[^\r\n]*',texts[0]):
   format_hint='form';[key(urllib.parse.unquote_plus(x.partition('=')[0])) for x in texts[0].split('&')[:2048]]
 samples=[head+raw]
 if complete:samples.append(body)
 samples += [urllib.parse.unquote_to_bytes(x.replace(b'+',b' ')) for x in list(samples)]
 matches=sorted(k for k,vals in refs.items() if any(v.encode(codec) in s for v in vals for codec in ('utf-8','utf-16-le') for s in samples))
 return {'decoded_body_examined':complete,'body_decode_status':status,'body_format_hint':format_hint,
  'known_field_name_hints':sorted(markers),'hardware_literal_categories':matches,
  'absence_of_match_does_not_prove_absence_of_hardware_data':True}


def safe_host(value):
 value=str(value or '').lower().rstrip('.')
 # Do not export malformed host text or arbitrary header values as a domain.
 if len(value)>253 or not value:return None
 import ipaddress
 try:return str(ipaddress.ip_address(value.strip('[]')))
 except ValueError:pass
 if '.' not in value or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in value.split('.')):return None
 return value


def target(flow):
 # All selected-program public-name HTTP(S), not one hard-coded destination.
 # Private/loopback names and mismatched TLS authorities remain metadata-only.
 host=safe_host(flow.request.host)
 if not host or host.endswith(('.localhost','.local')):return False
 import ipaddress
 try:
  if not ipaddress.ip_address(host).is_global:return False
 except ValueError:pass
 scheme=getattr(flow.request,'scheme','https')
 if scheme=='http':return True
 return safe_host(flow.client_conn.sni)==host


class Probe:
 def __init__(self):
  self.folder=Path(os.environ['INGEST_PROBE_RUN']);self.phase=os.environ.get('INGEST_PROBE_PHASE','capture')
  self.refs={};self.task=None;self.started=time.monotonic();self.count=0;self.private_bytes=0;self.rows={}
  self.report={'schema':'game-tls-probe-1','version':'0.1.0','scope':'selected_executable_basename_connections','status':'starting',
   'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'addon_ready':False,
   'tls_client_established_count':0,'tls_client_failed_count':0,'tls_server_failed_count':0,
   'requests':[],'destinations':[],'limits_hit':[],'hardware_reference_categories_available':[],
   'limits':{'observational_not_prevention':True,'no_absence_of_hardware_transmission_proof':True,
    'http_tls_authority_mismatch_content_not_saved':True,'destination_coverage_not_exhaustive':True,'udp_dns_custom_protocol_decoding_not_guaranteed':True,'private_samples_may_contain_identifiers_or_credentials':True,
    'private_samples_stay_local_no_automatic_upload':True,'request_body_limit_bytes':MAX_BODY,
    'maximum_exported_requests':32,'no_raw_tls_key_export_requested':True,
    'native_windows_qualification_completed_by_builder':False,'response_bodies_not_saved_by_addon':True}}
 def write(self):
  p=self.folder/'ingest-content.json';tmp=p.with_suffix('.tmp')
  tmp.write_text(json.dumps(self.report,ensure_ascii=True,indent=2)+'\n',encoding='utf-8');os.replace(tmp,p)
 async def timer(self):
  while time.monotonic()-self.started<150:
   if (self.folder/'stop.flag').exists():break
   await asyncio.sleep(.25)
  self.report['status']='observation_ended';self.write();ctx.master.shutdown()
 def running(self):
  if self.phase!='bootstrap':
   try:self.refs=refs_local()
   except Exception:self.report['reference_read_failed']=True
   self.report['hardware_reference_categories_available']=sorted(self.refs)
  self.report['addon_ready']=True;self.report['status']='running';self.write()
  (self.folder/'addon-ready.flag').write_text(self.phase)
  self.task=asyncio.create_task(self.timer())
 def endpoint(self,server,kind):
  address=getattr(server,'address',None);peer=getattr(server,'peername',None)
  host=safe_host(address[0]) if address else None
  port=int(address[1]) if address and isinstance(address[1],int) else None
  ip=safe_host(peer[0]) if peer else None
  sni=safe_host(getattr(server,'sni',None))
  row={'kind':kind,'destination_host_or_ip':host,'destination_port':port,'connected_peer_ip':ip,'visible_sni':sni}
  if row not in self.report['destinations']:
   if len(self.report['destinations'])<256:self.report['destinations'].append(row)
   elif 'destination_metadata_limit' not in self.report['limits_hit']:self.report['limits_hit'].append('destination_metadata_limit')
  self.write()
 def server_connect(self,data):self.endpoint(data.server,'connection_attempt')
 def server_connected(self,data):self.endpoint(data.server,'connected')
 def tcp_start(self,flow):self.endpoint(flow.server_conn,'raw_tcp_connection_content_not_decoded')
 def udp_start(self,flow):self.endpoint(flow.server_conn,'udp_connection_content_not_decoded')
 def tls_clienthello(self,data):
  name=safe_host(getattr(data.client_hello,'sni',None))
  if name:
   row={'kind':'clienthello','visible_sni':name}
   if row not in self.report['destinations'] and len(self.report['destinations'])<256:self.report['destinations'].append(row)
  self.write()
 def tls_established_client(self,data):
  self.report['tls_client_established_count']+=1;self.write()
 def tls_failed_client(self,data):
  self.report['tls_client_failed_count']+=1;self.report['failure_reason_not_proven']='client_tls_failed_not_necessarily_pinning'
  name=safe_host(getattr(data.conn,'sni',None))
  if name:self.report['last_failed_tls_domain']=name
  self.write();(self.folder/'tls-failed.flag').write_text('client_tls_failed')
 def tls_failed_server(self,data):
  self.report['tls_server_failed_count']+=1;self.write();(self.folder/'tls-failed.flag').write_text('server_tls_failed')
 def requestheaders(self,flow):
  # Response bodies are streamed later. Requests exceeding the threshold are not buffered/inspected.
  if target(flow):
   try:
    if int(flow.request.headers.get('content-length','0'))>MAX_BODY:flow.request.stream=True
   except ValueError:flow.request.stream=True
 def request(self,flow):
  if self.phase=='bootstrap' or not target(flow):return
  if self.count>=32:
   if 'request_count_limit' not in self.report['limits_hit']:self.report['limits_hit'].append('request_count_limit')
   self.write();return
  self.count+=1;req=flow.request;raw=req.raw_content
  row={'index':self.count,'method':req.method if re.fullmatch('[A-Z]{1,20}',req.method) else 'OTHER',
   'host':safe_host(req.host),'port':int(req.port),'query_present':'?' in req.path,'body_buffered':raw is not None,
   'buffered_body_bytes':len(raw) if raw is not None else None,'server_response_status':None,
   'credential_header_present':any(k.lower() in ('authorization','cookie','proxy-authorization') for k in req.headers),
   'raw_values_exported_in_shared_json':False,'request_forwarded_or_received_by_server_proven':False}
  headers=list(req.headers.items(multi=True));head=(req.method+' '+req.path+'\r\n'+'\r\n'.join(k+': '+v for k,v in headers)).encode('utf-8',errors='replace')[:MAX_BODY]
  if raw is not None:
   row.update(body_summary(raw,req.headers.get('content-encoding',''),self.refs,head))
  else:row['body_decode_status']='streamed_or_unavailable_not_examined'
  self.report['requests'].append(row);self.rows[flow.id]=row
  # Only outbound samples; private local directory, capped in count and total size.
  if raw is not None and len(raw)<=MAX_BODY:
   decoded,ok,_=decode_body(raw,req.headers.get('content-encoding',''))
   sample={'warning':'PRIVATE: may contain account/device identifiers. Do not upload.',
    'method':req.method,'host':safe_host(req.host),'path':req.path[:8192],
    'headers':[(k,v[:8192]) for k,v in headers[:128]],'raw_body_base64':base64.b64encode(raw).decode(),
    'decoded_body_utf8':decoded.decode('utf-8',errors='replace') if ok else None}
   blob=json.dumps(sample,ensure_ascii=True,indent=2).encode()
   if self.private_bytes+len(blob)<=4*1024**2:
    private=self.folder/'PRIVATE-REQUESTS';private.mkdir(exist_ok=True)
    with (private/('request-%02d.json'%self.count)).open('xb') as f:f.write(blob)
    self.private_bytes+=len(blob);row['private_sample_saved_locally']=True
   else:
    row['private_sample_saved_locally']=False
    if 'private_sample_total_limit' not in self.report['limits_hit']:self.report['limits_hit'].append('private_sample_total_limit')
  self.write()
 def responseheaders(self,flow):
  if target(flow):
   flow.response.stream=True
   row=self.rows.get(flow.id)
   if row is not None:row['server_response_status']=flow.response.status_code;self.write()
 def error(self,flow):
  row=self.rows.get(flow.id)
  if row is not None:row['flow_error_observed']=True;self.write()
 def done(self):
  self.refs.clear()
  if self.phase!='bootstrap':
   self.report['status']='observation_ended';self.write()

if 'INGEST_PROBE_RUN' in os.environ:addons=[Probe()]
