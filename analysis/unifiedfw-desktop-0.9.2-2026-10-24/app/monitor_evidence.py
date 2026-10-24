"""Validate logged evidence, not inferred HTTP activity. No logging configuration changes."""
import datetime,ipaddress,os,re
from pathlib import PureWindowsPath
from policy import path_key
STATUSES={'readable_logging_coverage_unverified','not_available_or_disabled','read_failed','not_collected'}
def device_path(path):
 if os.name!='nt':return ''
 try:
  import ctypes
  drive=PureWindowsPath(path).drive;buffer=ctypes.create_unicode_buffer(32768)
  q=ctypes.windll.kernel32.QueryDosDeviceW;q.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_uint32];q.restype=ctypes.c_uint32
  return buffer.value+path[len(drive):] if q(drive,buffer,len(buffer)) else ''
 except Exception:return ''
def instant(text):
 if not isinstance(text,str) or len(text)>64:raise ValueError('event_time')
 t=datetime.datetime.fromisoformat(text.replace('Z','+00:00'))
 if t.tzinfo is None:raise ValueError('event_time_zone')
 return t

def result_ips(text):
 out=[]
 for token in re.split(r'[;,\s]+',text):
  try:ip=str(ipaddress.ip_address(token))
  except ValueError:continue
  if ip not in out:out.append(ip)
  if len(out)>=64:break
 return out

def normalize(raw,programs):
 raw=raw if isinstance(raw,dict) else {};byid={p['id']:p for p in programs};events=[];seen=set();invalid=0
 source=raw.get('events',[]);source=source if isinstance(source,list) else []
 for e in source[:1000]:
  try:
   if not isinstance(e,dict) or not re.fullmatch('[a-f0-9]{32}',e.get('record_id','')) or e['record_id'] in seen:raise ValueError('event_id')
   p=byid[e['program_id']]
   if path_key(e['program_path'])!=path_key(p['path']) or type(e['pid']) is not int or not 0<e['pid']<=0xffffffff:raise ValueError('event_program')
   instant(e['observed_utc']);ident=e['event_record_id']
   if type(ident) is not int or ident<0:raise ValueError('event_record_id')
   row=dict(record_id=e['record_id'],program_id=p['id'],program_path=p['path'],pid=e['pid'],event_record_id=ident,observed_utc=e['observed_utc'],kind=e['kind'],attribution='logged_application_path_exact_match_not_process_birth_proof',HTTP_request_verified=False,rule_owner_verified=False,packet_drop_verified=False)
   if e['kind']=='dns_query':
    name=e['domain']
    if not isinstance(name,str) or not re.fullmatch(r'[a-z0-9_][a-z0-9_.-]{0,252}',name):raise ValueError('event_domain')
    results=str(e.get('query_results',''))[:2000]
    mapping=e.get('hosts_mapping')
    if mapping not in {'local_sink_mapping','mixed_mapping','other_mapping','system_local','not_listed','hosts_unavailable'}:mapping='hosts_unavailable'
    addresses=[]
    for value in e.get('hosts_addresses',[])[:16]:addresses.append(str(ipaddress.ip_address(value)))
    row.update(domain=name,dns_status=str(e.get('dns_status','unknown'))[:24],query_results=results,result_ips=result_ips(results),hosts_mapping=mapping,hosts_addresses=addresses,hosts_block_verified=False,source='Sysmon_22')
   elif e['kind']=='wfp_connection_block':
    if e.get('direction')!='outbound' or e.get('protocol') not in ('TCP','UDP') or type(e.get('port')) is not int or not 1<=e['port']<=65535:raise ValueError('wfp_scope')
    row.update(ip=str(ipaddress.ip_address(e['ip'])),port=e['port'],protocol=e['protocol'],direction='outbound',filter_id=str(e.get('filter_id',''))[:32],source='Security_5157',connection_denial_event=True)
   else:raise ValueError('event_kind')
   events.append(row);seen.add(e['record_id'])
  except (ValueError,TypeError,KeyError,AttributeError):invalid+=1
 streams={}
 for name in ('dns','wfp'):
  value=raw.get('streams',{});value=value.get(name,{}) if isinstance(value,dict) else {};status=value.get('status') if isinstance(value,dict) else None
  streams[name]=dict(status=status if status in STATUSES else 'not_collected',coverage_verified=False)
 return dict(schema='unified-event-evidence-1',streams=streams,events=events,truncated=raw.get('truncated') is True or invalid>0 or len(source)>1000,invalid_events=max(invalid,raw.get('invalid_events',0) if type(raw.get('invalid_events')) is int else 0),cap=1000,configuration_changed=False,hosts_snapshot_checked_utc=str(raw.get('hosts_snapshot_checked_utc','unknown'))[:64],hosts_snapshot_available=raw.get('hosts_snapshot_available') is True,hosts_snapshot_truncated=raw.get('hosts_snapshot_truncated') is True)

def inventory(raw,programs):
 unknown=dict(schema='unified-monitor-inventory-1',available=False,complete=False,checked_utc=None,rules=[],reason='not_collected_or_invalid',scope='this_owner_selected_paths_only_not_all_Windows_rules',packet_drop_verified=False,configuration_changed=False)
 if not isinstance(raw,dict):return unknown
 try:
  if type(raw.get('available')) is not bool or type(raw.get('complete')) is not bool or (raw['complete'] and not raw['available']):raise ValueError('inventory_flags')
  instant(raw['checked_utc']);rows=raw.get('rules',[])
  if not isinstance(rows,list) or len(rows)>1024:raise ValueError('inventory_limit')
  byid={p['id']:p for p in programs};out=[]
  for row in rows:
   p=byid[row['program_id']]
   if path_key(row['program'])!=path_key(p['path']) or row['protocol'] not in ('TCP','UDP') or type(row['port']) is not int or not 1<=row['port']<=65535:raise ValueError('inventory_scope')
   remote=row['remote_addresses']
   if not isinstance(remote,list) or not 1<=len(remote)<=2048:raise ValueError('inventory_addresses')
   for text in remote:ipaddress.ip_network(text,strict=True)
   out.append(dict(program_id=p['id'],program=p['path'],protocol=row['protocol'],port=row['port'],remote_addresses=remote,name=str(row.get('name',''))[:200]))
  return {**unknown,**{k:raw[k] for k in ('available','complete','checked_utc')},'reason':str(raw.get('reason','unknown'))[:100],'rules':out if raw['available'] else []}
 except (ValueError,KeyError,TypeError):return unknown

def rule_state(row,snapshot):
 if not snapshot['available']:return 'unknown'
 ip=ipaddress.ip_address(row['remote_ip'])
 for r in snapshot['rules']:
  if r['program_id']!=row['program_id'] or path_key(r['program'])!=path_key(row['program_path']) or r['protocol']!=row['protocol'] or r['port']!=row['remote_port']:continue
  if any(ip in ipaddress.ip_network(x,strict=True) for x in r['remote_addresses']):return 'verified_owned_block_snapshot'
 return 'no_matching_owned_block_snapshot' if snapshot['complete'] else 'unknown'

def enrich(c):
 c['event_evidence']=normalize(c.get('event_evidence'),c['programs']);c['block_inventory']=inventory(c.get('block_inventory'),c['programs'])
 index={}
 for e in c['event_evidence']['events']:
  if e['kind']=='dns_query':
   for ip in e['result_ips']:index.setdefault((e['program_id'],e['pid'],ip),[]).append(e)
 for row in c['endpoints']:
  row['rule_state']=rule_state(row,c['block_inventory']);row['rule_checked_utc']=c['block_inventory']['checked_utc']
  names=[];birth_ticks=int(row['process_start_ticks']);last=instant(row['last_seen_utc'])
  for e in index.get((row['program_id'],row['pid'],row['remote_ip']),[]):
   at=instant(e['observed_utc']);delta=at-datetime.datetime(1,1,1,tzinfo=datetime.timezone.utc);ticks=(delta.days*86400+delta.seconds)*10000000+delta.microseconds*10
   if ticks>=birth_ticks and at<=last and e['domain'] not in names:names.append(e['domain'])
  row['dns_names']=sorted(names)[:20];row['dns_association']='logged_same_executable_PID_result_IP_and_time_not_socket_hostname_proof'
 return c
