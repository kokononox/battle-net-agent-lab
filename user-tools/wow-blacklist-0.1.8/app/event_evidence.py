"""Conservative sanitization of existing Windows event evidence. No audit/configuration changes."""
import ipaddress,re,os
from observation_model import timestamp
MAX_EVENTS=1000
KINDS={'dns_query','wfp_connection_block'}
def device_program_path(program):
 if os.name!='nt':return ''
 try:
  import ctypes
  from pathlib import Path
  drive=Path(program).drive
  buffer=ctypes.create_unicode_buffer(32768)
  query=ctypes.windll.kernel32.QueryDosDeviceW;query.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_uint32];query.restype=ctypes.c_uint32
  if not query(drive,buffer,len(buffer)):return ''
  return buffer.value+str(program)[len(drive):]
 except Exception:return ''
def hosts_baseline(reader):
 try:
  raw=reader();return dict(available=True,truncated=raw.get('truncated') is True,checked_utc_epoch=raw.get('checked_utc_epoch'),entries=[dict(domain=e['domain'],addresses=e['addresses'],mapping_kind=e['mapping_kind']) for e in raw['entries'][:5000]])
 except Exception:return dict(available=False,truncated=False,entries=[])
def normalize_evidence(raw):
 raw=raw if isinstance(raw,dict) else {};events=[];seen=set()
 for e in raw.get('events',[])[:MAX_EVENTS] if isinstance(raw.get('events',[]),list) else []:
  try:
   ident=e['record_id'];kind=e['kind'];when=timestamp(e['observed_utc']);pid=e['pid']
   if not isinstance(ident,str) or not re.fullmatch('[a-f0-9]{32}',ident) or ident in seen or kind not in KINDS or not when or type(pid) is not int or not 0<pid<=0xffffffff:continue
   row=dict(record_id=ident,kind=kind,observed_utc=when,pid=pid,event_record_id=max(0,int(e.get('event_record_id',0))),attribution='logged_application_path_exact_match',HTTP_request_verified=False,rule_owner_verified=False)
   if kind=='dns_query':
    name=e.get('domain','').rstrip('.').lower()
    if not isinstance(name,str) or not re.fullmatch(r'[a-z0-9_][a-z0-9_.-]{0,252}',name):continue
    addresses=[]
    for value in e.get('hosts_addresses',[])[:16]:
     try:addresses.append(str(ipaddress.ip_address(value)))
     except ValueError:pass
    mapping=e.get('hosts_mapping') if e.get('hosts_mapping') in {'local_sink_mapping','mixed_mapping','other_mapping','system_local','not_listed','hosts_unavailable'} else 'hosts_unavailable'
    row.update(domain=name,dns_status=str(e.get('dns_status','unknown'))[:24],query_results=str(e.get('query_results',''))[:2000],source='Sysmon_22',hosts_mapping=mapping,hosts_addresses=addresses,hosts_block_verified=False,packet_block_verified=False)
   else:
    if e.get('direction')!='outbound':continue
    address=str(ipaddress.ip_address(e['ip']));port=e['port'];protocol=e['protocol']
    if type(port) is not int or not 1<=port<=65535 or protocol not in {'TCP','UDP'}:continue
    row.update(ip=address,port=port,protocol=protocol,source='Security_5157',direction='outbound',connection_block_event_verified=True,packet_drop_verified=False,filter_id=str(e.get('filter_id',''))[:32])
   events.append(row);seen.add(ident)
  except (ValueError,TypeError,KeyError,AttributeError):continue
 streams={}
 for source in ('dns','wfp'):
  item=raw.get('streams',{}).get(source,{}) if isinstance(raw.get('streams',{}),dict) else {};status=item.get('status') if isinstance(item,dict) else None
  streams[source]=dict(status=status if status in {'readable_logging_coverage_unverified','not_available_or_disabled','read_failed','not_collected'} else 'not_collected',coverage_verified=False)
 return dict(schema='wow-event-evidence-1',events=events,streams=streams,truncated=raw.get('truncated') is True,cap=MAX_EVENTS,configuration_changed=False,hosts_snapshot_available=raw.get('hosts_snapshot_available') is True,hosts_snapshot_truncated=raw.get('hosts_snapshot_truncated') is True)
