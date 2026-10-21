"""Read-only evidence normalization and matching; never infer packet drops from TCP snapshots."""
import datetime,ipaddress,re
STATES={'Closed','Listen','SynSent','SynReceived','Established','FinWait1','FinWait2','CloseWait','Closing','LastAck','TimeWait','DeleteTCB','Unknown'}

def timestamp(value):
 if not isinstance(value,str) or len(value)>50:return ''
 try:
  parsed=datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
  if parsed.tzinfo is None:return ''
  return parsed.astimezone(datetime.timezone.utc).isoformat()
 except (ValueError,OverflowError):return ''

def normalize_rows(raw):
 if not isinstance(raw,list):return []
 rows=[];seen=set()
 for item in raw[:2000]:
  try:
   ip=ipaddress.ip_address(item['ip']);port=item['port'];pid=item.get('pid',0);started=timestamp(item.get('process_started_utc'))
   if not ip.is_global or ip.is_multicast or ip.is_reserved or type(port) is not int or not 1<=port<=65535:continue
   if type(pid) is not int or not 0<=pid<=0xffffffff:continue
   key=(str(ip),port,pid,started)
   if key in seen:continue
   counts={};state_data=item.get('state_samples')
   if state_data is None:state_data={}
   if not isinstance(state_data,dict):continue
   for state,value in state_data.items():
    if state in STATES and type(value) is int and 0<value<=2000000:counts[state]=value
   if not counts:counts={'Unknown':max(1,min(2000000,int(item.get('samples',1))))}
   samples=max(0,min(2000000,int(item.get('samples',sum(counts.values())))))
   rows.append(dict(ip=str(ip),port=port,protocol='TCP',pid=pid,process_started_utc=started,fresh_process_seen=item.get('fresh_process_seen') is True and pid>0 and bool(started),samples=samples,state_samples=counts,established_seen=counts.get('Established',0)>0,syn_sent_seen=counts.get('SynSent',0)>0,first_seen_utc=timestamp(item.get('first_seen_utc')),last_seen_utc=timestamp(item.get('last_seen_utc'))))
   if 'phase_hits' in item:
    from phase_context import clean_hits
    rows[-1]['phase_hits']=clean_hits(item['phase_hits'],rows[-1]['first_seen_utc'],rows[-1]['last_seen_utc'],samples)
   if isinstance(item.get('record_id'),str) and re.fullmatch('[a-f0-9]{32}',item['record_id']):rows[-1]['record_id']=item['record_id']
   if item.get('destination_history') in ('previously_seen','first_in_local_history','history_uncertain'):rows[-1]['destination_history']=item['destination_history']
   if type(item.get('discovery_sequence')) is int and 1<=item['discovery_sequence']<=2000:rows[-1]['discovery_sequence']=item['discovery_sequence']
   if type(item.get('seen_in_latest_sample')) is bool:rows[-1]['seen_in_latest_sample']=item['seen_in_latest_sample']
   seen.add(key)
  except (KeyError,TypeError,ValueError,AttributeError,OverflowError):continue
 return rows

def classify_rows(rows,snapshot):
 verified=[]
 if snapshot.get('available') is True:
  for entry in snapshot.get('entries',[]):
   try:verified.append((ipaddress.ip_network(entry['ip']),entry['port'],entry['protocol'],entry['ip']))
   except (ValueError,KeyError,TypeError):continue
 out=[]
 for row in rows:
  ip=ipaddress.ip_address(row['ip']);matches=[]
  for net,port,protocol,target in verified:
   if protocol==row['protocol'] and port==row['port'] and ip in net:matches.append(dict(ip=target,port=port,protocol=protocol))
  out.append({**row,'covered_by_verified_block':bool(matches),'block_matches':matches,'block_classification':'verified_match' if matches else ('no_verified_match' if snapshot.get('available') is True else 'unverified'),'block_checked_utc':snapshot.get('checked_utc'),'packet_drop_verified':False})
 return out
