"""Bounded offline PCAPNG reader: DNS and TLS ClientHello only, no decryption.
Raw payloads never exported; system DNS metadata is NOT process-attributed.
Per-flow bytes are capture observations, not unique application bytes.
"""
from collections import Counter,defaultdict
import ipaddress,json,struct,hashlib
from pathlib import Path
MAX_BLOCK=2*1024**2
MAX_FLOWS=4096
MAX_STREAM=65536
MAX_STREAM_TOTAL=16*1024**2


def domain(s):
 import re
 if not isinstance(s,str):return None
 s=s.lower().rstrip('.')
 if not 1<=len(s)<=253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in s.split('.')):return None
 try:ipaddress.ip_address(s);return None
 except ValueError:return s


def packets(path):
 # Enhanced packet blocks only. Section changes reset interface IDs and timestamp resolution.
 with Path(path).open('rb') as f:
  endian=None;interfaces={};section=-1
  while True:
   head=f.read(8)
   if not head:return
   if len(head)!=8:raise ValueError('pcapng_truncated_block_header')
   if head[:4]==b'\x0a\x0d\x0d\x0a':
    magic=f.read(4)
    if magic==b'\x4d\x3c\x2b\x1a':endian='<'
    elif magic==b'\x1a\x2b\x3c\x4d':endian='>'
    else:raise ValueError('pcapng_invalid_section_magic')
    total=struct.unpack(endian+'I',head[4:])[0]
    if not 28<=total<=MAX_BLOCK or total%4:raise ValueError('pcapng_block_size_limit')
    rest=f.read(total-12);body=magic+rest[:-4]
    if len(rest)!=total-12 or struct.unpack(endian+'I',rest[-4:])[0]!=total:raise ValueError('pcapng_bad_section_length')
    interfaces={};section+=1;continue
   if endian is None:raise ValueError('pcapng_section_required')
   kind,total=struct.unpack(endian+'II',head)
   if not 12<=total<=MAX_BLOCK or total%4:raise ValueError('pcapng_block_size_limit')
   rest=f.read(total-8)
   if len(rest)!=total-8 or struct.unpack(endian+'I',rest[-4:])[0]!=total:raise ValueError('pcapng_bad_block_length')
   body=rest[:-4]
   if kind==1:
    if len(body)<8:raise ValueError('pcapng_short_interface')
    link=struct.unpack_from(endian+'H',body)[0];resolution=1e-6;offset=0;p=8
    while p+4<=len(body):
     code,n=struct.unpack_from(endian+'HH',body,p);p+=4
     if p+n>len(body):raise ValueError('pcapng_bad_interface_option')
     value=body[p:p+n];p+=(n+3)//4*4
     if code==0:break
     if code==9 and n==1:
      resolution=(2.0**-(value[0]&127)) if value[0]&128 else (10.0**-value[0])
     if code==14 and n==8:offset=struct.unpack(endian+'q',value)[0]
    if len(interfaces)>=1024:raise ValueError('pcapng_interface_limit')
    interfaces[len(interfaces)]=(link,resolution,offset)
   elif kind==6:
    if len(body)<20:raise ValueError('pcapng_short_packet')
    iface,hi,lo,caplen,wirelen=struct.unpack_from(endian+'IIIII',body)
    if iface not in interfaces or caplen>len(body)-20 or caplen>wirelen:raise ValueError('pcapng_packet_bounds')
    link,res,offset=interfaces[iface]
    yield {'data':body[20:20+caplen],'wire_length':wirelen,'interface':(section,iface),
     'timestamp':((hi<<32)|lo)*res+offset,'linktype':link,'capture_truncated':caplen<wirelen}


def ip_packet(frame,link):
 data=bytes(frame)
 if link==1:
  if len(data)<14:return None
  typ=int.from_bytes(data[12:14],'big');p=14
  for _ in range(2):
   if typ not in (0x8100,0x88a8):break
   if len(data)<p+4:return None
   typ=int.from_bytes(data[p+2:p+4],'big');p+=4
  if typ not in (0x800,0x86dd):return None
  data=data[p:]
 elif link==0:
  if len(data)<4:return None
  data=data[4:]
 elif link not in (12,101,228,229):return None
 if not data:return None
 version=data[0]>>4
 if version==4:
  if len(data)<20:return None
  h=(data[0]&15)*4;total=int.from_bytes(data[2:4],'big')
  if h<20 or h>len(data) or total<h:return None
  # IP fragments are not guessed/reassembled.
  if int.from_bytes(data[6:8],'big')&0x3fff:return None
  src=str(ipaddress.ip_address(data[12:16]));dst=str(ipaddress.ip_address(data[16:20]));proto=data[9]
  payload=data[h:min(total,len(data))];declared=total-h
 elif version==6:
  if len(data)<40:return None
  total=40+int.from_bytes(data[4:6],'big');src=str(ipaddress.ip_address(data[8:24]));dst=str(ipaddress.ip_address(data[24:40]));proto=data[6];h=40
  if total==40:return None # Jumbograms not supported.
  for _ in range(8):
   if proto not in (0,43,60,44,51):break
   if proto==44:return None
   if h+2>min(total,len(data)):return None
   n=(data[h+1]+2)*4 if proto==51 else (data[h+1]+1)*8
   if h+n>min(total,len(data)):return None
   proto,h=data[h],h+n
  payload=data[h:min(total,len(data))];declared=total-h
 else:return None
 if proto==6:
  if len(payload)<20:return None
  sp,dp,seq=struct.unpack_from('!HHI',payload);h=(payload[12]>>4)*4
  if h<20 or h>len(payload) or declared<h:return None
  return {'protocol':'tcp','src':src,'dst':dst,'sport':sp,'dport':dp,'seq':seq,
   'flags':payload[13],'payload':payload[h:],'declared_payload_bytes':declared-h}
 if proto==17:
  if len(payload)<8:return None
  sp,dp,n=struct.unpack_from('!HHH',payload)
  if n<8:return None
  return {'protocol':'udp','src':src,'dst':dst,'sport':sp,'dport':dp,'payload':payload[8:min(n,len(payload))],
   'declared_payload_bytes':n-8}
 return None


def dns_name(data,pos):
 parts=[];seen=set();end=None
 for _ in range(64):
  if pos>=len(data) or pos in seen:raise ValueError('dns_name_bounds')
  seen.add(pos);n=data[pos]
  if n&0xc0==0xc0:
   if pos+1>=len(data):raise ValueError('dns_pointer_bounds')
   if end is None:end=pos+2
   pos=((n&63)<<8)|data[pos+1];continue
  if n&0xc0 or n>63:raise ValueError('dns_label_invalid')
  pos+=1
  if n==0:
   text='.'.join(parts)
   if len(text)>253:raise ValueError('dns_name_limit')
   return text,end if end is not None else pos
  if pos+n>len(data):raise ValueError('dns_label_bounds')
  parts.append(data[pos:pos+n].decode('ascii'));pos+=n
 raise ValueError('dns_name_iteration_limit')


def dns_message(data):
 if len(data)<12:raise ValueError('dns_header_short')
 ident,flags,qd,an,ns,ar=struct.unpack_from('!HHHHHH',data)
 if qd>32 or an+ns+ar>256:raise ValueError('dns_record_limit')
 p=12;questions=[];answers=[]
 for _ in range(qd):
  name,p=dns_name(data,p)
  if p+4>len(data):raise ValueError('dns_question_bounds')
  typ,cls=struct.unpack_from('!HH',data,p);p+=4
  if (d:=domain(name)):questions.append({'domain':d,'type':typ})
 for i in range(an+ns+ar):
  name,p=dns_name(data,p)
  if p+10>len(data):raise ValueError('dns_answer_bounds')
  typ,cls,ttl,n=struct.unpack_from('!HHIH',data,p);p+=10
  if p+n>len(data):raise ValueError('dns_rdata_bounds')
  if i<an and cls==1:
   if typ==1 and n==4 or typ==28 and n==16:
    answers.append({'domain':domain(name),'ip':str(ipaddress.ip_address(data[p:p+n]))})
   elif typ==5:
    target,_=dns_name(data,p)
    if domain(name) and domain(target):answers.append({'domain':domain(name),'cname':domain(target)})
  p+=n
 return {'response':bool(flags&0x8000),'rcode':flags&15,'questions':questions,'answers':answers,'truncated':bool(flags&0x200)}


def clienthello_sni(stream):
 # Reassemble handshake bytes across consecutive TLS handshake records, not arbitrary byte scanning.
 raw=bytes(stream);p=0;hand=bytearray()
 for _ in range(16):
  if p+5>len(raw):return None,'incomplete_tls_records'
  kind,major,n=raw[p],raw[p+1],int.from_bytes(raw[p+3:p+5],'big')
  if kind!=22 or major!=3:return None,'not_clienthello_at_stream_start'
  if n>18432 or p+5+n>len(raw):return None,'incomplete_tls_records'
  hand.extend(raw[p+5:p+5+n]);p+=5+n
  if len(hand)<4:continue
  if hand[0]!=1:return None,'not_clienthello_at_stream_start'
  size=int.from_bytes(hand[1:4],'big')
  if size>MAX_STREAM:return None,'clienthello_size_limit'
  if len(hand)<4+size:continue
  b=hand[4:4+size]
  try:
   q=34
   def take(n):
    nonlocal q
    if q+n>len(b):raise ValueError()
    old=q;q+=n;return old
   n=b[take(1)];take(n);n=int.from_bytes(b[take(2):q],'big');take(n)
   n=b[take(1)];take(n)
   if q==len(b):return None,'clienthello_without_extensions'
   n=int.from_bytes(b[take(2):q],'big');end=q+n
   if end>len(b):raise ValueError()
   while q+4<=end:
    typ=int.from_bytes(b[take(2):q],'big');n=int.from_bytes(b[take(2):q],'big');start=take(n)
    if typ!=0:continue
    if n<2:raise ValueError()
    x=start+2;stop=x+int.from_bytes(b[start:start+2],'big')
    if stop>start+n:raise ValueError()
    while x+3<=stop:
     nt=b[x];ln=int.from_bytes(b[x+1:x+3],'big');x+=3
     if x+ln>stop:raise ValueError()
     if nt==0:
      return domain(b[x:x+ln].decode('ascii')),'clienthello_outer_sni'
     x+=ln
   return None,'clienthello_without_visible_sni'
  except (ValueError,IndexError,UnicodeError):return None,'invalid_clienthello'
 return None,'tls_record_limit'


class Analyzer:
 def __init__(self,ownership,refs=None):
  # Keys are exact sampled TCP local/remote address+port tuples. No domain inference by PTR.
  self.refs=dict(refs or {});self.ownership=ownership;self.flows={};self.streams={};self.total_stream_bytes=0
  self.dns={};self.counts=Counter();self.limits=[];self.parse_errors=Counter()
 def match(self,p,timestamp):
  fwd=(p['src'],p['sport'],p['dst'],p['dport']);rev=(p['dst'],p['dport'],p['src'],p['sport'])
  for key,direction in ((fwd,'outgoing'),(rev,'incoming')):
   owners=self.ownership.get(key,[])
   # All observed owners of this tuple must agree; unobserved PID reuse remains a limitation.
   ids={o['process_index'] for o in owners}
   if len(ids)!=1:continue
   near=[o for o in owners if o['first_seen_epoch']-1<=timestamp<=o['last_seen_epoch']+1]
   if near:return (key,next(iter(ids)),direction)
  return None
 def add(self,packet):
  self.counts['captured_packets']+=1
  if packet['capture_truncated']:self.counts['truncated_capture_packets']+=1
  p=ip_packet(packet['data'],packet['linktype'])
  if not p:self.counts['unsupported_or_non_ip_packets']+=1;return
  if p['protocol']=='udp':
   self.counts['udp_packets_not_process_attributed']+=1
   if p['sport']==53 or p['dport']==53:
    try:
     d=dns_message(p['payload']);key=json.dumps(d,sort_keys=True)
     if len(self.dns)<1024 or key in self.dns:self.dns[key]=d
     elif 'dns_export_limit' not in self.limits:self.limits.append('dns_export_limit')
    except (ValueError,UnicodeError):self.parse_errors['dns']+=1
   return
  m=self.match(p,packet['timestamp'])
  if not m:self.counts['tcp_packets_not_attributed_to_selected_processes']+=1;return
  key,index,direction=m;fk=(index,*key)
  if fk not in self.flows:
   if len(self.flows)>=MAX_FLOWS:
    if 'flow_limit' not in self.limits:self.limits.append('flow_limit')
    return
   self.flows[fk]={'process_index':index,'remote_address':key[2],'remote_port':key[3],
    'outgoing_captured_packets':0,'incoming_captured_packets':0,
    'outgoing_tcp_payload_bytes_observed':0,'incoming_tcp_payload_bytes_observed':0,
    'outgoing_captured_prefix_bytes':0,'incoming_captured_prefix_bytes':0,
    'first_packet_epoch':packet['timestamp'],'last_packet_epoch':packet['timestamp'],
    'sni':None,'sni_status':'not_inspected','plaintext_http_host':None,
    'capture_interface_count':0,'_interfaces':set(),'readable_http_requests':[]}
  f=self.flows[fk];f[direction+'_captured_packets']+=1
  f[direction+'_tcp_payload_bytes_observed']+=p['declared_payload_bytes']
  f[direction+'_captured_prefix_bytes']+=len(p['payload'])
  f['last_packet_epoch']=max(f['last_packet_epoch'],packet['timestamp']);f['_interfaces'].add(packet['interface']);f['capture_interface_count']=len(f['_interfaces'])
  if direction!='outgoing':return
  # One interface per stream to avoid fabricating reassembly across duplicate capture layers.
  sk=(fk,packet['interface']);s=self.streams.setdefault(sk,{'base':None,'parts':{},'syn':False,'limited':False,'first_ts':packet['timestamp']})
  if p['flags']&2:
   s['base']=(p['seq']+1)&0xffffffff;s['syn']=True
  if not p['payload']:return
  if s['base'] is None:s['base']=p['seq'] # Midstream observation, explicitly unproven stream beginning.
  seq=(p['seq']+(1 if p['flags']&2 else 0))&0xffffffff
  off=(seq-s['base'])&0xffffffff
  if off>MAX_STREAM or self.total_stream_bytes+len(p['payload'])>MAX_STREAM_TOTAL:
   s['limited']=True;return
  raw=p['payload'][:MAX_STREAM-off]
  if off in s['parts']:
   if s['parts'][off]!=raw:s['limited']=True
   return
  s['parts'][off]=raw;self.total_stream_bytes+=len(raw)
 def finish(self):
  from http_input import parse_requests
  dns_ip={}
  for d in self.dns.values():
   if not d['response'] or d['rcode']!=0:continue
   q=[x['domain'] for x in d['questions']]
   for a in d['answers']:
    if a.get('ip'):
     dns_ip.setdefault(a['ip'],set()).update(q+([a['domain']] if a.get('domain') else []))
  for (fk,iface),s in self.streams.items():
   data=bytearray();pos=0
   for off,raw in sorted(s['parts'].items()):
    if off>pos:break
    if off+len(raw)<=pos:continue
    # Overlapping bytes must agree, not silently win.
    overlap=pos-off
    if overlap and bytes(data[off:pos])!=raw[:overlap]:s['limited']=True;break
    data.extend(raw[overlap:]);pos=off+len(raw)
   f=self.flows[fk];name,status=clienthello_sni(data)
   if name:
    f['sni']=name;f['sni_status']=status;f['sni_stream_start_syn_observed']=s['syn']
   elif f['sni'] is None:f['sni_status']=status
   # Header-only HTTP Host preview, no URL/headers/body values exported.
   if bytes(data).startswith((b'GET ',b'POST ',b'HEAD ',b'PUT ',b'OPTIONS ',b'PATCH ',b'DELETE ')):
    try:
     rows,_=parse_requests(bytes(data),redact_secrets=False)
     if rows:
      f['plaintext_http_host']=rows[0]['host'];f['plaintext_http_methods']=sorted({r['method'] for r in rows})
      f['plaintext_http_request_count']=len(rows)
      if not f['readable_http_requests']:
       from hardware import literal_matches
       from body_meta import analyze_body
       import base64
       for r in rows:
        body=base64.b64decode(r['body_sample_base64'])
        head=(r['method']+' '+r['target']+' HTTP/1.1\r\n'+'\r\n'.join(k+': '+v for k,v in r['headers'])+'\r\n\r\n').encode('latin1')
        meta=analyze_body(head+body,len(head)+len(body))
        f['readable_http_requests'].append({'method':r['method'],'host':r['host'],
         'path_hint':'/tpr/...' if r['target'].startswith('/tpr/') else '/data' if r['target'].split('?',1)[0]=='/data' else 'other_not_exported',
         'query_present':'?' in r['target'],'body_complete':r['body_complete'],
         'body_declared_bytes':r['body_declared_bytes'],'body_observed_bytes':r['body_observed_bytes'],
         'body_format_hint':meta['format'],'known_field_name_hints':meta['field_name_hints'],
         'hardware_literal_categories':literal_matches(r,self.refs),
         'credential_header_present':any(k in {'cookie','authorization','proxy-authorization'} for k,v in r['headers'])})
    except (ValueError,UnicodeError):self.parse_errors['http']+=1
   if s['limited']:
    if 'stream_prefix_limit_or_overlap_conflict' not in self.limits:self.limits.append('stream_prefix_limit_or_overlap_conflict')
  rows=[]
  for fk,f in self.flows.items():
   f.pop('_interfaces',None);f['dns_answer_domain_candidates_not_proof']=sorted(dns_ip.get(f['remote_address'],set()))[:32]
   rows.append(f)
  reference_categories=sorted(self.refs);self.refs.clear()
  return {'selected_process_tcp_flows':rows,'system_dns_observations_not_process_attributed':list(self.dns.values()),
   'capture_counts':dict(self.counts),'parse_errors':dict(self.parse_errors),'limits_hit':self.limits,
   'tcp_payload_bytes_are_observed_wire_payload_not_unique_application_upload':True,
   'retransmissions_duplicate_capture_interfaces_offload_and_packet_loss_not_corrected':True,
   'dns_to_game_attribution_proven':False,'hardware_reference_categories_available':reference_categories,'tls_or_game_protocol_decrypted':False,
   'no_hardware_transmission_or_only_download_verdict':True}
