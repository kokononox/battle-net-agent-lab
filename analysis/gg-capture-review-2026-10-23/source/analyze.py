"""Bounded pcapng/TCP evidence analysis. No raw endpoints or payload in public reports."""
from pathlib import Path
from collections import Counter,defaultdict
import os,struct,gzip,hashlib,json,decimal,socket,csv,zipfile,re,datetime
import dpkt
D=Path(__file__).resolve().parents[1];(D/'work').mkdir(exist_ok=True);(D/'reports').mkdir(exist_ok=True)
P=Path(os.environ.get('CAPTURE','/data/raw/gg.pcapng.gz'));compressed=P.read_bytes()
with gzip.open(P,'rb') as f:raw=f.read(64*1024*1024+1)
assert len(raw)<=64*1024*1024
(D/'work/gg.pcapng').write_bytes(raw)
def sha(b):return hashlib.sha256(b).hexdigest()
# Parse all block boundaries/interfaces independently of dpkt's iterator.
blocks=[];interfaces=[];interface_stats=[];packets=[];at=0;endian=None;ignored=Counter();sections=0
while at<len(raw):
 assert at+12<=len(raw)
 if raw[at:at+4]==b'\x0a\x0d\x0d\x0a':
  bom=raw[at+8:at+12];assert bom in [b'\x4d\x3c\x2b\x1a',b'\x1a\x2b\x3c\x4d'];endian='<' if bom[0]==0x4d else '>';sections+=1
 assert endian
 typ,length=struct.unpack_from(endian+'II',raw,at);assert length>=12 and length%4==0 and at+length<=len(raw);assert struct.unpack_from(endian+'I',raw,at+length-4)[0]==length
 body=raw[at+8:at+length-4];blocks.append((typ,length))
 if typ==1:
  link,_,snap=struct.unpack_from(endian+'HHI',body);res=decimal.Decimal('0.000001');offset=0;i=8
  while i+4<=len(body):
   code,n=struct.unpack_from(endian+'HH',body,i);i+=4;assert i+n<=len(body);v=body[i:i+n];i+=(n+3)&~3
   if code==0:assert n==0;break
   if code==9:
    assert n==1;x=v[0];res=decimal.Decimal(2 if x&128 else 10)**(-(x&127))
   if code==14:assert n==8;offset=struct.unpack(endian+'q',v)[0]
  interfaces.append({'linktype':link,'snaplen':snap,'resolution':str(res),'offset_seconds':offset})
 elif typ==6:
  iid,hi,lo,cap,orig=struct.unpack_from(endian+'IIIII',body);assert iid<len(interfaces) and 20+cap<=len(body) and cap<=orig
  t=(decimal.Decimal((hi<<32)|lo)*decimal.Decimal(interfaces[iid]['resolution'])+interfaces[iid]['offset_seconds']);packets.append({'index':len(packets)+1,'timestamp':t,'iid':iid,'captured_len':cap,'original_len':orig,'data':body[20:20+cap]})
 elif typ==5:
  iid,hi,lo=struct.unpack_from(endian+'III',body);stats={'interface_id':iid};i=12
  names={4:'received_packets',5:'interface_dropped_packets',6:'filter_accepted_packets',7:'os_dropped_packets',8:'delivered_packets'}
  while i+4<=len(body):
   code,n=struct.unpack_from(endian+'HH',body,i);i+=4;assert i+n<=len(body);v=body[i:i+n];i+=(n+3)&~3
   if code==0:assert n==0;break
   if code in names:assert n==8;stats[names[code]]=struct.unpack(endian+'Q',v)[0]
  interface_stats.append(stats)
 elif typ not in [0x0a0d0d0a]:ignored[typ]+=1
 at+=length
assert at==len(raw) and sections==1 and len(interfaces)==1 and interfaces[0]['linktype']==1
# Reader B independently yields the same packet bytes/timestamps.
reader=dpkt.pcapng.Reader(__import__('io').BytesIO(raw));reader_pkts=list(reader);assert len(reader_pkts)==len(packets)
for pkt,(ts,b) in zip(packets,reader_pkts):assert pkt['data']==b and abs(float(pkt['timestamp'])-float(ts))<0.000001
# Reassemble IPv4 fragmentation before TCP stream reassembly; otherwise artificial TCP gaps appear.
protocol=Counter();fragmented=0;fragment_groups={};datagrams=[];ip_frames=0
for pkt in packets:
 b=pkt['data'];assert len(b)>=14;kind=struct.unpack_from('!H',b,12)[0];off=14
 while kind in [0x8100,0x88a8]:kind=struct.unpack_from('!H',b,off+2)[0];off+=4
 if kind!=0x800:protocol['non_ipv4']+=1;continue
 assert len(b)>=off+20 and b[off]>>4==4;ihl=(b[off]&15)*4;length=struct.unpack_from('!H',b,off+2)[0];flags=struct.unpack_from('!H',b,off+6)[0];assert ihl>=20 and ihl<=length and off+length<=len(b)
 header=b[off:off+ihl];payload=b[off+ihl:off+length];proto=b[off+9];protocol[str(proto)]+=1;ip_frames+=1
 fragoff=(flags&8191)*8;more=bool(flags&8192)
 if fragoff or more:
  fragmented+=1;ident=struct.unpack_from('!H',b,off+4)[0];key=(b[off+12:off+16],b[off+16:off+20],ident,proto)
  # Repeated ID generations are refused rather than silently merged.
  g=fragment_groups.setdefault(key,[]);g.append({'offset':fragoff,'more':more,'payload':payload,'header':header,'packet':pkt})
 else:datagrams.append({'header':header,'payload':payload,'packets':[pkt]})
fragment_results=[]
for key,items in fragment_groups.items():
 assert sum(x['offset']==0 for x in items)==1 and sum(not x['more'] for x in items)==1
 endings={x['offset']+len(x['payload']) for x in items if not x['more']};assert len(endings)==1;end=next(iter(endings));assert end<=65535
 positions={};overlap=0
 for x in items:
  assert x['offset']+len(x['payload'])<=end
  if x['more']:assert len(x['payload'])%8==0
  for k,v in enumerate(x['payload'],x['offset']):
   if k in positions:assert positions[k]==v;overlap+=1
   positions[k]=v
 assert len(positions)==end and min(positions)==0 and max(positions)==end-1
 joined=bytes(positions[k] for k in range(end));first=next(x for x in items if x['offset']==0)
 # Independent interval-concatenation reconstruction; do not use positions map.
 alternative=bytearray()
 for x in sorted(items,key=lambda x:x['offset']):
  start=x['offset'];assert start<=len(alternative)
  shared=min(len(x['payload']),len(alternative)-start);assert alternative[start:start+shared]==x['payload'][:shared]
  alternative.extend(x['payload'][shared:])
 assert bytes(alternative)==joined
 datagrams.append({'header':first['header'],'payload':joined,'packets':[x['packet'] for x in items]})
 fragment_results.append({'frame_count':len(items),'reassembled_ip_payload_bytes':end,'overlap_byte_observations':overlap,'independent_reconstruction_equal':True})
datagrams.sort(key=lambda x:min(p['index'] for p in x['packets']));tcp=[];manual_tcp=manual3724=manual_payload=manual3724payload=0
for dat in datagrams:
 header=dat['header'];payload=dat['payload']
 if header[9]!=6:continue
 assert len(payload)>=20;sp,dp=struct.unpack_from('!HH',payload);th=(payload[12]>>4)*4;assert 20<=th<=len(payload);body=payload[th:]
 # Decode TCP via dpkt independently of the manual header slice.
 x=dpkt.tcp.TCP(payload);assert x.sport==sp and x.dport==dp and bytes(x.data)==body
 first=min(dat['packets'],key=lambda p:p['index']);src=(header[12:16],sp);dst=(header[16:20],dp)
 row={'index':first['index'],'timestamp':first['timestamp'],'src':src,'dst':dst,'seq':x.seq,'ack':x.ack,'flags':x.flags,'payload':body,'captured_len':sum(p['captured_len'] for p in dat['packets']),'original_len':sum(p['original_len'] for p in dat['packets']),'frame_indexes':[p['index'] for p in dat['packets']]};tcp.append(row)
 manual_tcp+=1;manual_payload+=len(body)
 if 3724 in [sp,dp]:manual3724+=1;manual3724payload+=len(body)
selected=[x for x in tcp if 3724 in [x['src'][1],x['dst'][1]]];assert manual_tcp==len(tcp) and manual3724==len(selected) and manual_payload==sum(len(x['payload']) for x in tcp) and manual3724payload==sum(len(x['payload']) for x in selected)
# Cross-foot all captured IPv4 frames to reassembled datagrams.
assert sum(len(x['packets']) for x in datagrams)==ip_frames
# Split flow generations on a new client SYN sequence number, not on arbitrary packet gaps.
flows=[];active={}
for x in selected:
 key=tuple(sorted([x['src'],x['dst']]));f=active.get(key);syn=bool(x['flags']&2 and not x['flags']&16)
 if f is None or (syn and f['syn_seq'] is not None and (x['src'],x['seq'])!=f['syn_seq']):
  f={'id':f'F{len(flows)+1:02d}','key':key,'packets':[],'syn_seq':(x['src'],x['seq']) if syn else None};flows.append(f);active[key]=f
 elif syn and f['syn_seq'] is None:f['syn_seq']=(x['src'],x['seq'])
 f['packets'].append(x)
# Evidence values derived locally from prior logs, never published in raw form.
needles={};logzip=Path(os.environ.get('LOG_ARCHIVE','_retail_a.zip'))
if logzip.exists():
 with zipfile.ZipFile(logzip) as z:
  cpu=z.read('Logs/cpu.log').decode('utf-8-sig');gx=z.read('Logs/gx.log').decode('utf-8-sig')
  needles['cpu_vendor']=re.search(r'vendor: (.+)',cpu).group(1).strip();needles['cpu_branding']=re.search(r'branding: (.+)',cpu).group(1).strip();needles['cpu_model_token']=re.search(r'i\d-\d+[A-Za-z]*',needles['cpu_branding']).group(0)
  mat=re.search(r'Motherboard: "([^"]+)" by "([^"]+)" \(BIOS:(.+) version:(.+) date:([^\)]+)\)',gx);assert mat
  needles.update({'motherboard_model_short':mat[1],'bios_version':mat[4],'bios_date':mat[5]})
public=[];stream_needles=[];all_runs=[];packet_rows=[]
for f in flows:
 pk=f['packets'];key=f['key'];client=f['syn_seq'][0] if f['syn_seq'] else None
 a=client if client else key[0];b=key[1] if a==key[0] else key[0];fr={'id':f['id'],'tcp_segment_count':len(pk),'duration_seconds':float(max(x['timestamp'] for x in pk)-min(x['timestamp'] for x in pk)),'client_identified_by_syn':client is not None,'syn_destination_port_is_3724':b[1]==3724 if client else None,'syn_seen':any(x['flags']&2 for x in pk),'fin_seen':any(x['flags']&1 for x in pk),'rst_seen':any(x['flags']&4 for x in pk),'directions':[]}
 for source,target,label in [(a,b,'client_to_server' if client else 'A_to_B'),(b,a,'server_to_client' if client else 'B_to_A')]:
  ps=[x for x in pk if x['src']==source];data=[x for x in ps if x['payload']];syns=[x for x in ps if x['flags']&2];origin=((syns[0]['seq']+1)&0xffffffff) if syns else (data[0]['seq'] if data else 0)
  positions={};duplicated=0;conflicting=0
  for x in data:
   seq=(x['seq']+(1 if x['flags']&2 else 0))&0xffffffff;start=((seq-origin+2**31)%2**32)-2**31;assert abs(start)<64*1024*1024
   for k,val in enumerate(x['payload'],start):
    if k in positions:
     duplicated+=1
     if positions[k]!=val:conflicting+=1
    else:positions[k]=val
  ordered=sorted(positions);runs=[];gaps=[]
  for k in ordered:
   if not runs or k!=runs[-1][0]+len(runs[-1][1]):
    if runs:gaps.append([runs[-1][0]+len(runs[-1][1]),k])
    runs.append([k,bytearray()])
   runs[-1][1].append(positions[k])
  # Independent interval union validates unique counts and internal holes.
  intervals=[]
  for x in data:
   seq=(x['seq']+(1 if x['flags']&2 else 0))&0xffffffff;start=((seq-origin+2**31)%2**32)-2**31
   intervals.append((start,start+len(x['payload'])))
  merged=[]
  for left,right in sorted(intervals):
   if merged and left<=merged[-1][1]:merged[-1][1]=max(merged[-1][1],right)
   else:merged.append([left,right])
  assert sum(right-left for left,right in merged)==len(positions)
  assert [[left,left+len(buf)] for left,buf in runs]==merged
  assert duplicated==sum(len(x['payload']) for x in data)-len(positions)
  banners=[];tls=[]
  for no,(start,buf) in enumerate(runs):
   rawrun=bytes(buf);all_runs.append(rawrun)
   for banner in [b'WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT',b'WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER']:
    if banner in rawrun:banners.append({'text':banner.decode(),'stream_offset':start+rawrun.find(banner)})
   # TLS record at start is only recognized with complete record framing, no key claims.
   pos=0;records=[]
   while pos+5<=len(rawrun) and rawrun[pos] in [20,21,22,23,24] and rawrun[pos+1]==3 and rawrun[pos+2]<=4:
    n=int.from_bytes(rawrun[pos+3:pos+5],'big')
    if n>18432 or pos+5+n>len(rawrun):break
    records.append({'type':rawrun[pos],'legacy_version':rawrun[pos+1:pos+3].hex(),'length':n});pos+=5+n
   if records:tls.append({'run':no,'records':records,'covered_prefix_bytes':pos})
   for n,value in needles.items():
    for enc in ['ascii','utf-16le']:
     pattern=value.encode(enc);occ=[];off=0
     while True:
      hit=rawrun.find(pattern,off)
      if hit<0:break
      occ.append(start+hit);off=hit+1
     stream_needles.append({'flow':f['id'],'direction':label,'run':no,'value_label':n,'encoding':enc,'match_offsets':occ,'short_value_caveat':n.endswith('_short')})
  dr={'direction':label,'tcp_segment_count':len(ps),'payload_segments':len(data),'captured_payload_bytes_including_retransmissions':sum(len(x['payload']) for x in data),'unique_captured_bytes':len(positions),'duplicate_byte_observations':duplicated,'conflicting_byte_observations':conflicting,'initial_sequence_known_from_syn':bool(syns),'contiguous_runs':[{'offset':start,'length':len(buf),'sha256':sha(bytes(buf))} for start,buf in runs],'internal_gaps':gaps,'wow_banners':banners,'tls_framed_prefixes':tls}
  fr['directions'].append(dr)
 for x in pk:packet_rows.append({'first_frame_index':x['index'],'captured_frames_in_segment':len(x['frame_indexes']),'relative_seconds':float(x['timestamp']-packets[0]['timestamp']),'flow':f['id'],'direction':'client_to_server' if client and x['src']==client else 'server_to_client' if client else 'A_to_B' if x['src']==a else 'B_to_A','payload_bytes':len(x['payload']),'flags':x['flags'],'truncated':x['captured_len']<x['original_len']})
 public.append(fr)
with (D/'work/packet_metadata.csv').open('w') as f:
 fields=['first_frame_index','captured_frames_in_segment','relative_seconds','flow','direction','payload_bytes','flags','truncated'];w=csv.DictWriter(f,fields);w.writeheader();w.writerows(packet_rows)
matched=[x for x in stream_needles if x['match_offsets']]
evidence={'source':{'compressed_sha256':sha(compressed),'compressed_bytes':len(compressed),'pcapng_sha256':sha(raw),'pcapng_bytes':len(raw),'dpkt_version':dpkt.__version__,'profile_caveat':'Generic tabular profiler cannot parse pcapng/gzip; block and packet structure profiled with pcapng reader; derived metadata separately profiled.'},'capture':{'sections':sections,'blocks':dict(Counter(str(t) for t,n in blocks)),'interfaces':interfaces,'packet_count':len(packets),'interface_statistics':interface_stats,'start_utc':datetime.datetime.fromtimestamp(float(min(x['timestamp'] for x in packets)),datetime.timezone.utc).isoformat(),'end_utc':datetime.datetime.fromtimestamp(float(max(x['timestamp'] for x in packets)),datetime.timezone.utc).isoformat(),'capture_duration_seconds':float(max(x['timestamp'] for x in packets)-min(x['timestamp'] for x in packets)),'truncated_packet_count':sum(x['captured_len']<x['original_len'] for x in packets),'fragmented_ipv4_frame_count':fragmented,'reassembled_ipv4_datagram_count':len(datagrams),'fragmented_datagram_count':len(fragment_results),'fragment_reassembly':fragment_results,'ipv4_protocol_counts':dict(protocol),'ignored_block_types':dict(ignored)},'tcp3724':{'tcp_segment_count':len(selected),'flow_count':len(flows),'captured_frame_count':sum(len(x['frame_indexes']) for x in selected),'captured_payload_bytes_including_retransmissions':sum(len(x['payload']) for x in selected),'flows':public},'plaintext_value_search':{'source_log_archive_present':bool(needles),'source_log_archive_sha256':sha(logzip.read_bytes()) if needles else None,'value_labels':list(needles),'encodings':['ascii','utf-16le'],'scope':'Captured contiguous TCP/3724 stream runs only, no crossing sequence gaps. Values from local CPU/BIOS logs; binary/encoded/compressed representations not covered. Logs and capture not assumed same session.','match_records':matched,'search_tests':len(stream_needles),'examined_value_labels_count':len(needles),'raw_values_published':False},'independent_checks':{'pcapng_dpkt_packet_bytes_count_and_timestamps_equal':True,'ip_fragment_reassembly_two_paths_equal':True,'tcp_interval_union_independent_counts_and_gaps_equal':True,'manual_reassembled_tcp_segment_count':manual_tcp,'manual_reassembled_tcp3724_segment_count':manual3724,'manual_tcp3724_payload_bytes_including_retransmissions':manual3724payload},'answer_plan':{'question':'Does this capture establish hardware values sent on TCP/3724, and is application content interpretable?','chart_disposition':'omit','chart_reason':'Question is protocol/content evidence and missing attribution, not a comparison or time trend. Packet sizes/counts do not establish field contents; no causal chart is justified.','proof_of_hardware_message_send':False,'capture_process_or_exact_build_verified':False,'application_prefix_interpretable':'World of Warcraft connection banners on three SYN-observed TCP/3724 flows','post_banner_application_fields_decoded':False,'encryption_claim':'Do not infer encryption from non-printable bytes or failure to find values. Need recognized framing or verified protocol/cipher state.'}}
(D/'reports/evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
print('Packets',len(packets),'TCP3724',len(selected),'flows',len(flows),'capture_duration',evidence['capture']['capture_duration_seconds'],'truncated',evidence['capture']['truncated_packet_count'])
for f in public:
 print(f['id'],'pkts',f['tcp_segment_count'],'duration',f['duration_seconds'],'SYN',f['syn_seen'],'FIN',f['fin_seen'],'RST',f['rst_seen'])
 for x in f['directions']:print(x['direction'],'unique',x['unique_captured_bytes'],'duplicate',x['duplicate_byte_observations'],'conflicts',x['conflicting_byte_observations'],'runs',len(x['contiguous_runs']),'gaps',x['internal_gaps'],'banners',x['wow_banners'],'TLS',x['tls_framed_prefixes'])
print('plaintext matches',matched)
