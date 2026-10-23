"""Independent transport reconstruction checked against pinned prior stream hashes."""
from pathlib import Path
import os,gzip,json,struct,hashlib,collections
import dpkt
D=Path(__file__).resolve().parents[1]
def sha(b):return hashlib.sha256(b).hexdigest()
def rebuild():
 P=Path(os.environ.get('CAPTURE','/data/raw/gg.pcapng.gz'));base=json.loads((D/'reference/capture-baseline.json').read_text());assert sha(P.read_bytes())==base['source']['compressed_sha256']
 with gzip.open(P,'rb') as f:raw=f.read(64*1024*1024+1)
 assert len(raw)<=64*1024*1024 and sha(raw)==base['source']['pcapng_sha256']
 reader=dpkt.pcapng.Reader(__import__('io').BytesIO(raw));assert reader.datalink()==1
 groups=collections.defaultdict(list);datagrams=[]
 for idx,(ts,b) in enumerate(reader,1):
  assert len(b)>=14;kind=struct.unpack_from('!H',b,12)[0];off=14
  while kind in (0x8100,0x88a8):kind=struct.unpack_from('!H',b,off+2)[0];off+=4
  if kind!=0x800:continue
  ihl=(b[off]&15)*4;length=struct.unpack_from('!H',b,off+2)[0];flags=struct.unpack_from('!H',b,off+6)[0];assert off+length<=len(b);proto=b[off+9]
  if proto!=6:continue
  src=b[off+12:off+16];dst=b[off+16:off+20];part=b[off+ihl:off+length];fragoff=(flags&8191)*8;more=bool(flags&8192)
  if fragoff or more:
   key=(src,dst,struct.unpack_from('!H',b,off+4)[0]);groups[key].append((fragoff,more,part,idx,float(ts)))
  else:datagrams.append((idx,float(ts),src,dst,part,[{'offset':0,'length':len(part),'index':idx,'time':float(ts)}]))
 for (src,dst,ident),pieces in groups.items():
  pieces.sort();assert pieces[0][0]==0 and sum(not x[1] for x in pieces)==1 and sum(x[0]==0 for x in pieces)==1;out=bytearray()
  for at,more,buf,idx,ts in pieces:
   assert at<=len(out);overlap=min(len(out)-at,len(buf));assert out[at:at+overlap]==buf[:overlap];out.extend(buf[overlap:])
  last=next(x for x in pieces if not x[1]);assert len(out)==last[0]+len(last[2]);first=min(pieces,key=lambda x:x[3]);datagrams.append((first[3],first[4],src,dst,bytes(out),[{'offset':a,'length':len(buf),'index':idx,'time':ts} for a,more,buf,idx,ts in pieces]))
 flows=[];keys={}
 for idx,ts,src,dst,payload,parts in sorted(datagrams):
  t=dpkt.tcp.TCP(payload)
  if 3724 not in [t.sport,t.dport]:continue
  a=(src,t.sport);b=(dst,t.dport);key=tuple(sorted([a,b]));syn=bool(t.flags&2 and not t.flags&16)
  if key not in keys:
   f={'id':f'F{len(flows)+1:02d}','key':key,'client':None,'synseq':None,'events':[]};keys[key]=f;flows.append(f)
  f=keys[key]
  if syn:
   if f['client'] is not None:assert f['client']==a and f['synseq']==t.seq
   f['client']=a;f['synseq']=t.seq
  th=(payload[12]>>4)*4;arrivals=[]
  for part in parts:
   lo=max(th,part['offset']);hi=min(len(payload),part['offset']+part['length'])
   if lo<hi:arrivals.append({'data_offset':lo-th,'length':hi-lo,'index':part['index'],'time':part['time']})
  assert sum(x['length'] for x in arrivals)==len(t.data)
  f['events'].append({'index':idx,'time':ts,'src':a,'dst':b,'seq':t.seq,'flags':t.flags,'payload':bytes(t.data),'arrivals':arrivals})
 assert len(flows)==base['tcp3724']['flow_count']
 streams=[]
 for f,prior in zip(flows,base['tcp3724']['flows']):
  assert f['id']==prior['id'] and len(f['events'])==prior['tcp_segment_count'];a=f['client'] or f['key'][0];b=f['key'][1] if a==f['key'][0] else f['key'][0]
  for endpoint,label in [(a,'client_to_server' if f['client'] else 'A_to_B'),(b,'server_to_client' if f['client'] else 'B_to_A')]:
   events=[x for x in f['events'] if x['src']==endpoint];data=[x for x in events if x['payload']];syns=[x for x in events if x['flags']&2];origin=((syns[0]['seq']+1)&0xffffffff) if syns else data[0]['seq'];positions={};spans=[]
   for e in data:
    seq=(e['seq']+bool(e['flags']&2))&0xffffffff;at=((seq-origin+2**31)%2**32)-2**31;spans.extend({'offset':at+x['data_offset'],'length':x['length'],'first_frame_index':x['index'],'time':x['time']} for x in e['arrivals'])
    for k,v in enumerate(e['payload'],at):
     if k in positions:assert positions[k]==v
     positions[k]=v
   assert positions;lo,hi=min(positions),max(positions)+1;assert len(positions)==hi-lo;buf=bytes(positions[x] for x in range(lo,hi));pd=next(x for x in prior['directions'] if x['direction']==label);assert len(pd['contiguous_runs'])==1;pr=pd['contiguous_runs'][0];assert lo==pr['offset'] and len(buf)==pr['length'] and sha(buf)==pr['sha256']
   # Private buffers remain in memory/work; caller publishes structural facts only.
   streams.append({'flow':f['id'],'direction':label,'data':buf,'spans':spans,'offset':lo,'has_syn':bool(syns)})
 return streams
if __name__=='__main__':
 (D/'work').mkdir(exist_ok=True);summary=[]
 for s in rebuild():
  if not s['has_syn']:continue
  b=s['data'];end=b.find(b'\n');assert 0<=end<80;banner=b[:end+1].decode('ascii');(D/'work'/f"{s['flow']}.{s['direction']}.bin").write_bytes(b)
  n=end+1;summary.append({'flow':s['flow'],'direction':s['direction'],'banner':banner,'banner_length':n,'stream_length':len(b),'following_first_u32_le':struct.unpack_from('<I',b,n)[0] if n+4<=len(b) else None,'following_12_bytes_zero':b[n+4:n+16]==bytes(12),'following_u32_at_16':hex(struct.unpack_from('<I',b,n+16)[0]) if n+20<=len(b) else None})
 (D/'reports/stream-prefixes.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
