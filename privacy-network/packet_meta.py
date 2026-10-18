"""Bounded pcapng metadata parser; no URLs, headers, bodies or TLS secrets exported.
Partial parser, not Wireshark: Ethernet/raw IP, nonfragmented IPv4/IPv6,
UDP DNS and initial contiguous outbound TCP prefix only.
"""
import collections
import ipaddress
import re
import struct

MAX_PREFIX=65536

def host(raw):
 try:s=raw.decode('ascii').lower().rstrip('.') if isinstance(raw,bytes) else raw.lower().rstrip('.')
 except (UnicodeError,AttributeError):return None
 if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?',s) or '.' not in s:return None
 labels=s.split('.')
 if any(not x or len(x)>63 or x.startswith('-') or x.endswith('-') for x in labels):return None
 # Avoid exporting plausible IDs/tokens encoded as individual DNS labels.
 return '.'.join('redacted' if re.fullmatch(r'(?:[0-9a-f]{16,}|[0-9]{8,}|[0-9a-f]{8}-[0-9a-f-]{27,})',x) else x for x in labels)

def packets(path,stats):
 endian='<';links=[]
 with path.open('rb') as f:
  while True:
   h=f.read(8)
   if not h:return
   if len(h)!=8:raise ValueError('pcapng_header')
   if h[:4]==b'\x0a\x0d\x0d\x0a':
    bom=f.read(4)
    if bom==b'\x4d\x3c\x2b\x1a':endian='<'
    elif bom==b'\x1a\x2b\x3c\x4d':endian='>'
    else:raise ValueError('pcapng_bom')
    size=struct.unpack(endian+'I',h[4:])[0]
    if not 28<=size<=1024*1024:raise ValueError('pcapng_section_size')
    b=bom+f.read(size-12);kind=0x0a0d0d0a;links=[]
   else:
    kind,size=struct.unpack(endian+'II',h)
    if not 12<=size<=1024*1024 or size%4:raise ValueError('pcapng_block_size')
    b=f.read(size-8)
   if len(b)!=size-8 or struct.unpack(endian+'I',b[-4:])[0]!=size:raise ValueError('pcapng_block_bounds')
   if kind==1:
    if len(b)<12:raise ValueError('pcapng_interface')
    links.append(struct.unpack_from(endian+'H',b)[0])
   elif kind==6:
    if len(b)<24:raise ValueError('pcapng_packet')
    interface,_,_,cap,orig=struct.unpack_from(endian+'IIIII',b)
    if interface>=len(links) or cap>len(b)-24:raise ValueError('pcapng_capture_bounds')
    stats['packets']+=1
    if cap<orig:stats['truncated_packets']+=1
    yield links[interface],b[20:20+cap]
   elif kind not in (0x0a0d0d0a,4,5):stats['unparsed_block_types']+=1

def network(link,p):
 if link==1:
  if len(p)<14:return None
  typ=int.from_bytes(p[12:14],'big');p=p[14:]
  for _ in range(2):
   if typ in (0x8100,0x88a8) and len(p)>=4:typ=int.from_bytes(p[2:4],'big');p=p[4:]
  if typ not in (0x0800,0x86dd):return None
 elif link not in (101,228,229):return None
 if not p:return None
 v=p[0]>>4
 if v==4:
  if len(p)<20:return None
  off=(p[0]&15)*4;total=int.from_bytes(p[2:4],'big')
  if off<20 or off>len(p) or int.from_bytes(p[6:8],'big')&0x3fff:return None
  return str(ipaddress.ip_address(p[12:16])),str(ipaddress.ip_address(p[16:20])),p[9],p[off:min(total,len(p))]
 if v==6 and len(p)>=40 and p[6] in (6,17):
  total=40+int.from_bytes(p[4:6],'big')
  return str(ipaddress.ip_address(p[8:24])),str(ipaddress.ip_address(p[24:40])),p[6],p[40:min(total,len(p))]
 return None

def dns_name(b,pos):
 labels=[];end=None;seen=set()
 for _ in range(128):
  if pos>=len(b) or pos in seen:raise ValueError('dns_name_bounds')
  seen.add(pos);n=b[pos];pos+=1
  if n==0:return host(b'.'.join(labels)),end if end is not None else pos
  if n&0xc0==0xc0:
   if pos>=len(b):raise ValueError('dns_pointer')
   if end is None:end=pos+1
   pos=((n&63)<<8)|b[pos];continue
  if n>63 or pos+n>len(b):raise ValueError('dns_label')
  labels.append(b[pos:pos+n]);pos+=n
 raise ValueError('dns_depth')

def dns_answers(b):
 if len(b)<12:return []
 _,flags,qd,an,ns,ar=struct.unpack_from('!HHHHHH',b)
 if not flags&0x8000 or qd>16 or an+ns+ar>512:return []
 pos=12;questions=[];records=[]
 for _ in range(qd):
  name,pos=dns_name(b,pos);questions.append(name);pos+=4
 for _ in range(an+ns+ar):
  name,pos=dns_name(b,pos)
  if pos+10>len(b):raise ValueError('dns_rr')
  typ,cls,ttl,size=struct.unpack_from('!HHIH',b,pos);pos+=10
  if pos+size>len(b):raise ValueError('dns_rdata')
  if cls==1 and ((typ==1 and size==4) or (typ==28 and size==16)):
   ip=str(ipaddress.ip_address(b[pos:pos+size]))
   if ipaddress.ip_address(ip).is_global:
    for h in [name,*questions]:
     if h:records.append((h,ip))
  pos+=size
 return records

def client_hello_sni(data):
 handshake=b'';pos=0
 while pos+5<=len(data):
  typ=data[pos];n=int.from_bytes(data[pos+3:pos+5],'big')
  if n>18432 or pos+5+n>len(data):break
  if typ!=22:break
  handshake+=data[pos+5:pos+5+n];pos+=5+n
 if len(handshake)<4 or handshake[0]!=1:return None
 n=int.from_bytes(handshake[1:4],'big')
 if n>65532 or len(handshake)<n+4:return None
 b=handshake[4:n+4]
 if len(b)<35:return None
 p=34;sid=b[p];p+=1+sid
 if p+2>len(b):return None
 n=int.from_bytes(b[p:p+2],'big');p+=2+n
 if p>=len(b):return None
 p+=1+b[p]
 if p+2>len(b):return None
 end=p+2+int.from_bytes(b[p:p+2],'big');p+=2
 if end>len(b):return None
 while p+4<=end:
  typ=int.from_bytes(b[p:p+2],'big');size=int.from_bytes(b[p+2:p+4],'big');p+=4
  if p+size>end:return None
  if typ==0:
   ext=b[p:p+size]
   if len(ext)<5 or int.from_bytes(ext[:2],'big')!=len(ext)-2:return None
   q=2
   while q+3<=len(ext):
    kind=ext[q];l=int.from_bytes(ext[q+1:q+3],'big');q+=3
    if q+l>len(ext):return None
    if kind==0:return host(ext[q:q+l])
    q+=l
  p+=size
 return None

def prefix_metadata(b):
 out={'tls_sni':None,'http_host':None,'http_method':None}
 if b[:1]==b'\x16':out['tls_sni']=client_hello_sni(b)
 if b'\r\n\r\n' in b:
  headers=b.split(b'\r\n\r\n',1)[0].split(b'\r\n')
  method=headers[0].split(b' ',1)[0]
  if method in (b'GET',b'POST',b'HEAD',b'PUT',b'OPTIONS',b'CONNECT',b'DELETE',b'PATCH'):
   out['http_method']=method.decode()
   hosts=[line.split(b':',1)[1].strip() for line in headers[1:] if line.lower().startswith(b'host:')]
   if len(hosts)==1:out['http_host']=host(hosts[0].split(b':',1)[0])
 return out

class Prefix:
 def __init__(self):self.seq=None;self.data=bytearray();self.gap=False;self.limit=False
 def add(self,seq,payload,syn=False):
  if not payload:return
  if syn:seq=(seq+1)&0xffffffff
  if self.seq is None:self.seq=seq
  offset=(seq-self.seq)&0xffffffff
  if offset>=2**31:return # earlier/retransmitted prefix unavailable
  if offset>len(self.data):self.gap=True;return
  new=payload[max(0,len(self.data)-offset):]
  room=MAX_PREFIX-len(self.data)
  if len(new)>room:self.limit=True
  self.data.extend(new[:room])

def analyze(path,watched):
 stats=collections.Counter();prefixes={};counts=collections.Counter();dns=set();global_prefix=0
 for link,p in packets(path,stats):
  n=network(link,p)
  if n is None:stats['unsupported_or_non_ip_packets']+=1;continue
  src,dst,proto,b=n
  if proto==17 and len(b)>=8:
   sport,dport,length=struct.unpack_from('!HHH',b)
   if sport==53:
    try:
     for pair in dns_answers(b[8:min(length,len(b))]):
      if len(dns)<4096:dns.add(pair)
      else:stats['dns_pair_limit_hit']=1
    except ValueError:stats['dns_parse_errors']+=1
   continue
  if proto!=6 or len(b)<20:continue
  sport,dport,seq=struct.unpack_from('!HHI',b);off=(b[12]>>4)*4
  if off<20 or off>len(b):stats['tcp_parse_errors']+=1;continue
  key=(src,sport,dst,dport)
  if key not in watched:continue
  counts[key]+=1
  payload=b[off:]
  if key not in prefixes:
   if len(prefixes)>=512:stats['flow_limit_hit']=1;continue
   prefixes[key]=Prefix()
  pre=prefixes[key]
  if global_prefix>=16*1024*1024:stats['prefix_memory_limit_hit']=1;continue
  old=len(pre.data);pre.add(seq,payload,bool(b[13]&2));global_prefix+=len(pre.data)-old
 result=[]
 for key,identity in watched.items():
  pre=prefixes.get(key);meta=prefix_metadata(bytes(pre.data)) if pre else {'tls_sni':None,'http_host':None,'http_method':None}
  result.append({'process_name':identity['process_name'],'pid':identity['pid'],'address':key[2],'port':key[3],
   'matched_outbound_packet_observations':counts[key],'prefix_gap':pre.gap if pre else False,'prefix_limit_hit':pre.limit if pre else False,
   'dns_candidates':sorted(h for h,ip in dns if ip==key[2])[:32],**meta})
 return {'packet_stats':dict(stats),'flows':result}
