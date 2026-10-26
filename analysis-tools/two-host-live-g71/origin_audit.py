"""Volatile, bounded evidence of prior byte occurrence. Never claims derivation or privacy."""
import re
from collections import Counter,deque
class OriginAudit:
 def __init__(self,public_paths=(),limit=32*1024*1024):
  self.public=set(public_paths);self.limit=limit;self.sources=deque();self.size=0;self.serial=0;self.counts=Counter();self.targets={};self.buffers={};self.tails={};self.rows=[];self.on_target=None
 def source(self,key,data,kind,frames=()):
  if kind not in ('selected_two_host_recv','selected_two_host_WSARecv_immediate','disk_ReadFile_sync','version_TLS_plaintext','target_InternetReadFile'):return
  data=bytes(data);self.serial+=1;self.counts[kind+'_bytes']+=len(data)
  # Include a 63-byte overlap to find 16/32/64-byte tokens split between consecutive reads.
  prior=self.tails.get((kind,key),b'') if kind in ('selected_two_host_recv','selected_two_host_WSARecv_immediate','version_TLS_plaintext') else b'';joined=prior+data;self.tails[(kind,key)]=joined[-63:]
  if len(self.tails)>512:self.tails.clear();self.counts['tail_key_cap_reset']+=1
  if len(joined)>self.limit:self.counts['oversized_source_dropped']+=1;return
  item=(self.serial,kind,joined,list(frames)[:16]);self.sources.append(item);self.size+=len(joined)
  while self.size>self.limit:
   old=self.sources.popleft();self.size-=len(old[2]);self.counts['evicted_chunks']+=1
  for token,row in self.targets.items():self._match(token,row,item,False)
 def _match(self,token,row,item,prior):
  serial,kind,data,frames=item
  formats=[]
  if token.encode() in data:formats.append('ASCII_lower_hex')
  if token.upper().encode() in data:formats.append('ASCII_upper_hex')
  if token.encode('utf-16le') in data:formats.append('UTF16LE_lower_hex')
  if bytes.fromhex(token) in data:formats.append('binary_16_bytes')
  if formats and len(row['occurrences'])<24 and not any(x['source_event']==serial for x in row['occurrences']):
   row['occurrences'].append({'source_event':serial,'source_kind':kind,'representation':formats,'preceded_request_observation':prior,'frames':frames,'derivation_proven':False})
 def requests(self,key,data,frames=()):
  # Independent HTTP reassembly for trace correlation, not a replacement for semantic Audit.
  b=self.buffers.get(key,b'')+bytes(data)
  if len(b)>1048576:self.counts['request_buffer_limit']+=1;self.buffers.pop(key,None);return
  while b:
   if not re.match(rb'(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS) ',b):
    if len(b)<8:break
    self.counts['non_HTTP_request_bytes']+=len(b);b=b'';break
   end=b.find(b'\r\n\r\n')
   if end<0:break
   lines=b[:end].decode('latin1').split('\r\n');first=lines[0].split(' ');headers={}
   if len(first)!=3:self.counts['bad_request']+=1;b=b'';break
   for line in lines[1:]:
    if ':' in line:
     k,v=line.split(':',1);headers.setdefault(k.lower(),[]).append(v.strip())
   if 'transfer-encoding' in headers or len(headers.get('content-length',[]))>1:self.counts['unsupported_framing']+=1;b=b'';break
   try:n=int(headers.get('content-length',['0'])[0])
   except ValueError:n=-1
   if not 0<=n<=1048576:self.counts['bad_length']+=1;b=b'';break
   if len(b)<end+4+n:break
   method,path,_=first
   m=re.fullmatch(r'/tpr/[A-Za-z0-9_-]+/(?:data|patch|config)/([0-9a-f]{2})/([0-9a-f]{2})/([0-9a-f]{32})(?:\.index)?',path)
   if headers.get('host')==['level3.blizzard.com'] and path not in self.public and m and m[1]==m[3][:2] and m[2]==m[3][2:4]:
    token=m[3]
    if token in self.targets:self.targets[token]['observation_count']+=1
    elif len(self.rows)<16:
     row={'target_index':len(self.rows)+1,'observation_count':1,'method':method if method in ('GET','HEAD') else 'other','request_frames':list(frames)[:16],'occurrences':[],'raw_values_exported':False,'derivation_proven':False,'public_origin_proven':False}
     self.rows.append(row);self.targets[token]=row
     if self.on_target:self.on_target(token,path)
     for item in self.sources:self._match(token,row,item,True)
    else:self.counts['target_cap']+=1
   b=b[end+4+n:]
  self.buffers[key]=b
 def close(self,key):
  self.buffers.pop(key,None)
  for k in list(self.tails):
   if k[1]==key:self.tails.pop(k,None)
 def report(self):
  return {'targets':self.rows,'source_counts':dict(self.counts),'retained_source_bytes':self.size,'retention_limit':self.limit,'raw_values_exported':False,'coverage_complete':False,'meaning':'byte occurrence is not causal derivation; incoming data is not independently public; negative results are bounded by retention and unsupported asynchronous/mapped/decompressed reads'}
