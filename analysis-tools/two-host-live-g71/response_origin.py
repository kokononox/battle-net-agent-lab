"""Pair identity HTTP/1 responses on each TLS context; redact all dynamic values."""
import re,json
from collections import Counter,deque
MAX=1024*1024
PRODUCTS=('agent','bna','bnt')
ROUTES={'/summary','/v1/summary','/v2/summary'}|{'/'+p+'/'+k for p in PRODUCTS for k in ('versions','cdns','bgdl','config')}|{'/v'+v+'/products/'+p+'/'+k for v in ('1','2') for p in PRODUCTS for k in ('versions','cdns','bgdl','config')}
FIELDS={'Region','BuildConfig','CDNConfig','KeyRing','BuildId','VersionsName','ProductConfig','Name','Path','Hosts','Servers','ConfigPath','Product','Seqn','Flags','Key','Value','Hash','ContentKey','EncodingKey','CKey','EKey','Version','AgentConfig','KeyName','KeyId'}
HEADERS={'etag','content-md5','content-type','content-length','last-modified','date','location','x-blz-contentkey','x-blz-encodingkey'}
class Reject(Exception):pass

def split_http(buf,request=False):
 """Return None for incomplete; reject ambiguity instead of guessing byte boundaries."""
 cut=buf.find(b'\r\n\r\n')
 if cut<0:
  if len(buf)>65536:raise Reject('header_cap')
  return None
 if cut>65536:raise Reject('header_cap')
 lines=buf[:cut].decode('latin1').split('\r\n');headers={}
 for line in lines[1:]:
  if ':' not in line or line[:1] in ' \t':raise Reject('invalid_header')
  k,v=line.split(':',1)
  if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",k):raise Reject('invalid_header_name')
  headers.setdefault(k.lower(),[]).append(v.strip())
 if request:
  m=re.fullmatch(r'(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS) ([^ ]+) HTTP/1\.[01]',lines[0])
  if not m:raise Reject('bad_request_line')
  info={'method':m[1],'path':m[2]};status=None
 else:
  m=re.fullmatch(r'HTTP/1\.[01] ([0-9]{3})(?: .*)?',lines[0])
  if not m:raise Reject('bad_response_line')
  status=int(m[1]);info={'status':status}
 cl=headers.get('content-length',[]);te=headers.get('transfer-encoding',[])
 if len(cl)>1 or (cl and te) or (te and te!=['chunked']):raise Reject('ambiguous_framing')
 start=cut+4
 if request and te:raise Reject('chunked_request_unsupported')
 if not request and (100<=status<200 or status in (204,304)):body=b'';end=start
 elif cl:
  if not re.fullmatch(r'[0-9]{1,10}',cl[0]) or int(cl[0])>MAX:raise Reject('length_cap')
  end=start+int(cl[0])
  if len(buf)<end:return None
  body=buf[start:end]
 elif te:
  pos=start;parts=[];size=0
  while True:
   e=buf.find(b'\r\n',pos)
   if e<0:return None
   if not re.fullmatch(rb'[0-9a-fA-F]{1,8}',buf[pos:e]):raise Reject('chunk_syntax')
   n=int(buf[pos:e],16);size+=n
   if size>MAX:raise Reject('chunk_cap')
   pos=e+2
   if len(buf)<pos+n+2:return None
   if buf[pos+n:pos+n+2]!=b'\r\n':raise Reject('chunk_boundary')
   if not n:body=b''.join(parts);end=pos+2;break
   parts.append(buf[pos:pos+n]);pos+=n+2
 elif request:body=b'';end=start
 else:raise Reject('close_delimited_unsupported')
 return info,headers,body,end

def route_label(path):
 route=path.partition('?')[0]
 return route if route in ROUTES else '<other_route>'

def locate(token,headers,body):
 """Occurrences are locations, not interpretations of a content key."""
 out=[]
 for k,vs in headers.items():
  for v in vs:
   if token in v:
    out.append({'area':'HTTP_header','field':k if k in HEADERS else '<other_header>','match':'exact_value' if v==token else 'quoted_value' if v=='"'+token+'"' else 'substring'})
 if token.encode() not in body:return out
 try:text=body.decode('utf-8-sig')
 except UnicodeError:
  out.append({'area':'body','field':'<non_UTF8>','match':'ASCII_substring'});return out
 lines=[x for x in text.splitlines() if x and not x.startswith('#')]
 schema=[]
 if lines:
  for c in lines[0].split('|'):
   m=re.fullmatch(r'([A-Za-z][A-Za-z0-9_]{0,63})!(STRING|HEX|DEC):[0-9]{1,3}',c)
   if not m:schema=[];break
   schema.append(m[1])
 if schema:
  for row in lines[1:]:
   cells=row.split('|')
   if len(cells)!=len(schema):continue
   for i,v in enumerate(cells):
    if token in v:out.append({'area':'typed_table_cell','field':schema[i] if schema[i] in FIELDS else '<other_column>','column_index':i,'match':'exact_value' if v==token else 'space_delimited_token' if token in v.split() else 'substring'})
 if not any(x['area'] in ('typed_table_cell',) for x in out):
  # Fixed allowlisted JSON member names only. Arbitrary keys and values stay private.
  try:j=json.loads(text)
  except (ValueError,RecursionError):j=None
  def walk(v,field=None,depth=0):
   if depth>8:return
   if isinstance(v,dict):
    for k,x in list(v.items())[:128]:walk(x,k,depth+1)
   elif isinstance(v,list):
    for x in v[:128]:walk(x,field,depth+1)
   elif isinstance(v,str) and token in v:out.append({'area':'JSON_value','field':field if field in FIELDS else '<other_member>','match':'exact_value' if v==token else 'substring'})
  walk(j)
 if not any(x['area'] in ('typed_table_cell','JSON_value') for x in out):out.append({'area':'body','field':'<unrecognized_body>','match':'ASCII_substring'})
 return out[:32]

class ResponseOrigin:
 def __init__(self,reference_rows=()):
  self.refs=[r for r in reference_rows if r.get('status')==200 and r.get('route') in ROUTES];self.buffers={};self.blocked=set();self.queues={};self.docs=[];self.targets={};self.rows=[];self.counts=Counter();self.serial=0;self.total=0;self.retained=0
 def reject(self,key,why):self.counts[why]+=1;self.blocked.add(key);self.buffers.pop((key,'out'),None);self.buffers.pop((key,'in'),None);self.queues.pop(key,None)
 def feed(self,key,direction,data):
  if key in self.blocked:return
  self.total+=len(data)
  if self.total>16*MAX:self.reject(key,'input_cap');return
  k=(key,direction);b=self.buffers.get(k,b'')+bytes(data)
  if len(b)>MAX+65536:self.reject(key,'stream_cap');return
  while b:
   try:parsed=split_http(b,direction=='out')
   except Reject as e:self.reject(key,str(e));return
   if parsed is None:break
   info,h,body,end=parsed;b=b[end:]
   if direction=='out':
    if info['method']!='GET':self.reject(key,'non_GET_pairing_unsupported');return
    if h.get('host') not in (['us.version.battle.net'],['us.version.battle.net:443'],['localhost']):self.reject(key,'request_host_unknown');return
    q=self.queues.setdefault(key,deque())
    if len(q)>=64:self.reject(key,'queue_cap');return
    q.append(info);self.counts['complete_requests']+=1
   else:
    self.counts['complete_responses']+=1
    if 100<=info['status']<200:
     if info['status']==101:self.reject(key,'protocol_switch');return
     self.counts['informational_responses']+=1;continue
    q=self.queues.get(key,deque());req=q.popleft() if q else None
    if not req:self.reject(key,'response_without_observed_request');return
    self.serial+=1;enc=h.get('content-encoding',['identity']);supported=enc==['identity']
    doc={'event':self.serial,'route':route_label(req['path']),'query_present':'?' in req['path'],'method':req['method'],'status':info['status'],'headers':h,'body':body if supported else b'','body_decoding_supported':supported}
    self.retained+=len(body)+sum(len(v) for vs in h.values() for v in vs)
    if self.retained>8*MAX:self.reject(key,'retention_cap');return
    self.docs.append(doc);self.counts['paired_responses']+=1
    if not supported:self.counts['unsupported_content_encoding']+=1
    for token,row in self.targets.items():self.match_doc(token,row,doc,False)
  self.buffers[k]=b
 def match_doc(self,token,row,doc,prior):
  locations=locate(token,doc['headers'],doc['body'])
  if locations and len(row['paired_response_occurrences'])<32:
   row['paired_response_occurrences'].append({k:doc[k] for k in ('event','route','query_present','method','status','body_decoding_supported')}|{'preceded_target_observation':prior,'locations':locations,'pairing_basis':'FIFO_on_same_observed_TLS_context'})
 def target(self,token,path):
  if token in self.targets:return
  if len(self.rows)>=16:self.counts['target_cap']+=1;return
  row={'target_index':len(self.rows)+1,'path_family':path.split('/')[3] if path.split('/')[3] in ('config','data','patch') else '<other>','paired_response_occurrences':[],'independent_reference_occurrences':[],'raw_values_exported':False,'causal_derivation_proven':False,'whole_CDN_path_independently_public':False}
  self.targets[token]=row;self.rows.append(row)
  for doc in self.docs:self.match_doc(token,row,doc,True)
  for ref in self.refs:
   h=ref.get('headers') or {};h={k.lower():[v] if isinstance(v,str) else v for k,v in h.items()}
   loc=locate(token,h,ref.get('text','').encode('utf-8'))
   if loc:row['independent_reference_occurrences'].append({'route':ref['route'],'locations':loc,'fixed_public_request_before_target':True})
 def report(self):return {'targets':self.rows,'counts':dict(self.counts),'buffered_bytes':sum(map(len,self.buffers.values())),'unanswered_observed_requests':sum(map(len,self.queues.values())),'retained_response_bytes':self.retained,'blocked_contexts':len(self.blocked),'independent_successful_reference_documents':len(self.refs),'raw_values_exported':False,'coverage_complete':False,'meaning':'paired location and independent equality, never causal derivation or privacy clearance'}
