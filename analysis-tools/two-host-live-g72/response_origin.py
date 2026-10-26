"""Pair identity HTTP/1 responses on each TLS context; redact all dynamic values."""
import re,json,hashlib,base64
from email.parser import BytesParser
from email import policy
from collections import Counter,deque
from schema_attribution import typed_header,products_from_refs,route_info,schemas,public_config_paths
MAX=1024*1024
PRODUCTS=('agent','bna','bnt')
ROUTES={'/summary','/v1/summary','/v2/summary'}|{'/'+p+'/'+k for p in PRODUCTS for k in ('versions','cdns','bgdl','config')}|{'/v'+v+'/products/'+p+'/'+k for v in ('1','2') for p in PRODUCTS for k in ('versions','cdns','bgdl','config')}
FIELDS={'Region','BuildConfig','CDNConfig','KeyRing','BuildId','VersionsName','ProductConfig','Name','Path','Hosts','Servers','ConfigPath','Product','Seqn','Flags','Key','Value','Hash','ContentKey','EncodingKey','CKey','EKey','Version','AgentConfig','KeyName','KeyId','hash','architecture','cdn_product','version','url','path','key','data','encoding','root','install','download','archives'}
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
 if route in ROUTES:return route
 m=re.fullmatch(r'/v([12])/products/(agent|bna|bnt)/blobs/[0-9a-f]{32}',route)
 return '/v'+m[1]+'/products/'+m[2]+'/blobs/<opaque_key>' if m else '<other_route>'

def body_parts(headers,body):
 """Bounded format selection; MIME/BLTE recognition is not signature verification."""
 ct=' '.join(headers.get('content-type',[]))
 if body.startswith(b'BLTE'):
  # Only a chunkless, identity N frame. Other BLTE shapes remain unsupported here.
  if len(body)>=9 and body[4:8]==b'\0\0\0\0' and body[8:9]==b'N':return [('BLTE_chunkless_N',body[9:])]
  return [('BLTE_unsupported',b'')]
 if ct.lower().startswith('multipart/'):
  try:
   msg=BytesParser(policy=policy.default).parsebytes(('MIME-Version: 1.0\r\nContent-Type: '+ct+'\r\n\r\n').encode()+body)
   parts=[]
   for i,part in enumerate(msg.walk()):
    if i>=12:break
    if not part.is_multipart():
     value=part.get_payload(decode=True)
     if isinstance(value,bytes) and len(value)<=MAX:parts.append(('MIME_part',value))
   return parts or [('MIME_unsupported',b'')]
  except Exception:return [('MIME_unsupported',b'')]
 return [('identity',body)]

def locate(token,headers,body):
 out=[]
 for k,vs in headers.items():
  for v in vs:
   if token in v:out.append({'area':'HTTP_header','field':k if k in HEADERS else '<other_header>','match':'exact_value' if v==token else 'quoted_value' if v=='"'+token+'"' else 'substring'})
 for wrapper,payload in body_parts(headers,body):
  if token.encode() not in payload:continue
  before=len(out)
  try:text=payload.decode('utf-8-sig')
  except UnicodeError:
   out.append({'area':'body','field':'<non_UTF8>','match':'ASCII_substring','wrapper':wrapper});continue
  lines=text.splitlines()
  # A signed/preamble wrapper may put the actual table below its first line.
  for n,line in enumerate(lines):
   schema=[c[0] for c in typed_header(line)]
   if not schema:continue
   for row in lines[n+1:]:
    if row.startswith('#'):continue
    cells=row.split('|')
    if len(cells)!=len(schema):break
    for i,v in enumerate(cells):
     if token in v:out.append({'area':'typed_table_cell','field':schema[i] if schema[i] in FIELDS else '<other_column>','column_index':i,'match':'exact_value' if v==token else 'space_delimited_token' if token in v.split() else 'substring','wrapper':wrapper})
  try:j=json.loads(text)
  except (ValueError,RecursionError):j=None
  visited=[0]
  def walk(v,field=None,depth=0,embedded=0):
   visited[0]+=1
   if visited[0]>4096 or depth>20:return
   if isinstance(v,dict):
    for k,x in v.items():walk(x,k,depth+1,embedded)
   elif isinstance(v,list):
    for x in v:walk(x,field,depth+1,embedded)
   elif isinstance(v,str) and token in v:
    if embedded<3 and len(v)<=65536 and v.lstrip().startswith(('{','[')):
     try:inner=json.loads(v)
     except (ValueError,RecursionError):inner=None
     if inner is not None:walk(inner,field,depth+1,embedded+1);return
    out.append({'area':'embedded_JSON_value' if embedded else 'JSON_value','field':field if field in FIELDS else '<other_member>','match':'exact_value' if v==token else 'substring','wrapper':wrapper})
  walk(j)
  if len(out)==before:
   hitlines=[line for line in lines if token in line]
   out.append({'area':'body','field':'<unrecognized_body>','match':'ASCII_substring','wrapper':wrapper,'line_contains_pipe':any('|' in line for line in hitlines),'line_contains_equals':any('=' in line for line in hitlines),'line_contains_colon':any(':' in line for line in hitlines)})
 return out[:32]

def load_pinned_product_refs(base):
 from pathlib import Path
 raw=(Path(base)/'public-reference-fixtures.json').read_bytes()
 if hashlib.sha256(raw).hexdigest()!='372a42ca244cb5b10a73c10a7a94d753e5e0d92b5b47f8b640c031429f809ca7':raise ValueError('public_fixture_pin')
 fixtures=json.loads(raw);out=[]
 for product in ('agent','bna'):
  body=base64.b64decode(fixtures[product+'-product'],validate=True)
  versions=base64.b64decode(fixtures[product+'-versions'],validate=True).decode('utf-8-sig').splitlines();names=[x.split('!')[0] for x in versions[0].split('|')];keys=[]
  for line in versions[1:]:
   cells=line.split('|')
   if len(cells)==len(names) and cells[names.index('Region')]=='us':keys.append(cells[names.index('ProductConfig')])
  if hashlib.md5(body).hexdigest() not in keys:raise ValueError('public_ProductConfig_content_key')
  out.append({'route':'pinned_ProductConfig:'+product,'kind':'pinned_ProductConfig','status':200,'text':body.decode('utf-8'),'headers':{},'public_product':product})
 return out

class ResponseOrigin:
 def __init__(self,reference_rows=()):
  self.refs=[r for r in reference_rows if r.get('status')==200 and (r.get('route') in ROUTES or r.get('kind') in ('pinned_ProductConfig','independent_related_metadata'))];self.public_products=products_from_refs(self.refs);self.public_config_paths=public_config_paths(self.refs);self.buffers={};self.blocked=set();self.queues={};self.docs=[];self.targets={};self.rows=[];self.counts=Counter();self.serial=0;self.total=0;self.retained=0
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
    doc={'event':self.serial,'route':route_info(req['path'],self.public_products)['route'],'query_present':'?' in req['path'],'method':req['method'],'request_path':req['path'],'status':info['status'],'headers':h,'body':body if supported else b'','body_decoding_supported':supported,'schema_diagnostics':schemas(body) if supported else [],'route_diagnostics':route_info(req['path'],self.public_products)}
    self.retained+=len(body)+sum(len(v) for vs in h.values() for v in vs)
    if self.retained>8*MAX:self.reject(key,'retention_cap');return
    self.docs.append(doc);self.counts['paired_responses']+=1
    if not supported:self.counts['unsupported_content_encoding']+=1
    for token,row in self.targets.items():self.match_doc(token,row,doc,False)
  self.buffers[k]=b
 def match_doc(self,token,row,doc,prior):
  locations=locate(token,doc['headers'],doc['body'])
  # If framing wraps an entire independently pinned document, attribute only by
  # exact contained public bytes; never strip arbitrary bytes and call them JSON.
  for ref in self.refs:
   if ref.get('kind')=='pinned_ProductConfig':
    public=ref['text'].encode()
    if token.encode() in public and public in doc['body']:
     for loc in locate(token,{},public):locations.append(dict(loc,area='exact_pinned_public_subdocument_'+loc['area'],public_document=ref['route']))
  if locations and len(row['paired_response_occurrences'])<32:
   exact=[]
   for wrapper,payload in body_parts(doc['headers'],doc['body']):
    for ref in self.refs:
     if ref.get('kind')=='pinned_ProductConfig' and payload==ref['text'].encode():
      exact.append({'public_document':ref['route'],'decoded_body_byte_exact':True,'source_request_key_matches_public_ProductConfig_MD5':doc['request_path'].partition('?')[0].endswith('/'+hashlib.md5(payload).hexdigest()),'wrapper':wrapper})
   for ref in self.refs:
    if ref.get('kind')=='pinned_ProductConfig' and ref['text'].encode() in doc['body']:
     exact.append({'public_document':ref['route'],'entire_pinned_document_contained':True,'source_request_key_matches_public_ProductConfig_MD5':doc['request_path'].partition('?')[0].endswith('/'+hashlib.md5(ref['text'].encode()).hexdigest())})
   row['paired_response_occurrences'].append({k:doc[k] for k in ('event','route','query_present','method','status','body_decoding_supported','schema_diagnostics','route_diagnostics')}|{'preceded_target_observation':prior,'locations':locations,'pairing_basis':'FIFO_on_same_observed_TLS_context','pinned_public_body_equalities':exact})
 def target(self,token,path):
  if token in self.targets:return
  if len(self.rows)>=16:self.counts['target_cap']+=1;return
  row={'target_index':len(self.rows)+1,'path_family':path.split('/')[3] if path.split('/')[3] in ('config','data','patch') else '<other>','paired_response_occurrences':[],'independent_reference_occurrences':[],'raw_values_exported':False,'causal_derivation_proven':False,'whole_CDN_path_independently_public':bool(self.public_config_paths.get(path)),'independent_configuration_path_references':self.public_config_paths.get(path,[])}
  self.targets[token]=row;self.rows.append(row)
  for doc in self.docs:self.match_doc(token,row,doc,True)
  for ref in self.refs:
   h=ref.get('headers') or {};h={k.lower():[v] if isinstance(v,str) else v for k,v in h.items()}
   loc=locate(token,h,ref.get('text','').encode('utf-8'))
   if loc:row['independent_reference_occurrences'].append({'route':ref['route'],'locations':loc,'fixed_public_request_before_target':True})
 def report(self):return {'targets':self.rows,'counts':dict(self.counts),'buffered_bytes':sum(map(len,self.buffers.values())),'unanswered_observed_requests':sum(map(len,self.queues.values())),'retained_response_bytes':self.retained,'blocked_contexts':len(self.blocked),'independent_successful_reference_documents':len(self.refs),'independent_reference_routes':len({r['route'] for r in self.refs}),'independently_derived_configuration_paths':len(self.public_config_paths),'raw_values_exported':False,'coverage_complete':False,'meaning':'paired location and independent equality, never causal derivation or privacy clearance'}
