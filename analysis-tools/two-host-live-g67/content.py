"""Bounded HTTP/1 request classification. No raw paths, values or bodies exported."""
import re
from collections import Counter
TARGETS=('level3.blizzard.com','us.version.battle.net')
HINTS=re.compile(r'cpu|gpu|hardware|machine|device|fingerprint|serial|uuid|hostname|computer|username|memory',re.I)
class Inspector:
 def __init__(self):self.buffers={};self.rows=[];self.unknown=Counter();self.total=0;self.capped=False
 def feed(self,key,data):
  self.total+=len(data)
  if self.total>16*1024*1024 or len(self.rows)>=1000:self.capped=True;return
  buf=self.buffers.get(key,b'')+data
  if len(buf)>1024*1024:self.unknown['stream_buffer_limit']+=1;self.buffers[key]=b'';return
  while buf:
   if not re.match(rb'(GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS) ',buf):
    # Partial method prefix may be continued by the next accepted write.
    if len(buf)<8:break
    self.unknown['tls_or_non_http1_or_midstream_bytes']+=len(buf);buf=b'';break
   cut=buf.find(b'\r\n\r\n')
   if cut<0:break
   head=buf[:cut].decode('latin1');lines=head.split('\r\n')
   first=lines[0].split(' ')
   if len(first)!=3 or first[2] not in ('HTTP/1.0','HTTP/1.1'):
    self.unknown['bad_request_line']+=1;buf=b'';break
   headers={};invalid=False
   for line in lines[1:]:
    if ':' not in line:invalid=True;break
    k,v=line.split(':',1);k=k.lower();headers.setdefault(k,[]).append(v.strip())
   if invalid or len(headers.get('host',[]))!=1:
    self.unknown['invalid_or_ambiguous_headers']+=1;buf=b'';break
   if 'transfer-encoding' in headers or len(headers.get('content-length',[]))>1:
    self.unknown['unsupported_or_ambiguous_framing']+=1;buf=b'';break
   try:n=int(headers.get('content-length',['0'])[0])
   except ValueError:n=-1
   if not 0<=n<=1024*1024:self.unknown['invalid_or_large_length']+=1;buf=b'';break
   end=cut+4+n
   if len(buf)<end:break
   host=headers['host'][0].lower();host=host[:-3] if host.endswith(':80') else host
   method,path,_=first;query=path.split('?',1)[1] if '?' in path else ''
   keys=[p.split('=',1)[0] for p in query.split('&') if p]
   body=buf[cut+4:end]
   if host in TARGETS:
    self.rows.append({'host':host,'method':method,'path_class':'tpr' if path.startswith('/tpr/') else 'version_product' if re.match(r'^/(v[12]/products/)?(agent|bna|bnt)/',path) else 'other',
     'query_present':bool(query),'query_key_count':len(keys),'body_bytes':len(body),
     'header_names':sorted({k if k in {'host','accept','accept-encoding','accept-language','range','user-agent','connection','content-length','content-type','cookie','authorization','proxy-authorization','cache-control','pragma'} else '<other>' for k in headers}),'credential_header_present':bool({'cookie','authorization','proxy-authorization'}&headers.keys()),
     'hardware_field_name_hint':bool(HINTS.search(' '.join(headers)+ ' '+ ' '.join(keys))) or bool(re.search(rb'(?i)(cpu|gpu|hardware|machine|device|fingerprint|serial|uuid|hostname)\s*["\x27]?\s*[:=]',body)),
     'identifier_absence_proven':False})
   else:self.unknown['non_target_http_host']+=1
   buf=buf[end:]
  self.buffers[key]=buf
 def report(self):
  return {'requests':self.rows,'unparsed':dict(self.unknown),'buffered_unparsed_bytes':sum(map(len,self.buffers.values())),
   'api_input_bytes_seen':self.total,'cap_hit':self.capped,'fingerprinting_absence_proven':False,
   'raw_values_exported':False,'request_grain':'synchronous_Winsock_accepted_input_not_independent_wire_or_server_receipt'}
