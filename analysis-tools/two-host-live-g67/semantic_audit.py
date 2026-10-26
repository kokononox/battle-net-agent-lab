"""Bounded in-memory request-value review; no raw paths/queries/header values exported."""
import os,re,json,hashlib,base64
from pathlib import Path
from urllib.parse import unquote,parse_qsl
from collections import Counter
from privacy_semantics import ua_structure,ResponseRelation
TARGETS={'level3.blizzard.com','us.version.battle.net'}
WORDS={'tpr','agent','bna','bnt','config','data','patch','versions','cdns','products','v1','v2','version','index','indices','summary'}
PRODUCTS={'agent','bna','bnt'};PLATFORMS={'win','windows','win32','win64','x86','x64','x86_64','amd64','arm64','mac','osx','linux'}
REGIONS={'us','eu','kr','tw','cn','enus','engb','dede','frfr','eses','esmx','ruru','kokr','zhcn','zhtw','itit','ptbr','plpl','jajp'}
KEYS={'p','platform','product','locale','region','channel','version','build','os','arch','agent','nocache','_','t','timestamp','key','hash','id','installid','machineid','deviceid','fingerprint','uid','uuid','client','tag','branch','seqn','since','sequence','lastseqn','last_seqn'}
HARDWARE=re.compile(r'(?i)cpu|gpu|hardware|machine|device|fingerprint|serial|uuid|hostname|computer|username|memory')
HEADERS={'host','accept','accept-encoding','accept-language','range','user-agent','connection','content-length','content-type','cookie','authorization','proxy-authorization','cache-control','pragma'}
ROUTES={'/v'+v+'/products/'+p+'/'+k for v in ('1','2') for p in PRODUCTS for k in ('versions','cdns')}|{'/'+p+'/'+k for p in PRODUCTS for k in ('versions','cdns')}|{'/v1/summary','/v2/summary'}

def variants(value):
 raw=value.strip()
 if len(raw)<4:return []
 result=[('literal',raw.lower())]
 compact=re.sub(r'[^a-zA-Z0-9]','',raw)
 for text in {raw,raw.lower(),compact,compact.lower()}:
  if len(text)<4:continue
  data=text.encode()
  for name in ('md5','sha1','sha256'):result.append((name,hashlib.new(name,data).hexdigest()))
  result.append(('base64',base64.b64encode(data).decode().lower()))
 return result

def local_comparisons():
 result=[]
 for role,key in [('machine_name','COMPUTERNAME'),('user_name','USERNAME')]:
  for transform,v in variants(os.environ.get(key,'')):result.append((role,transform,v))
 try:
  import winreg
  with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Cryptography',0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY) as k:value=winreg.QueryValueEx(k,'MachineGuid')[0]
  for transform,v in variants(value):result.append(('machine_guid',transform,v))
 except (ImportError,OSError):pass
 return result

class Audit:
 def __init__(self,public_tokens=(),identifiers=()):self.buffers={};self.rows=[];self.unparsed=Counter();self.total=0;self.public=set(public_tokens);self.ids=list(identifiers);self.capped=False;self.responses=ResponseRelation(self.public)
 def matches(self,value):
  v=unquote(value).lower();hits=[]
  for role,transform,token in self.ids:
   # Exact value or identifier-bearing boundary match; avoid incidental substring hits.
   if v==token or (transform=='literal' and re.search(r'(?<![a-z0-9])'+re.escape(token)+r'(?![a-z0-9])',v)):hits.append({'identifier_role':role,'comparison':transform})
  return hits[:12]
 def value(self,v):
  decoded=unquote(v);low=decoded.lower();hits=self.matches(v)
  if hits:kind='local_identifier_match'
  elif not decoded:kind='empty'
  elif '@seq:'+decoded in self.public:kind='fixed_public_sequence_exact'
  elif decoded in self.public or low in self.public:kind='fixed_public_reference_token_exact'
  elif low in PLATFORMS:kind='platform_or_architecture_literal'
  elif low in PRODUCTS:kind='product_literal'
  elif low in REGIONS:kind='region_or_locale_literal'
  elif re.fullmatch(r'\d+',decoded):kind='decimal_shape_meaning_unknown'
  elif re.fullmatch(r'[0-9a-fA-F]{16,128}',decoded):kind='opaque_hex_not_proven_content_hash'
  elif re.fullmatch(r'[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',decoded):kind='UUID_shape_unknown_origin'
  else:kind='opaque_or_unclassified'
  return {'class':kind,'local_identifier_matches':hits,'raw_value_exported':False}
 def analyze(self,first,headers,body,stream_key=None):
  method,path,_=first;host=headers.get('host',[''])[0].lower().removesuffix(':80').removesuffix(':443')
  if host not in TARGETS:return None
  route,sep,query=path.partition('?');segments=[x for x in route.split('/') if x];queryrows=[]
  for key,value in parse_qsl(query,keep_blank_values=True,max_num_fields=64):
   keylow=key.lower();q=self.value(value);q.update(key=keylow if keylow in KEYS else '<other>',key_hardware_word_hint=bool(HARDWARE.search(key)));queryrows.append(q)
  for key,value in parse_qsl(query,keep_blank_values=True,max_num_fields=64):
   if key.lower()=='seqn' and host=='us.version.battle.net':self.responses.note_query(stream_key,value,route)
  ua=headers.get('user-agent',[''])[0];ua_low=ua.lower()
  uar={'present':bool(ua),'known_product_words':[x for x in ['blizzard','battle.net','agent','mozilla','curl'] if x in ua_low],'platform_words':[x for x in ['windows','win64','win32','x64','x86','arm64','linux','macintosh'] if re.search(r'\b'+x+r'\b',ua_low)],'version_number_groups':len(re.findall(r'\b\d+(?:\.\d+){1,4}\b',ua)),'local_identifier_matches':self.matches(ua),'hardware_word_hint':bool(HARDWARE.search(ua)),'raw_value_exported':False,'absence_of_encoded_identifiers_proven':False}
  uar['matches_exact_agent_version_only_grammar']=bool(re.fullmatch(r'Agent(?:/| )[0-9]+(?:\.[0-9]+){1,5}',ua))
  versions=re.findall(r'\b[0-9]+(?:\.[0-9]+){1,5}\b',ua)
  uar['all_version_groups_match_fixed_public_reference']=bool(versions) and all(v in self.public for v in versions)
  uar['non_version_text_excluded_by_exact_grammar']=uar['matches_exact_agent_version_only_grammar']
  uar['bounded_structure']=ua_structure(ua,self.public)
  pathclasses=Counter('fixed_download_route_word' if unquote(x).lower() in WORDS else self.value(x)['class'] for x in segments)
  pathhits=self.matches(route);headerhits=[]
  for key,values in headers.items():
   for value in values:
    for hit in self.matches(value):headerhits.append({'header':key if key in HEADERS else '<other>',**hit})
  accept=headers.get('accept',[]);ranges=headers.get('range',[])
  rangevalid=all(re.fullmatch(r'bytes=\d*-\d*(?:,\s*\d*-\d*)*',x) is not None for x in ranges)
  matches=pathhits+headerhits+[h for x in queryrows for h in x['local_identifier_matches']]+self.matches(body.decode('latin1'))
  unknown_segments=sum(n for kind,n in pathclasses.items() if kind not in ('fixed_download_route_word','fixed_public_reference_token_exact','product_literal'))
  # Public-token agreement is evidence of public download selection, not global privacy clearance.
  query_consistent=all(x['class'] in ('fixed_public_reference_token_exact','fixed_public_sequence_exact','product_literal','platform_or_architecture_literal','region_or_locale_literal','empty') for x in queryrows)
  verdict='suspicious_local_identifier_match' if matches else 'consistent_with_download_selection_not_privacy_clearance' if route in ROUTES and query_consistent else 'unknown_requires_more_evidence'
  return {'host':host,'method':method if method in {'GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'} else 'other','route_matches_fixed_public_endpoint':route in ROUTES,'path_segment_classes':dict(pathclasses),'unresolved_path_segments':unknown_segments,'path_local_identifier_matches':pathhits,'query_parameters':queryrows,'user_agent':uar,'header_local_identifier_matches':headerhits,'explicit_credentials_present':any(x in headers for x in ('cookie','authorization','proxy-authorization')),'accept_values_all_generic_download_types':all(x in ('*/*','application/octet-stream','application/json') for x in accept),'range_present':bool(ranges),'range_syntax_valid':rangevalid,'body_bytes':len(body),'body_local_identifier_match':bool(self.matches(body.decode('latin1'))),'verdict':verdict,'fingerprinting_absence_proven':False,'raw_path_query_header_values_exported':False}
 def feed(self,key,data):
  self.total+=len(data)
  if self.total>16777216 or len(self.rows)>=1000:self.capped=True;return
  buf=self.buffers.get(key,b'')+data
  if len(buf)>1048576:self.unparsed['stream_limit']+=1;self.buffers[key]=b'';return
  while buf:
   if not re.match(rb'(GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS) ',buf):
    if len(buf)<8:break
    self.unparsed['non_HTTP1_or_midstream_bytes']+=len(buf);buf=b'';break
   cut=buf.find(b'\r\n\r\n')
   if cut<0:break
   lines=buf[:cut].decode('latin1').split('\r\n');first=lines[0].split(' ');headers={};bad=False
   if len(first)!=3 or first[2] not in ('HTTP/1.0','HTTP/1.1'):self.unparsed['invalid_request_line']+=1;buf=b'';break
   for line in lines[1:]:
    if ':' not in line:bad=True;break
    k,v=line.split(':',1);headers.setdefault(k.lower(),[]).append(v.strip())
   if bad or len(headers.get('host',[]))!=1 or 'transfer-encoding' in headers or len(headers.get('content-length',[]))>1:self.unparsed['ambiguous_or_unsupported_headers']+=1;buf=b'';break
   try:n=int(headers.get('content-length',['0'])[0])
   except ValueError:n=-1
   if not 0<=n<=1048576:self.unparsed['bad_body_length']+=1;buf=b'';break
   end=cut+4+n
   if len(buf)<end:break
   try:row=self.analyze(first,headers,buf[cut+4:end],key)
   except ValueError:self.unparsed['query_parse_limit_or_error']+=1;row=None
   if row is not None:self.rows.append(row)
   buf=buf[end:]
  self.buffers[key]=buf
 def report(self):return {'rows':self.rows,'unparsed':dict(self.unparsed),'buffered_bytes':sum(len(x) for x in self.buffers.values()),'cap_hit':self.capped,'fingerprinting_absence_proven':False,'query_response_relation':self.responses.report(),'comparison_scope':'machine_name_user_name_MachineGuid_literal_and_common_unsalted_encodings_only','local_identifier_roles_available':sorted({x[0] for x in self.ids}),'raw_values_exported':False}

def load_public(root):
 path=root/'public-reference.PRIVATE.json';tokens=set();summary=[]
 if not path.is_file():return tokens,{'available':False,'rows':[]}
 raw=json.loads(path.read_text(encoding='utf-8-sig'))
 for row in raw['rows']:
  text=row['text'];valid=row['status']==200 and ('!STRING:' in text or '!HEX:' in text or '!DEC:' in text)
  if valid:
   seqs=re.findall(r'(?im)^\s*#{0,2}\s*seqn\s*=\s*([0-9]+)\s*$',text)
   if row['route']=='/v2/summary':
    for n in seqs:tokens.add('@summaryseq:'+n)
   if row['route']=='/v2/summary' and 'Product!STRING:0|Seqn!DEC:4|Flags!STRING:0' in text:
    seqs+=re.findall(r'(?m)^[^|\r\n]+\|([0-9]+)\|[^\r\n]*$',text)
   for n in seqs:tokens.add('@seq:'+n)
   for token in re.findall(r'\b[a-fA-F0-9]{16,128}\b|\b\d+(?:\.\d+){1,4}\b',text):tokens.add(token);tokens.add(token.lower())
  summary.append({'fixed_route':row['route'],'status':row['status'],'recognized_table_header':valid,'raw_body_exported':False})
 return tokens,{'available':True,'rows':summary,'distinct_reference_tokens':len(tokens),'reference_is_fixed_public_request_not_installer_reflection':True}
