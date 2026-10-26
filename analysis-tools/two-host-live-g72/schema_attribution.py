"""Only known schema labels and independently public product names may be exported."""
import re,json,hashlib
from pathlib import Path
PIN='71a487b4ac5c2aa3f9df71d29469408d8276b37ea97c9a0b988c34225190e052'
KNOWN={'Region','BuildConfig','CDNConfig','KeyRing','BuildId','VersionsName','ProductConfig','Name','Path','Hosts','Servers','ConfigPath','Product','Seqn','Flags','Key','Value','Hash','ContentKey','EncodingKey','CKey','EKey','Version','AgentConfig','KeyName','KeyId'}
OPS={'versions','cdns','bgdl','config','blobs','blob','summary'}
def typed_header(line):
 cols=[]
 for cell in line.split('|'):
  m=re.fullmatch(r'([A-Za-z][A-Za-z0-9_]{0,63})!(STRING|HEX|DEC):([0-9]{1,3})',cell,re.I)
  if not m:return []
  cols.append((m[1],m[2].upper(),int(m[3])))
 return cols if 1<=len(cols)<=64 else []
def table(text):
 lines=text.lstrip('\ufeff').splitlines()
 if not lines:return None
 header=typed_header(lines[0])
 if not header:return None
 rows=[]
 for line in lines[1:]:
  if not line or line.startswith('#'):continue
  cells=line.split('|')
  if len(cells)!=len(header):return None
  for (name,typ,width),value in zip(header,cells):
   if typ=='HEX' and value and (width==0 or not re.fullmatch(r'[0-9a-f]{'+str(width*2)+'}',value)):return None
   if typ=='DEC' and value and (not re.fullmatch(r'[0-9]{1,20}',value) or width not in (1,2,4,8) or int(value)>=2**(width*8)):return None
  rows.append(dict(zip([x[0] for x in header],cells)))
 return header,rows

def products_from_refs(refs):
 names={'agent','bna','bnt'}
 for ref in refs:
  if ref.get('status')!=200 or ref.get('route')!='/v2/summary':continue
  t=table(ref.get('text',''))
  if not t or [c[0] for c in t[0]]!=['Product','Seqn','Flags']:continue
  for row in t[1]:
   p=row['Product']
   if re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,63}',p):names.add(p)
 return names

def load_extra_refs(base):
 raw=(Path(base)/'public-schema-reference.json').read_bytes()
 if hashlib.sha256(raw).hexdigest()!=PIN:raise ValueError('public_schema_reference_pin')
 j=json.loads(raw)
 if j['installer_input_used'] is not False or j['runtime_permission'] is not False:raise ValueError('reference_scope')
 rows=j['rows'];products=products_from_refs(rows)
 for r in rows:
  expected='https://us.version.battle.net'+r['route']
  if r['receipt']['url']!=expected or hashlib.sha256(r['text'].encode()).hexdigest()!=r['receipt']['sha256']:raise ValueError('reference_receipt')
  if r['route']=='/v2/summary':continue
  m=re.fullmatch(r'/v2/products/(agent_beta|agent_redist)/(versions|cdns)',r['route'])
  if not m or m[1] not in products or table(r['text']) is None:raise ValueError('independent_related_schema')
 return rows

def relative_target(path):
 # Parse exact absolute-form only for this HTTPS host. No unquoting/normalization.
 if path.startswith('https://us.version.battle.net/'):
  return path[len('https://us.version.battle.net'):],'absolute_selected_host'
 if path.startswith('/') and not path.startswith('//'):return path,'origin'
 return path,'other'

def route_info(path,products):
 rel,form=relative_target(path);route=rel.partition('?')[0];atoms=route.split('/')[1:]
 m=re.fullmatch(r'/(?:v([12])/products/)?([a-z0-9][a-z0-9_.-]{0,63})/(versions|cdns|bgdl|config)',route)
 label=None
 if m and m[2] in products:label=route
 m2=re.fullmatch(r'/v([12])/products/([a-z0-9][a-z0-9_.-]{0,63})/blobs/([0-9a-f]{32})',route)
 if m2 and m2[2] in products:label='/v'+m2[1]+'/products/'+m2[2]+'/blobs/<opaque_key>'
 if route in ('/summary','/v1/summary','/v2/summary'):label=route
 structure=[]
 for a in atoms[:12]:
  if a in OPS|{'v1','v2','products'}:structure.append({'kind':'fixed_protocol_word','word':a})
  elif a in products:structure.append({'kind':'independently_public_product','product':a})
  elif re.fullmatch(r'[0-9a-f]{32}',a):structure.append({'kind':'opaque_hex32'})
  elif not a:structure.append({'kind':'empty'})
  else:structure.append({'kind':'other','length_class':str(len(a)) if len(a)<=16 else 'longer'})
 return {'route':label or '<other_route>','request_target_form':form,'route_structure':structure,'query_present':'?' in rel}

def schemas(body):
 try:lines=body.decode('utf-8-sig').splitlines()
 except UnicodeError:return []
 out=[]
 for line in lines[:64]:
  header=typed_header(line)
  if not header:continue
  out.append({'columns':[{'field':n if n in KNOWN else '<other_column>','type':t,'width':w if w in (0,1,2,4,8,16,20,32) else 'other'} for n,t,w in header],'typing_rule':'case_insensitive_type_marker'})
  if len(out)>=4:break
 return out

def public_config_paths(refs):
 versions={};cdns={};paths={}
 for r in refs:
  m=re.fullmatch(r'/v2/products/(agent|bna|bnt|agent_beta|agent_redist)/(versions|cdns)',r.get('route',''))
  if not m or r.get('status')!=200:continue
  parsed=table(r.get('text',''))
  if parsed:(versions if m[2]=='versions' else cdns)[m[1]]=parsed[1]
 for product,vs in versions.items():
  for v in vs:
   for c in cdns.get(product,[]):
    if v.get('Region')!=c.get('Name') or 'level3.blizzard.com' not in c.get('Hosts','').split():continue
    for field in ('BuildConfig','CDNConfig','ProductConfig'):
     key=v.get(field,'');prefix=c.get('ConfigPath','') if field=='ProductConfig' else c.get('Path','')+'/config'
     if not re.fullmatch(r'[0-9a-f]{32}',key) or not re.fullmatch(r'[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+){0,7}',prefix):continue
     path='/'+prefix+'/'+key[:2]+'/'+key[2:4]+'/'+key
     rec={'product':product,'version_field':field,'prefix_basis':'ConfigPath' if field=='ProductConfig' else 'Path_plus_config','version_route':'/v2/products/'+product+'/versions','cdn_route':'/v2/products/'+product+'/cdns'}
     if rec not in paths.setdefault(path,[]):paths[path].append(rec)
 return paths
