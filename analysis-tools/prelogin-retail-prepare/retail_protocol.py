"""One Retail preparation request, no finalization/login or game-content transfer."""
import http.client,json,re,urllib.request,hashlib
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]/'agent-interface-lab'))
import probe
PRODUCT='wow'
FIELDS={'authentication','game_dir','min_spec','language','eula','finalized','shortcut','tome_path'}
BLOCKERS={'authentication_error','minimum_spec_error','game_dir_error','eula_review_pending','eula_error','tome_path_error','language_error','agent_error','schema_invalid','unknown_fields'}
CODES={'authentication':'authentication_error','min_spec':'minimum_spec_error','game_dir':'game_dir_error','eula':'eula_error','tome_path':'tome_path_error','language':'language_error'}
def empty_summary(data):
 return type(data) is dict and (not data or (set(data)=={'error'} and type(data['error']) is int and data['error']==0))

def initialized_payload():
 return dict(instructions_dataset=['torrent','win',PRODUCT,'enUS'],instructions_patch_url='http://eu.patch.battle.net:1119/'+PRODUCT,instructions_product='NGDP',monitor_pid=0,priority={'insert_at_head':True,'value':900},uid=PRODUCT)
def code(value):
 if type(value) is not int or not 0<=value<=2**32:raise ValueError('numeric_code')
 return value

def summarize(data):
 result=dict(form_fields=[],unknown_fields=False,form_schema_valid=False,error_codes={k:None for k in ('agent',*CODES)},blockers=[])
 blockers=set();form=data.get('form')
 try:
  result['error_codes']['agent']=code(data.get('error',0))
  if result['error_codes']['agent']:blockers.add('agent_error')
 except ValueError:blockers.add('schema_invalid')
 if type(form) is not dict or len(form)>32:
  result['blockers']=sorted(blockers|{'schema_invalid'});return result
 result['form_fields']=sorted(set(form)&FIELDS);result['unknown_fields']=bool(set(form)-FIELDS)
 if result['unknown_fields']:blockers.add('unknown_fields')
 for name,blocker in CODES.items():
  if name not in form and name not in {'authentication','min_spec','game_dir'}:continue
  p=form.get(name)
  try:
   if type(p) is not dict or 'error' not in p:raise ValueError('schema')
   c=code(p['error']);result['error_codes'][name]=c
   if c:blockers.add(blocker)
  except ValueError:blockers.add('schema_invalid')
 if 'eula' in form:
  blockers.add('eula_review_pending')
  if type(form['eula']) is not dict or type(form['eula'].get('eula')) is not bool:blockers.add('schema_invalid')
 if 'finalized' in form and type(form['finalized']) is not bool:blockers.add('schema_invalid')
 if 'shortcut' in form and (type(form['shortcut']) is not str or len(form['shortcut'])>2048):blockers.add('schema_invalid')
 result['form_schema_valid']='schema_invalid' not in blockers and 'unknown_fields' not in blockers
 result['blockers']=sorted(blockers);return result

class Session:
 def __init__(self,port,token,verify,r,factory=http.client.HTTPConnection):
  if type(port) is not int or not 1<=port<=65535 or type(token) is not str or re.fullmatch('[!-~]{1,8192}',token) is None:raise ValueError('session')
  self.port=port;self.token=token;self.verify=verify;self.r=r;self.factory=factory;self.summary_done=False;self.init_done=False
 def request(self,method,path):
  if (method,path) not in [('GET','/game'),('POST','/install')]:raise ValueError('request_scope')
  if self.r['local_requests']>=2:raise ValueError('request_count')
  if method=='GET':
   if self.summary_done or self.init_done:raise ValueError('summary_once')
   self.summary_done=True
  else:
   if self.init_done or not self.summary_done or not self.r['initial_summary_empty']:raise ValueError('initialization_once')
   self.init_done=True
  if self.verify() is not True:raise ValueError('identity')
  self.r['local_requests']+=1
  if method=='POST':self.r['initialization_attempted']=True
  payload=initialized_payload() if method=='POST' else None
  body=None if payload is None else json.dumps(payload,separators=(',',':')).encode('ascii')
  headers={'Authorization':self.token,'User-Agent':'phoenix-agent/1.0','Accept':'application/json','Accept-Encoding':'identity','Connection':'close'}
  if body is not None:headers['Content-Type']='application/json'
  conn=self.factory('127.0.0.1',self.port,timeout=10)
  try:
   conn.request(method,path,body=body,headers=headers);response=conn.getresponse();self.r['last_http_status']=response.status
   if method=='POST':self.r['initialization_http_status']=response.status
   if response.status not in ((200,201) if method=='POST' else (200,)):raise ValueError('http_status')
   if response.getheader('Content-Encoding','identity').lower() not in ('','identity'):raise ValueError('encoding')
   n=response.getheader('Content-Length')
   if n is not None and (re.fullmatch('[0-9]{1,10}',n) is None or int(n)>65536):raise ValueError('length')
   raw=response.read(65537)
   if len(raw)>65536 or (n is not None and len(raw)!=int(n)):raise ValueError('body_limit')
   if method=='POST':self.r['initialization_response_bytes']=len(raw)
   data=probe.unique_json(raw)
   if self.verify() is not True:raise ValueError('identity')
   return data
  finally:conn.close()

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):return None

def versions(raw):
 if len(raw)>1024**2:raise ValueError('metadata_limit')
 lines=[x for x in raw.decode('utf-8-sig').splitlines() if x and not x.startswith('#')]
 if not lines or len(lines)>128:raise ValueError('metadata_rows')
 header=[x.split('!')[0] for x in lines[0].split('|')]
 if len(set(header))!=len(header):raise ValueError('metadata_headers')
 rows=[]
 for line in lines[1:]:
  values=line.split('|')
  if len(values)!=len(header):raise ValueError('metadata_fields')
  d=dict(zip(header,values))
  if d.get('Region')=='eu':rows.append(d)
 if len(rows)!=1:raise ValueError('metadata_region')
 d=rows[0];v=d.get('VersionsName');b=d.get('BuildConfig')
 if type(v) is not str or re.fullmatch(r'\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,10}',v) is None or type(b) is not str or re.fullmatch('[0-9a-f]{32}',b) is None:raise ValueError('metadata_identity')
 return dict(version=v,build_config=b,versions_sha256=hashlib.sha256(raw).hexdigest(),response_bytes=len(raw))

def discover():
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 req=urllib.request.Request('https://eu.version.battle.net/v2/products/wow/versions',headers={'User-Agent':'AgentLab/0.1','Accept-Encoding':'identity'})
 with opener.open(req,timeout=15) as response:
  if response.status!=200 or response.headers.get('Content-Encoding','identity').lower() not in ('','identity'):raise ValueError('metadata_http')
  raw=response.read(1024**2+1)
 return versions(raw)
