"""One-shot, metadata-only official Classic Era preflight. No Agent or game writer."""
import datetime, hashlib, http.client, json, pathlib, re, signal, socket, time, urllib.parse
ROOT=pathlib.Path(__file__).resolve().parent
CAP=64*1024**2
class Stop(Exception):pass
class Client:
 def __init__(self):self.started=time.monotonic();self.used=0;self.receipts=[]
 def fetch(self,url,cap,expected=None):
  if time.monotonic()-self.started>=600:raise Stop('deadline')
  p=urllib.parse.urlsplit(url)
  if p.scheme!='https' or p.username or p.password or p.port or p.query or p.fragment:raise Stop('url_rejected')
  host=p.hostname
  if not(host in ('eu.version.battle.net','blzddist1-a.akamaihd.net') or host.endswith('.blizzard.com') or host.endswith('.battle.net')):raise Stop('host_not_approved')
  if not re.fullmatch(r'/[a-zA-Z0-9_./-]+',p.path) or '..' in p.path:raise Stop('path_rejected')
  remaining=min(cap,CAP-self.used)
  if remaining<=0:raise Stop('total_budget')
  conn=http.client.HTTPSConnection(host,timeout=min(20,max(1,600-(time.monotonic()-self.started))))
  rec={'url':url,'response_bytes':0};self.receipts.append(rec)
  try:
   conn.request('GET',p.path,headers={'Accept-Encoding':'identity','User-Agent':'ClassicMetadataPreflight/1.0'})
   res=conn.getresponse();rec['http_status']=res.status
   if res.status!=200 or res.getheader('Content-Encoding','identity').lower() not in ('','identity') or res.getheader('Content-Range'):raise Stop('response_rejected')
   length=res.getheader('Content-Length')
   if length is None or not length.isdecimal():raise Stop('explicit_length_required')
   n=int(length);rec['declared_bytes']=n
   if not 0<n<=remaining or expected is not None and n!=expected:raise Stop('response_size_rejected_before_body')
   out=bytearray()
   while len(out)<n:
    if time.monotonic()-self.started>=600:raise Stop('deadline')
    try:b=res.read(min(65536,n-len(out)))
    except http.client.IncompleteRead as e:
     self.used+=len(e.partial);rec['response_bytes']+=len(e.partial);raise Stop('truncated_body')
    self.used+=len(b);rec['response_bytes']+=len(b)
    if not b:raise Stop('truncated_body')
    out.extend(b)
   raw=bytes(out);rec['sha256']=hashlib.sha256(raw).hexdigest();return raw
  finally:conn.close()
def table(raw):
 lines=[x for x in raw.decode('utf-8-sig').splitlines() if x and not x.startswith('#')]
 fields=[x.split('!')[0] for x in lines[0].split('|')]
 if len(set(fields))!=len(fields):raise Stop('duplicate_table_column')
 rows=[]
 for line in lines[1:]:
  parts=line.split('|')
  if len(parts)!=len(fields):raise Stop('table_geometry')
  rows.append(dict(zip(fields,parts)))
 return rows
def one(rows,key,value):
 x=[r for r in rows if r.get(key)==value]
 if len(x)!=1:raise Stop('region_not_unique')
 return x[0]
def key(v):
 if not re.fullmatch('[0-9a-f]{32}',v):raise Stop('invalid_hash')
 return v
def config(raw,wanted):
 if hashlib.md5(raw).hexdigest()!=wanted:raise Stop('config_hash_mismatch')
 d={}
 for line in raw.decode('ascii').splitlines():
  if not line or line.startswith('#'):continue
  if ' = ' not in line:raise Stop('config_syntax')
  k,v=line.split(' = ',1)
  if k in d:raise Stop('duplicate_config_key')
  d[k]=v
 return d
def run():
 if (ROOT/'preflight-report.json').exists():raise Stop('existing_receipt_no_automatic_restart')
 c=Client();report={'schema':'classic-era-metadata-preflight-1','started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'product':'wow_classic_era','region':'eu','experimental_profile':{'os':'Windows','architecture':'x86_64','locale':'enUS'},'body_budget_bytes':CAP,'deadline_seconds':600,'game_payload_requested':False,'agent_executed':False,'product_initialized':False,'account_login_attempted':False,'user_files_accessed':False,'install_requested':False,'update_requested':False,'repair_requested':False,'requests':c.receipts,'status':'stopped_safely','full_install_size_proven':False,'required_update_bytes':None,'installation_ready':False,'apply_authorized':False}
 try:
  base='https://eu.version.battle.net/v2/products/wow_classic_era/'
  vr=c.fetch(base+'versions',1024**2);cr=c.fetch(base+'cdns',1024**2)
  v=one(table(vr),'Region','eu');cd=one(table(cr),'Name','eu')
  report['version_snapshot']=v
  path=cd['Path']
  if not re.fullmatch('[a-zA-Z0-9_/.-]+',path) or '..' in path:raise Stop('cdn_path')
  # A single returned official host, no fallback or probing.
  hosts=cd['Hosts'].split();host=next((h for h in hosts if h.endswith('.blizzard.com')),None)
  if host is None:raise Stop('official_cdn_host_unavailable')
  root='https://'+host+'/'+path.strip('/')
  report['cdn_host']=host;report['cdn_path']=path
  for name,field in [('build','BuildConfig'),('cdn','CDNConfig')]:
   h=key(v[field]);raw=c.fetch(root+'/config/'+h[:2]+'/'+h[2:4]+'/'+h,2*1024**2);cfg=config(raw,h)
   (ROOT/(name+'.config')).write_bytes(raw)
   report[name+'_config_hash']=h
   if name=='build':build=cfg
  report['build_name']=build.get('build-name');report['metadata_declarations']={k:build[k] for k in ('install','install-size','download','download-size','encoding','encoding-size','size','size-size') if k in build}
  report['status']='version_and_configs_verified'
 except Exception as e:report['stop_reason']=str(e) if isinstance(e,Stop) else type(e).__name__
 finally:
  report['body_bytes_received']=c.used;report['elapsed_seconds']=round(time.monotonic()-c.started,3)
  (ROOT/'preflight-report.json').write_text(json.dumps(report,indent=2)+'\n')
 return report,c
if __name__=='__main__':
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(Stop('deadline')));signal.alarm(600)
 r,c=run();print(json.dumps({k:v for k,v in r.items() if k not in ('requests',)},indent=2))
