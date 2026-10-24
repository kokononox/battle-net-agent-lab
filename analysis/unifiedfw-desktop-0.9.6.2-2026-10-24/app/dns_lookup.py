"""Explicit reverse-DNS lookups only. No domain ownership or service-role inference."""
import base64,concurrent.futures,ipaddress,json,os,re,subprocess,time
from pathlib import Path
MAX_IPS=100
STATUSES={'found','no_ptr','error','timeout'}

def clean_names(names):
 if not isinstance(names,list):return []
 out=[]
 for name in names[:4]:
  if not isinstance(name,str):continue
  try:name=name.rstrip('.').encode('idna').decode('ascii').lower()
  except (UnicodeError,ValueError):continue
  labels=name.split('.')
  if len(name)>253 or any(not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?',x) for x in labels):continue
  if name not in out:out.append(name)
 return out

def query_ptr(ip,app):
 """Each read-only resolver child is independently bounded; the UI never blocks on DNS."""
 env=os.environ.copy();env['WOW_PTR_IP']=ip
 code="& ([scriptblock]::Create([IO.File]::ReadAllText('"+str(Path(app)/'resolve.ps1').replace("'","''")+"')))"
 ps=Path(os.environ.get('SystemRoot','C:/Windows'))/'System32/WindowsPowerShell/v1.0/powershell.exe'
 try:
  r=subprocess.run([str(ps),'-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(code.encode('utf-16le')).decode()],env=env,capture_output=True,timeout=6,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
  if r.returncode:return dict(status='error',names=[])
  raw=json.loads(r.stdout.decode('utf-8-sig'))
  return raw if isinstance(raw,dict) else dict(status='error',names=[])
 except subprocess.TimeoutExpired:return dict(status='timeout',names=[])
 except (OSError,ValueError,UnicodeError):return dict(status='error',names=[])

class Resolver:
 def __init__(self,path,app,atomic,query=None,clock=time.time):
  self.path=Path(path);self.atomic=atomic;self.clock=clock;self.query=query or (lambda ip:query_ptr(ip,app));self.cache={}
  try:
   if self.path.stat().st_size>2000000:raise ValueError('oversized_cache')
   raw=json.loads(self.path.read_text('utf-8'))
   for ip,item in list(raw.get('entries',{}).items())[:1000]:
    addr=ipaddress.ip_address(ip)
    if not addr.is_global or addr.is_multicast or addr.is_reserved:continue
    status=item.get('status');checked=float(item['checked_utc']);expires=float(item['expires_utc']);now=self.clock()
    if status not in STATUSES or not 0<=checked<=now+60 or not checked<=expires<=checked+86400:continue
    names=clean_names(item.get('names'))
    if status=='found' and not names:continue
    self.cache[str(addr)]=dict(ip=str(addr),status=status,names=names if status=='found' else [],checked_utc=checked,expires_utc=expires,source='system_DNS_PTR',actual_domain_verified=False)
  except (OSError,ValueError,TypeError,AttributeError,KeyError):pass
 def rows(self):
  now=self.clock()
  return [{**x,'stale':x['expires_utc']<=now} for x in self.cache.values()]
 def lookup(self,entries,force=False,stop=None,progress=None):
  ips=[];skipped=[]
  for entry in entries:
   value=entry['ip']
   if '/' in value:
    if value not in skipped:skipped.append(value)
    continue
   if value not in ips:ips.append(value)
  if len(ips)>MAX_IPS:raise ValueError('select_at_most_100_unique_IPs')
  now=self.clock();results={};pending=[]
  for ip in ips:
   cached=self.cache.get(ip)
   if not force and cached and cached['expires_utc']>now:results[ip]={**cached,'cached':True,'stale':False}
   else:pending.append(ip)
  def report():
   if progress:progress(dict(done=len(results),total=len(ips),skipped_ranges=len(skipped)))
  report();cancelled=False;iterator=iter(pending)
  # Only four read-only children in flight, no unbounded OS resolver threads.
  with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
   tasks={}
   def fill():
    nonlocal cancelled
    if stop and stop():cancelled=True;return
    while len(tasks)<4:
     try:ip=next(iterator)
     except StopIteration:return
     tasks[pool.submit(self.query,ip)]=ip
   fill()
   while tasks:
    done,_=concurrent.futures.wait(tasks,timeout=.2,return_when=concurrent.futures.FIRST_COMPLETED)
    for future in done:
     ip=tasks.pop(future)
     try:raw=future.result();status=raw.get('status');names=clean_names(raw.get('names'))
     except Exception:status='error';names=[]
     if status not in STATUSES:status='error'
     if status=='found' and not names:status='error'
     if status!='found':names=[]
     checked=self.clock();ttl=86400 if status=='found' else (900 if status=='no_ptr' else 60)
     row=dict(ip=ip,status=status,names=names,checked_utc=checked,expires_utc=checked+ttl,source='system_DNS_PTR',actual_domain_verified=False)
     self.cache[ip]=row;results[ip]={**row,'cached':False,'stale':False};report()
    fill()
  if stop and stop():cancelled=True
  self.cache=dict(sorted(self.cache.items(),key=lambda x:x[1]['checked_utc'],reverse=True)[:1000])
  self.atomic(self.path,dict(schema='wow-blacklist-ptr-cache-1',entries=self.cache))
  return dict(entries=[results[ip] for ip in ips if ip in results],skipped_ranges=skipped,cancelled=cancelled,requested=len(ips),completed=len(results),actual_domain_verified=False,firewall_changed=False)
