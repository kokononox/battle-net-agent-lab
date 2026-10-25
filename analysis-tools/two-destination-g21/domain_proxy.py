"""Two-host explicit proxy. No TLS interception, private CA or cert bypass.
A CONNECT is not an allow decision: ClientHello SNI must match its authority.
Only pinned public IPs are used; no runtime DNS or arbitrary forwarding.
"""
import ipaddress,json,os,re,select,socket,socketserver,struct,sys,threading,time,hashlib
from pathlib import Path
from urllib.parse import urlsplit
from peer_guard import admit
HOSTS=frozenset({'us.version.battle.net','level3.blizzard.com'})
LOCK=threading.Lock();LIMIT=threading.BoundedSemaphore(16)
ACTIVE_LOCK=threading.Lock();ACTIVE=set()

def authority(text,port):
 text=text.strip().lower()
 if text.count(':')>1 or '@' in text or any(x in text for x in '/?#\\'):raise ValueError('authority_rejected')
 parts=text.split(':');host=parts[0];actual=int(parts[1]) if len(parts)==2 and parts[1].isdigit() else port if len(parts)==1 else -1
 if host not in HOSTS or actual!=port:raise ValueError('authority_rejected')
 return host

def sni(hello):
 if len(hello)<4 or hello[0]!=1 or int.from_bytes(hello[1:4],'big')!=len(hello)-4:raise ValueError('tls_clienthello_rejected')
 i=4
 def take(n):
  nonlocal i
  if n<0 or i+n>len(hello):raise ValueError('tls_bounds')
  b=hello[i:i+n];i+=n;return b
 def u8():return take(1)[0]
 def u16():return int.from_bytes(take(2),'big')
 take(34);take(u8());take(u16());take(u8());size=u16();end=i+size
 if end!=len(hello):raise ValueError('tls_extensions_rejected')
 names=[]
 while i<end:
  kind=u16();data=take(u16())
  if kind==0xfe0d:raise ValueError('tls_ech_refused')
  if kind==0:
   if len(data)<2 or int.from_bytes(data[:2],'big')!=len(data)-2:raise ValueError('tls_sni_rejected')
   p=2
   while p<len(data):
    if p+3>len(data):raise ValueError('tls_sni_rejected')
    typ=data[p];n=int.from_bytes(data[p+1:p+3],'big');p+=3
    if p+n>len(data) or typ!=0:raise ValueError('tls_sni_rejected')
    try:names.append(data[p:p+n].decode('ascii').lower())
    except UnicodeError:raise ValueError('tls_sni_rejected')
    p+=n
 if len(names)!=1 or names[0] not in HOSTS:raise ValueError('tls_sni_rejected')
 return names[0]

def exact(sock,n):
 out=bytearray()
 while len(out)<n:
  b=sock.recv(n-len(out))
  if not b:raise ValueError('peer_closed')
  out.extend(b)
 return bytes(out)

def clienthello(sock):
 raw=bytearray();hello=bytearray()
 for _ in range(8):
  header=exact(sock,5);kind,major,minor,n=struct.unpack('!BBBH',header)
  if kind!=22 or major!=3 or not 0<n<=18432:raise ValueError('tls_record_rejected')
  body=exact(sock,n);raw.extend(header+body);hello.extend(body)
  if len(hello)>65536:raise ValueError('tls_hello_limit')
  if len(hello)>=4:
   wanted=4+int.from_bytes(hello[1:4],'big')
   if len(hello)>=wanted:
    if len(hello)!=wanted:raise ValueError('tls_extra_handshake_refused')
    return bytes(raw),sni(bytes(hello))
 raise ValueError('tls_fragment_limit')

def header(sock):
 b=bytearray()
 while not b.endswith(b'\r\n\r\n'):
  if len(b)>=32768:raise ValueError('http_header_limit')
  b.extend(exact(sock,1))
 try:lines=bytes(b).decode('iso-8859-1').split('\r\n')
 except UnicodeError:raise ValueError('http_header_rejected')
 request=lines[0].split(' ')
 if len(request)!=3 or request[2] not in {'HTTP/1.0','HTTP/1.1'}:raise ValueError('http_request_rejected')
 fields=[]
 for line in lines[1:-2]:
  if ':' not in line or line[0] in ' \t':raise ValueError('http_header_rejected')
  name,value=line.split(':',1)
  if not re.fullmatch('[!#$%&\'*+.^_`|~0-9A-Za-z-]+',name):raise ValueError('http_header_rejected')
  fields.append((name.lower(),value.strip()))
 if any(k in {'proxy-authorization'} for k,v in fields):raise ValueError('authentication_not_supported')
 return request,fields

def validated_config(raw):
 if type(raw) is not dict or set(raw) not in ({'hosts','port','seconds','log','peer_policy'},{'hosts','port','seconds','log','peer_policy','transparent'}) or set(raw['hosts'])!=HOSTS:raise ValueError('config_scope')
 for host,addresses in raw['hosts'].items():
  if type(addresses) is not list or not 1<=len(addresses)<=32:raise ValueError('config_addresses')
  for text in addresses:
   if type(text) is not str or not ipaddress.ip_address(text).is_global:raise ValueError('config_nonpublic')
 if type(raw['port']) is not int or not 1024<=raw['port']<=65535 or type(raw['seconds']) is not int or not 10<=raw['seconds']<=600:raise ValueError('config_bounds')
 if type(raw['peer_policy']) is not str:raise ValueError('config_peer_policy')
 if type(raw['log']) is not str:raise ValueError('config_log')
 if type(raw.get('transparent',False)) is not bool:raise ValueError('config_mode')
 return raw

def log(config,kind,host='other',method='',reason=''):
 # Only fixed allowlist names and fixed reason enums are serialized, no bodies,
 # credentials, URLs, query strings, machine identifiers or rejected hostnames.
 row=dict(kind=kind,host=host if host in HOSTS else 'other',method=method if method in {'GET','HEAD','POST','CONNECT'} else 'other',reason=reason,utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))
 with LOCK:
  p=Path(config['log'])
  if p.exists() and p.stat().st_size>=1048576:return
  with p.open('a',encoding='utf-8') as f:f.write(json.dumps(row)+'\n')

def metadata(config,kind,host,**fields):
 row={'kind':kind,'host':host if host in HOSTS else 'other','utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
 for k,v in fields.items():
  if k in {'request_body_bytes','response_bytes','status','client_to_server_bytes','server_to_client_bytes','port','tls_hello_read_bytes','tls_hello_attempted_bytes','tls_hello_sent_bytes','client_read_bytes','client_attempted_bytes','client_sent_bytes','server_read_bytes','server_attempted_bytes','server_sent_bytes'} and type(v)==int and 0<=v<=2**40:row[k]=v
  elif k in {'path_sha256','request_body_sha256'} and type(v)==str and re.fullmatch('[a-f0-9]{64}',v):row[k]=v
  elif k=='method' and v in {'GET','HEAD','POST'}:row[k]=v
  elif k=='end_reason' and type(v)==str and re.fullmatch('[a-z_]{1,64}',v):row[k]=v
  elif k=='send_error_partial_possible' and type(v)==bool:row[k]=v
  elif k=='query_present' and type(v)==bool:row[k]=v
 with LOCK:
  p=Path(config['log'])
  if p.exists() and p.stat().st_size>=1048576:return
  with p.open('a',encoding='utf-8') as f:f.write(json.dumps(row)+'\n')

def connect(config,host,port,permit):
 permit.revalidate()
 for ip in config['hosts'][host]:
  try:
   permit.revalidate()
   log(config,'upstream_dial_started',host,reason='attempt')
   stream=socket.create_connection((ip,port),timeout=5)
   log(config,'upstream_connected',host,reason=('ipv6_' if ':' in ip else 'ipv4_')+('version_http' if port==1119 else 'tls' if port==443 else 'http'))
   return stream
  except OSError:continue
 raise ValueError('upstream_unreachable')

def reason_for(exc):
 if type(exc) is ValueError and re.fullmatch('[a-z_]{1,64}',str(exc)):return str(exc)
 if isinstance(exc,TimeoutError):return 'io_timeout'
 if isinstance(exc,ConnectionResetError):return 'connection_reset'
 if isinstance(exc,BrokenPipeError):return 'broken_pipe'
 if isinstance(exc,OSError):return 'socket_os_error'
 return 'io_or_protocol_error'

def new_transfer():
 return {k:0 for k in ('tls_hello_read_bytes','tls_hello_attempted_bytes','tls_hello_sent_bytes','client_read_bytes','client_attempted_bytes','client_sent_bytes','server_read_bytes','server_attempted_bytes','server_sent_bytes')} | {'send_error_partial_possible':False,'end_reason':'not_started'}

def send_counted(dest,data,permit,t,direction):
 # Counts confirmed socket.send acceptances, not delivery/application processing.
 # Never use sendall: it can raise after a partial send without returning its size.
 view=memoryview(data);position=0
 while position<len(view):
  permit.revalidate()
  t[direction+'_attempted_bytes']+=len(view)-position
  try:n=dest.send(view[position:])
  except Exception:
   t['send_error_partial_possible']=True
   raise
  if type(n)!=int or not 0<n<=len(view)-position:raise ValueError('socket_send_no_progress')
  t[direction+'_sent_bytes']+=n;position+=n

def relay(a,b,permit,config,host,t):
 deadline=time.monotonic()+180;total=0
 while time.monotonic()<deadline:
  readable,_,_=select.select([a,b],[],[],1)
  for source in readable:
   data=source.recv(65536)
   if not data:
    t['end_reason']='client_eof' if source is a else 'server_eof';return
   total+=len(data);direction='client' if source is a else 'server'
   t[direction+'_read_bytes']+=len(data)
   if total>512*1024**2:raise ValueError('transfer_limit')
   send_counted(b if source is a else a,data,permit,t,direction)
 raise ValueError('connection_deadline')

def finish_transfer(config,host,t):
 # Called in handler finally, including failures before admission/upstream dial.
 metadata(config,'tls_transfer_final',host,**t)

class Tracked:
 def setup(self):
  with ACTIVE_LOCK:ACTIVE.add(self.request)
 def finish(self):
  with ACTIVE_LOCK:ACTIVE.discard(self.request)

class Handler(Tracked,socketserver.BaseRequestHandler):
 def handle(self):
  config=self.server.config;host='other';method='';upstream=None;permit=None;destination_port=getattr(self.server,'destination_port',80)
  if not LIMIT.acquire(False):
   log(config,'refused_or_failed',reason='connection_capacity');return
  t=None
  try:
   permit=admit(self.request,config['peer_policy'])
   log(config,'peer_admitted',reason='native_owner_and_live_job_verified')
   self.request.settimeout(10);request,fields=header(self.request);method,target,_=request
   hosts=[v for k,v in fields if k=='host']
   if len(hosts)!=1:raise ValueError('http_host_rejected')
   if method=='CONNECT':
    t=new_transfer()
    host=authority(target,443)
    if authority(hosts[0],443)!=host:raise ValueError('http_host_mismatch')
    self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
    raw,name=clienthello(self.request);t['tls_hello_read_bytes']=len(raw)
    if name!=host:raise ValueError('tls_authority_mismatch')
    log(config,'tls_sni_allowed',host,method)
    upstream=connect(config,host,443,permit);send_counted(upstream,raw,permit,t,'tls_hello');self.request.settimeout(15);upstream.settimeout(15);relay(self.request,upstream,permit,config,host,t)
   else:
    if method not in {'GET','HEAD','POST'}:raise ValueError('http_method_rejected')
    if getattr(self.server,'transparent_http',False) and target.startswith('/') and not target.startswith('//'):
     target='http://'+hosts[0]+target
    u=urlsplit(target)
    if u.scheme!='http' or u.username is not None or u.password is not None or u.fragment:raise ValueError('http_url_rejected')
    host=authority(u.netloc,destination_port)
    if destination_port==1119 and host!='us.version.battle.net':raise ValueError('http_host_port_rejected')
    if authority(hosts[0],destination_port)!=host:raise ValueError('http_host_mismatch')
    if any(k=='transfer-encoding' for k,v in fields):raise ValueError('http_transfer_encoding_refused')
    sizes=[v for k,v in fields if k=='content-length']
    if len(sizes)>1 or sizes and not sizes[0].isdigit():raise ValueError('http_body_rejected')
    length=int(sizes[0]) if sizes else 0
    if length>1048576:raise ValueError('http_body_limit')
    body=exact(self.request,length);path=(u.path or '/')+('?' + u.query if u.query else '')
    if any(c in path for c in '\r\n\x00'):raise ValueError('http_url_rejected')
    forwarded=[(k,v) for k,v in fields if k not in {'host','proxy-connection','connection','proxy-authorization'}]
    wire=(method+' '+path+' HTTP/1.1\r\nHost: '+host+(':'+str(destination_port) if destination_port!=80 else '')+'\r\nConnection: close\r\n'+''.join(k+': '+v+'\r\n' for k,v in forwarded)+'\r\n').encode('iso-8859-1')+body
    metadata(config,'http_request',host,method=method,port=destination_port,path_sha256=hashlib.sha256((u.path or '/').encode()).hexdigest(),query_present=bool(u.query),request_body_bytes=length,request_body_sha256=hashlib.sha256(body).hexdigest());log(config,'http_host_allowed',host,method);upstream=connect(config,host,destination_port,permit);permit.revalidate();upstream.sendall(wire)
    total=0;prefix=b'';deadline=time.monotonic()+180
    while time.monotonic()<deadline:
     data=upstream.recv(65536)
     if not data:break
     total+=len(data)
     if len(prefix)<4096:prefix+=data[:4096-len(prefix)]
     if total>512*1024**2:raise ValueError('transfer_limit')
     permit.revalidate();self.request.sendall(data)
    else:raise ValueError('connection_deadline')
    status=re.match(br'HTTP/1[.][01] ([0-9]{3})',prefix)
    metadata(config,'http_response',host,response_bytes=total,status=int(status[1]) if status else 0,port=destination_port)
   log(config,'connection_closed',host,method)
  except Exception as exc:
   reason=reason_for(exc)
   if t is not None:t['end_reason']=reason
   log(config,'refused_or_failed',host,method,reason)
   try:self.request.sendall(b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
   except OSError:pass
  finally:
   if t is not None:finish_transfer(config,host,t)
   if upstream is not None:upstream.close()
   if permit is not None:permit.close()
   LIMIT.release()

class Server(socketserver.ThreadingTCPServer):
 allow_reuse_address=False;daemon_threads=True

class IPv6Server(Server):
 address_family=socket.AF_INET6

class TransparentTLSHandler(Tracked,socketserver.BaseRequestHandler):
 def handle(self):
  config=self.server.config;upstream=None;permit=None;host='other'
  if not LIMIT.acquire(False):
   log(config,'refused_or_failed',reason='connection_capacity');return
  t=new_transfer()
  try:
   permit=admit(self.request,config['peer_policy'])
   log(config,'peer_admitted',reason='native_owner_and_live_job_verified')
   self.request.settimeout(10);raw,host=clienthello(self.request);t['tls_hello_read_bytes']=len(raw)
   log(config,'tls_sni_allowed',host,'CONNECT')
   upstream=connect(config,host,443,permit);send_counted(upstream,raw,permit,t,'tls_hello')
   self.request.settimeout(15);upstream.settimeout(15);relay(self.request,upstream,permit,config,host,t)
   log(config,'connection_closed',host,'CONNECT')
  except Exception as exc:
   reason=reason_for(exc)
   if t is not None:t['end_reason']=reason
   log(config,'refused_or_failed',host,'CONNECT',reason)
  finally:
   if t is not None:finish_transfer(config,host,t)
   if upstream is not None:upstream.close()
   if permit is not None:permit.close()
   LIMIT.release()

def main():
 if len(sys.argv)!=2:raise SystemExit('config_file_required')
 config=validated_config(json.loads(Path(sys.argv[1]).read_text(encoding='utf-8-sig')))
 servers=[]
 try:
  bindings=[(Server,'127.0.0.1',config['port'],Handler,False)]
  if config.get('transparent',False):
   bindings=[(cls,ip,port,handler,port in {80,1119}) for cls,ip in [(Server,'127.0.0.1'),(IPv6Server,'::1')] for port,handler in [(80,Handler),(443,TransparentTLSHandler),(1119,Handler)]]
  for cls,ip,port,handler,transparent_http in bindings:
   try:server=cls((ip,port),handler)
   except OSError as exc:
    code=getattr(exc,'winerror',None) or exc.errno
    kind='in_use' if code in {10048,98} else 'access_denied' if code in {10013,13} else 'unavailable' if code in {10049,99} else 'os_error'
    log(config,'proxy_start_failed',reason=('ipv6_' if cls is IPv6Server else 'ipv4_')+('http_' if port==80 else 'tls_' if port==443 else 'version_http_' if port==1119 else 'explicit_')+kind)
    raise
   server.config=config;server.transparent_http=transparent_http;server.destination_port=port if transparent_http else 80;servers.append(server)
   threading.Thread(target=server.serve_forever,daemon=True).start()
  log(config,'proxy_ready');deadline=time.monotonic()+config['seconds']
  while time.monotonic()<deadline:
   try:
    lease=Path(config['peer_policy']).parent/'lease.json'
    if lease.is_file() and json.loads(lease.read_text(encoding='utf-8-sig')).get('phase') in {'releasing','released'}:break
   except (OSError,ValueError):pass
   time.sleep(.25)
 finally:
  for server in servers:server.shutdown();server.server_close()
  with ACTIVE_LOCK:sockets=list(ACTIVE)
  for client in sockets:
   try:client.shutdown(socket.SHUT_RDWR)
   except OSError:pass
  deadline=time.monotonic()+18
  while time.monotonic()<deadline:
   with ACTIVE_LOCK:remaining=len(ACTIVE)
   if not remaining:break
   time.sleep(.1)
  with ACTIVE_LOCK:remaining=len(ACTIVE)
  receipt={'complete':remaining==0,'active_handlers':remaining}
  try:
   dest=Path(config['peer_policy']).parent/'proxy-drain.json';temp=dest.with_suffix('.tmp');temp.write_text(json.dumps(receipt));os.replace(temp,dest)
   log(config,'proxy_shutdown',reason='drained' if receipt['complete'] else 'drain_deadline')
  except OSError:pass
if __name__=='__main__':main()
