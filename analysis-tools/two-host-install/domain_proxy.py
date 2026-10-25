"""Two-host explicit proxy. No TLS interception, private CA or cert bypass.
A CONNECT is not an allow decision: ClientHello SNI must match its authority.
Only pinned public IPs are used; no runtime DNS or arbitrary forwarding.
"""
import ipaddress,json,os,re,select,socket,socketserver,struct,sys,threading,time
from pathlib import Path
from urllib.parse import urlsplit
HOSTS=frozenset({'us.version.battle.net','level3.blizzard.com'})
LOCK=threading.Lock();LIMIT=threading.BoundedSemaphore(16)

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
 if type(raw) is not dict or set(raw) not in ({'hosts','port','seconds','log'},{'hosts','port','seconds','log','transparent'}) or set(raw['hosts'])!=HOSTS:raise ValueError('config_scope')
 for host,addresses in raw['hosts'].items():
  if type(addresses) is not list or not 1<=len(addresses)<=32:raise ValueError('config_addresses')
  for text in addresses:
   if type(text) is not str or not ipaddress.ip_address(text).is_global:raise ValueError('config_nonpublic')
 if type(raw['port']) is not int or not 1024<=raw['port']<=65535 or type(raw['seconds']) is not int or not 10<=raw['seconds']<=600:raise ValueError('config_bounds')
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

def connect(config,host,port):
 for ip in config['hosts'][host]:
  try:return socket.create_connection((ip,port),timeout=5)
  except OSError:continue
 raise ValueError('upstream_unreachable')

def relay(a,b):
 # Fixed deadline/byte bound: reaching either is a coverage/transfer limit, never
 # evidence that a domain is unnecessary. Qualification uses only small probes.
 deadline=time.monotonic()+120;total=0
 while time.monotonic()<deadline:
  readable,_,_=select.select([a,b],[],[],1)
  for source in readable:
   data=source.recv(65536)
   if not data:return
   total+=len(data)
   if total>512*1024**2:raise ValueError('transfer_limit')
   (b if source is a else a).sendall(data)
 raise ValueError('connection_deadline')

class Handler(socketserver.BaseRequestHandler):
 def handle(self):
  config=self.server.config;host='other';method='';upstream=None
  if not LIMIT.acquire(False):return
  try:
   self.request.settimeout(10);request,fields=header(self.request);method,target,_=request
   hosts=[v for k,v in fields if k=='host']
   if len(hosts)!=1:raise ValueError('http_host_rejected')
   if method=='CONNECT':
    host=authority(target,443)
    if authority(hosts[0],443)!=host:raise ValueError('http_host_mismatch')
    self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
    raw,name=clienthello(self.request)
    if name!=host:raise ValueError('tls_authority_mismatch')
    log(config,'tls_sni_allowed',host,method)
    upstream=connect(config,host,443);upstream.sendall(raw);self.request.settimeout(15);upstream.settimeout(15);relay(self.request,upstream)
   else:
    if method not in {'GET','HEAD','POST'}:raise ValueError('http_method_rejected')
    if getattr(self.server,'transparent_http',False) and target.startswith('/') and not target.startswith('//'):
     target='http://'+hosts[0]+target
    u=urlsplit(target)
    if u.scheme!='http' or u.username is not None or u.password is not None or u.fragment:raise ValueError('http_url_rejected')
    host=authority(u.netloc,80)
    if authority(hosts[0],80)!=host:raise ValueError('http_host_mismatch')
    if any(k=='transfer-encoding' for k,v in fields):raise ValueError('http_transfer_encoding_refused')
    sizes=[v for k,v in fields if k=='content-length']
    if len(sizes)>1 or sizes and not sizes[0].isdigit():raise ValueError('http_body_rejected')
    length=int(sizes[0]) if sizes else 0
    if length>1048576:raise ValueError('http_body_limit')
    body=exact(self.request,length);path=(u.path or '/')+('?' + u.query if u.query else '')
    if any(c in path for c in '\r\n\x00'):raise ValueError('http_url_rejected')
    forwarded=[(k,v) for k,v in fields if k not in {'host','proxy-connection','connection','proxy-authorization'}]
    wire=(method+' '+path+' HTTP/1.1\r\nHost: '+host+'\r\nConnection: close\r\n'+''.join(k+': '+v+'\r\n' for k,v in forwarded)+'\r\n').encode('iso-8859-1')+body
    log(config,'http_host_allowed',host,method);upstream=connect(config,host,80);upstream.sendall(wire)
    total=0;deadline=time.monotonic()+120
    while time.monotonic()<deadline:
     data=upstream.recv(65536)
     if not data:break
     total+=len(data)
     if total>512*1024**2:raise ValueError('transfer_limit')
     self.request.sendall(data)
   log(config,'connection_closed',host,method)
  except Exception as exc:
   reason=str(exc) if type(exc) is ValueError and re.fullmatch('[a-z_]{1,64}',str(exc)) else 'io_or_protocol_error'
   log(config,'refused_or_failed',host,method,reason)
   try:self.request.sendall(b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
   except OSError:pass
  finally:
   if upstream is not None:upstream.close()
   LIMIT.release()

class Server(socketserver.ThreadingTCPServer):
 allow_reuse_address=False;daemon_threads=True

class IPv6Server(Server):
 address_family=socket.AF_INET6

class TransparentTLSHandler(socketserver.BaseRequestHandler):
 def handle(self):
  config=self.server.config;upstream=None;host='other'
  if not LIMIT.acquire(False):return
  try:
   self.request.settimeout(10);raw,host=clienthello(self.request)
   log(config,'tls_sni_allowed',host,'CONNECT')
   upstream=connect(config,host,443);upstream.sendall(raw)
   self.request.settimeout(15);upstream.settimeout(15);relay(self.request,upstream)
   log(config,'connection_closed',host,'CONNECT')
  except Exception as exc:
   reason=str(exc) if type(exc) is ValueError and re.fullmatch('[a-z_]{1,64}',str(exc)) else 'io_or_protocol_error'
   log(config,'refused_or_failed',host,'CONNECT',reason)
  finally:
   if upstream is not None:upstream.close()
   LIMIT.release()

def main():
 if len(sys.argv)!=2:raise SystemExit('config_file_required')
 config=validated_config(json.loads(Path(sys.argv[1]).read_text(encoding='utf-8-sig')))
 servers=[]
 try:
  bindings=[(Server,'127.0.0.1',config['port'],Handler,False)]
  if config.get('transparent',False):
   bindings=[(cls,ip,port,handler,port==80) for cls,ip in [(Server,'127.0.0.1'),(IPv6Server,'::1')] for port,handler in [(80,Handler),(443,TransparentTLSHandler)]]
  for cls,ip,port,handler,transparent_http in bindings:
   try:server=cls((ip,port),handler)
   except OSError as exc:
    code=getattr(exc,'winerror',None) or exc.errno
    kind='in_use' if code in {10048,98} else 'access_denied' if code in {10013,13} else 'unavailable' if code in {10049,99} else 'os_error'
    log(config,'proxy_start_failed',reason=('ipv6_' if cls is IPv6Server else 'ipv4_')+('http_' if port==80 else 'tls_' if port==443 else 'explicit_')+kind)
    raise
   server.config=config;server.transparent_http=transparent_http;servers.append(server)
   threading.Thread(target=server.serve_forever,daemon=True).start()
  log(config,'proxy_ready');time.sleep(config['seconds'])
 finally:
  for server in servers:server.shutdown();server.server_close()
if __name__=='__main__':main()
