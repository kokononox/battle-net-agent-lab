"""Bounded public, read-only protocol fixtures for the two approved names only.
No Setup, login, cookies, persistent network changes, raw responses or TLS bypass.
"""
import ipaddress,json,os,re,socket,ssl,sys
from pathlib import Path
HOSTS=('level3.blizzard.com','us.version.battle.net')
APPROVAL='lab: approved two-host protocol diagnosis G6 20261025'
def authorized(e,p):
 return p=='win32' and e.get('GITHUB_ACTIONS')=='true' and e.get('RUNNER_ENVIRONMENT')=='github-hosted' and e.get('RUNNER_OS')=='Windows' and e.get('GITHUB_REF')=='refs/heads/research/battlenet-minimal-install-isolation-2026-10-25' and e.get('GITHUB_EVENT_NAME')=='push' and e.get('GITHUB_RUN_ATTEMPT')=='1' and e.get('BNET_TWO_HOSTS')==APPROVAL

def probe(host,port,fixture,wire,tls=False):
 row=dict(host=host,port=port,fixture=fixture,connected=False,tls_verified=False,response_kind='none',http_status=None,received_bytes=0,error_code=None)
 addresses=sorted({x[4][0] for x in socket.getaddrinfo(host,port,type=socket.SOCK_STREAM) if ipaddress.ip_address(x[4][0]).is_global},key=lambda x:(':' in x,x))
 if not 1<=len(addresses)<=32:row['error_code']='resolution_refused';return row
 s=None
 try:
  for ip in addresses[:4]:
   try:s=socket.create_connection((ip,port),timeout=3);break
   except OSError:pass
  if s is None:row['error_code']='connect_unavailable';return row
  row['connected']=True;s.settimeout(4)
  if tls:
   s=ssl.create_default_context().wrap_socket(s,server_hostname=host);row['tls_verified']=True
  s.sendall(wire);b=bytearray()
  try:
   while len(b)<8192:
    part=s.recv(min(4096,8192-len(b)))
    if not part:break
    b.extend(part)
    if b'\r\n\r\n' in b:break
  except socket.timeout:row['error_code']='read_timeout'
  row['received_bytes']=len(b)
  m=re.match(rb'HTTP/1\.[01] ([1-5][0-9][0-9])(?: |\r\n)',b)
  if m:row['response_kind']='http';row['http_status']=int(m[1])
  elif b:row['response_kind']='non_http_bytes'
 except ssl.SSLCertVerificationError:row['error_code']='tls_certificate_not_verified'
 except ssl.SSLError:row['error_code']='tls_handshake_failed'
 except OSError:row['error_code']='socket_operation_failed'
 finally:
  if s is not None:s.close()
 return row

def main():
 if not authorized(os.environ,sys.platform):raise SystemExit('approved_fresh_hosted_protocol_diagnosis_required')
 r=dict(schema='bnet-two-hosts-protocol-g6-1',source_commit=os.environ['GITHUB_SHA'],run_id=os.environ['GITHUB_RUN_ID'],allowed_hosts=list(HOSTS),installer_launched=False,policy_changed=False,tls_certificates_changed=False,raw_response_exported=False,probes=[])
 for host in HOSTS:
  fixtures=[(80,'http_root', '/',False),(443,'https_root','/',True)]
  if host=='us.version.battle.net':fixtures += [(80,'http_agent_versions','/agent/versions',False),(1119,'http_agent_versions_1119','/agent/versions',False)]
  for port,label,path,tls in fixtures:
   wire=('GET '+path+' HTTP/1.1\r\nHost: '+host+(':'+str(port) if port==1119 else '')+'\r\nConnection: close\r\n\r\n').encode()
   r['probes'].append(probe(host,port,label,wire,tls))
  if host=='us.version.battle.net':r['probes'].append(probe(host,1119,'ribbit_agent_versions',b'v1/products/agent/versions\r\n'))
 out=Path('output/two-hosts-protocol-g6.json');out.parent.mkdir(exist_ok=True);out.write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
 print('Read-only fixed protocol probes complete; no installer or policy changes.')
if __name__=='__main__':main()
