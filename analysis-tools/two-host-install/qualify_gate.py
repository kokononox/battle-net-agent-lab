"""G2: qualify the two-host egress gate, without downloading/running Battle.net.
The CI runner's own Listener/Worker retain management connectivity. No such
exception exists for Setup/Agent or arbitrary descendants. No raw state exported.
"""
import hashlib,ipaddress,json,os,re,socket,ssl,subprocess,sys,tempfile,time
from pathlib import Path
from domain_proxy import HOSTS,validated_config
from redirect_hosts import Redirect
APPROVAL='lab: approved two-host egress qualification G8 20261025'
BRANCH='research/battlenet-minimal-install-isolation-2026-10-25'

def authorized(e,p):
 return p=='win32' and e.get('GITHUB_ACTIONS')=='true' and e.get('RUNNER_ENVIRONMENT')=='github-hosted' and e.get('RUNNER_OS')=='Windows' and e.get('GITHUB_REF')=='refs/heads/'+BRANCH and e.get('GITHUB_EVENT_NAME')=='push' and e.get('GITHUB_RUN_ATTEMPT')=='1' and e.get('BNET_TWO_HOSTS')==APPROVAL

def connect(ip,port):
 try:
  with socket.create_connection((ip,port),timeout=3):return True
 except OSError:return False

def request(port,data,extra=None,addr='127.0.0.1'):
 with socket.create_connection((addr,port),timeout=5) as s:
  s.settimeout(6);s.sendall(data);head=bytearray()
  while b'\r\n\r\n' not in head and len(head)<16384:
   b=s.recv(1)
   if not b:break
   head.extend(b)
  if extra is not None:s.sendall(extra);return bytes(head),s.recv(128)
  return bytes(head),b''

def fixture_http(port,wire,addr,version=False):
 # At most one retry, only idempotent fixed GET fixtures. Keep every failure.
 attempts=[]
 for attempt in range(2):
  row=dict(ok=False,status=None,error_code=None)
  try:
   head,_=request(port,wire,addr=addr)
   match=re.match(rb'HTTP/1\.[01] ([1-5][0-9][0-9])',head)
   row['status']=int(match[1]) if match else None
   gateway=head.startswith(b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0')
   row['ok']=bool(match and not gateway and (not version or row['status']==200))
   if gateway:row['error_code']='gateway_refused'
   elif not match:row['error_code']='no_http_status'
  except OSError as exc:
   row['error_code']='io_timeout' if isinstance(exc,TimeoutError) else 'socket_operation_failed'
  attempts.append(row)
  if row['ok']:break
  if attempt==0:time.sleep(1)
 return attempts

def public_ips(host):
 result=sorted({x[4][0] for x in socket.getaddrinfo(host,80,type=socket.SOCK_STREAM) if ipaddress.ip_address(x[4][0]).is_global},key=lambda x:(':' in x,x))
 if not 1<=len(result)<=32:raise ValueError('public_resolution_unavailable')
 return result

def main():
 if not authorized(os.environ,sys.platform):raise SystemExit('approved_fresh_hosted_qualification_required')
 base=Path(__file__).resolve().parent;repo=base.parents[1];sys.path.insert(0,str(repo/'scripts'));import observe_agent as obs
 env=obs.clean_environment(os.environ);ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
 r=dict(schema='bnet-two-hosts-g8-1',source_commit=os.environ['GITHUB_SHA'],run_id=os.environ['GITHUB_RUN_ID'],allowed_hosts=sorted(HOSTS),installer_launched=False,status='stopped',stage='prepare',firewall_prepared=False,firewall_applied=False,firewall_verified=False,firewall_restored=False,management_exception_scope='runner_listener_worker_only_not_target_installers',proxy_binary_sha256=None,baseline_direct={},direct_denied={},http_allowed={},other_authority_denied=False,wrong_sni_denied=False,proxy_log_counts={},tls_certificates_changed=False,raw_state_exported=False,all_traffic_blocked_proven=False,error_code=None)
 r.update(hosts_steered=False,hosts_restored=False,proxy_before_firewall={},http_probe_kinds={},ipv6_loopback_http={},tls_end_to_end_verified=False,listener_bind_probes={},proxy_exit_code=None,proxy_start_error_kind=None,tls_by_host={},baseline_direct_tls={},direct_tls_denied={},http_status_by_host={},http_attempts={})
 def write():
  out=Path('output/two-hosts-g8.json');out.parent.mkdir(exist_ok=True);out.write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
 with tempfile.TemporaryDirectory(prefix='bnet-two-hosts-g8-',dir=os.environ['RUNNER_TEMP'],ignore_cleanup_errors=True) as tmp:
  work=Path(tmp);config=work/'proxy.json';log=work/'proxy-private.jsonl';proxy=None;prepared=False;redirect=Redirect(work,env)
  exe=base/'dist/TwoHostProxy.exe';startup_error=work/'proxy-stderr.private.txt';error_stream=None
  def gate(action):
   p=subprocess.run([str(ps),'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(base/'firewall_gate.ps1'),'-Action',action,'-Work',str(work),'-ProxyExe',str(exe),'-Config',str(config)],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=60,check=False)
   if len(p.stdout)>8192:raise ValueError('firewall_helper_output_limit')
   try:v=json.loads(p.stdout.decode('utf-8-sig'))
   except (ValueError,UnicodeError):raise ValueError('firewall_helper_protocol_failed')
   if p.returncode!=0:raise ValueError('firewall_helper_failed')
   return v
  try:
   for ip,family in [('127.0.0.1',socket.AF_INET),('::1',socket.AF_INET6)]:
    for port_probe in [80,443,1119]:
     probe_socket=socket.socket(family,socket.SOCK_STREAM)
     try:
      probe_socket.bind((ip,port_probe));code=None
     except OSError as exc:code=getattr(exc,'winerror',None) or exc.errno
     finally:probe_socket.close()
     r['listener_bind_probes'][('ipv4_' if family==socket.AF_INET else 'ipv6_')+str(port_probe)]=code
   if not exe.is_file():raise ValueError('proxy_binary_missing')
   r['proxy_binary_sha256']=hashlib.sha256(exe.read_bytes()).hexdigest()
   pins={host:public_ips(host) for host in HOSTS};negative=public_ips('example.com')[0]
   baseline={h:next((ip for ip in pins[h] if ':' not in ip and connect(ip,1119 if h=='us.version.battle.net' else 80)),None) for h in HOSTS}
   r['baseline_direct']={h:ip is not None for h,ip in baseline.items()};r['baseline_direct']['negative_fixture']=connect(negative,443)
   r['baseline_direct_tls']={h:connect(ip,443) for h,ip in baseline.items() if ip is not None}
   if not all(r['baseline_direct'].values()) or not all(r['baseline_direct_tls'].values()):raise ValueError('network_baseline_not_healthy')
   # A fixed loopback port is tested before any firewall change.
   port=80;cfg=validated_config(dict(hosts=pins,port=18731,seconds=150,log=str(log),transparent=True));config.write_text(json.dumps(cfg),encoding='utf-8')
   error_stream=startup_error.open('wb')
   proxy=subprocess.Popen([str(exe),str(config)],cwd=work,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=error_stream)
   for _ in range(60):
    if log.exists() and 'proxy_ready' in log.read_text():break
    if proxy.poll() is not None:
     r['proxy_exit_code']=proxy.returncode;raise ValueError('proxy_start_failed')
    time.sleep(.5)
   else:raise ValueError('proxy_ready_timeout')
   for host in sorted(HOSTS):
    path='/agent/versions' if host=='us.version.battle.net' else '/'
    target_port=1119 if host=='us.version.battle.net' else 80;host_header=host+(':1119' if target_port==1119 else '')
    attempts=fixture_http(target_port,('GET '+path+' HTTP/1.1\r\nHost: '+host_header+'\r\nConnection: close\r\n\r\n').encode(),'127.0.0.1',host=='us.version.battle.net')
    r['http_attempts']['before_'+host]=attempts;r['proxy_before_firewall'][host]=attempts[-1]['ok']
   if not all(r['proxy_before_firewall'].values()):raise ValueError('proxy_http_fixture_not_healthy_before_firewall')
   redirect.prepare()
   result=gate('Prepare');prepared=result.get('prepared') is True;r['firewall_prepared']=prepared;write()
   r['hosts_steered']=redirect.apply()
   r['stage']='apply';result=gate('Apply');r['firewall_applied']=result.get('verified') is True;write()
   if not r['firewall_applied']:raise ValueError('firewall_not_applied')
   r['stage']='probe'
   r['direct_denied']={h:not connect(ip,1119 if h=='us.version.battle.net' else 80) for h,ip in baseline.items()};r['direct_denied']['negative_fixture']=not connect(negative,443)
   for host in sorted(HOSTS):
    path='/agent/versions' if host=='us.version.battle.net' else '/'
    target_port=1119 if host=='us.version.battle.net' else 80;host_header=host+(':1119' if target_port==1119 else '')
    wire=('GET '+path+' HTTP/1.1\r\nHost: '+host_header+'\r\nConnection: close\r\n\r\n').encode()
    attempts=fixture_http(target_port,wire,host,host=='us.version.battle.net')
    r['http_attempts']['gated_'+host]=attempts
    good=attempts[-1]['ok'];r['http_status_by_host'][host]=attempts[-1]['status']
    r['http_allowed'][host]=good;r['http_probe_kinds'][host]='http_response' if good else 'no_usable_http_response'
    attempts6=fixture_http(target_port,wire,'::1',host=='us.version.battle.net')
    r['http_attempts']['gated_ipv6_loopback_'+host]=attempts6;r['ipv6_loopback_http'][host]=attempts6[-1]['ok']
   r['direct_tls_denied']={h:not connect(ip,443) for h,ip in baseline.items()}
   for host in sorted(HOSTS):
    try:
     with socket.create_connection((host,443),timeout=5) as raw_socket:
      with ssl.create_default_context().wrap_socket(raw_socket,server_hostname=host) as secure:
       r['tls_by_host'][host]=bool(secure.getpeercert())
    except (OSError,ssl.SSLError):r['tls_by_host'][host]=False
   r['tls_end_to_end_verified']=len(r['tls_by_host'])==2 and all(r['tls_by_host'].values())
   head,_=request(port,b'HEAD http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n');r['other_authority_denied']=head.startswith(b'HTTP/1.1 403')
   incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO();tls=ssl.create_default_context().wrap_bio(incoming,outgoing,server_hostname='example.com')
   try:tls.do_handshake()
   except ssl.SSLWantReadError:pass
   head,tail=request(port,b'CONNECT us.version.battle.net:443 HTTP/1.1\r\nHost: us.version.battle.net:443\r\n\r\n',outgoing.read());r['wrong_sni_denied']=head.startswith(b'HTTP/1.1 200') and (not tail or tail.startswith(b'HTTP/1.1 403'))
   r['stage']='verify';r['firewall_verified']=gate('Verify').get('verified') is True
   if all(r['direct_denied'].values()) and all(r['http_allowed'].values()) and r['other_authority_denied'] and r['wrong_sni_denied'] and r['firewall_verified'] and r['hosts_steered'] and all(r['ipv6_loopback_http'].values()) and all(r['direct_tls_denied'].values()) and r['tls_end_to_end_verified']:r['status']='qualified_two_host_http_tls_ipv4_gate'
   else:r['error_code']='qualification_probe_failed'
  except Exception as exc:
   text=str(exc);r['error_code']=text if type(exc) is ValueError and re.fullmatch('[a-z_]{1,80}',text) else 'qualification_operation_failed'
  finally:
   r['stage']='restore'
   try:r['hosts_restored']=redirect.restore()
   except Exception:r['hosts_restored']=False
   if not r['hosts_restored']:r['status']='stopped';r['error_code']='hosts_restore_not_verified'
   if prepared:
    try:r['firewall_restored']=gate('Restore').get('restored_modified_fields') is True
    except Exception:r['firewall_restored']=False
    if not r['firewall_restored']:r['status']='stopped';r['error_code']='firewall_restore_not_verified'
   if proxy is not None:
    proxy.terminate()
    try:proxy.wait(timeout=5)
    except subprocess.TimeoutExpired:proxy.kill()
   if error_stream is not None:error_stream.close()
   if startup_error.exists():
    error_bytes=startup_error.read_bytes()[:16384]
    for label in ['PermissionError','OSError','ValueError','ModuleNotFoundError','ImportError','FileNotFoundError','UnicodeDecodeError']:
     if label.encode() in error_bytes:r['proxy_start_error_kind']=label;break
   if log.exists():
    counts={}
    for line in log.read_text(encoding='utf-8').splitlines():
     try:x=json.loads(line)
     except ValueError:continue
     k=x.get('kind','')+':'+x.get('reason','')
     if re.fullmatch('[a-z_:]{1,130}',k):counts[k]=counts.get(k,0)+1
    r['proxy_log_counts']=counts
    if r['status']=='qualified_two_host_http_tls_ipv4_gate' and not counts.get('refused_or_failed:tls_sni_rejected'):
     r['status']='stopped';r['error_code']='wrong_sni_refusal_not_confirmed'
   r['stage']='complete';write();print(json.dumps(dict(status=r['status'],error_code=r['error_code'],firewall_restored=r['firewall_restored'])))
if __name__=='__main__':main()
