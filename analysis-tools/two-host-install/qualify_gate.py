"""G1: qualify the two-host egress gate, without downloading/running Battle.net.
The CI runner's own Listener/Worker retain management connectivity. No such
exception exists for Setup/Agent or arbitrary descendants. No raw state exported.
"""
import hashlib,ipaddress,json,os,re,socket,ssl,subprocess,sys,tempfile,time
from pathlib import Path
from domain_proxy import HOSTS,validated_config
APPROVAL='lab: approved two-host egress qualification G1 20261025'
BRANCH='research/battlenet-minimal-install-isolation-2026-10-25'

def authorized(e,p):
 return p=='win32' and e.get('GITHUB_ACTIONS')=='true' and e.get('RUNNER_ENVIRONMENT')=='github-hosted' and e.get('RUNNER_OS')=='Windows' and e.get('GITHUB_REF')=='refs/heads/'+BRANCH and e.get('GITHUB_EVENT_NAME')=='push' and e.get('GITHUB_RUN_ATTEMPT')=='1' and e.get('BNET_TWO_HOSTS')==APPROVAL

def connect(ip,port):
 try:
  with socket.create_connection((ip,port),timeout=3):return True
 except OSError:return False

def request(port,data,extra=None):
 with socket.create_connection(('127.0.0.1',port),timeout=5) as s:
  s.settimeout(6);s.sendall(data);head=bytearray()
  while b'\r\n\r\n' not in head and len(head)<16384:
   b=s.recv(1)
   if not b:break
   head.extend(b)
  if extra is not None:s.sendall(extra);return bytes(head),s.recv(128)
  return bytes(head),b''

def public_ips(host):
 result=sorted({x[4][0] for x in socket.getaddrinfo(host,80,type=socket.SOCK_STREAM) if ipaddress.ip_address(x[4][0]).is_global})
 if not 1<=len(result)<=32:raise ValueError('public_resolution_unavailable')
 return result

def main():
 if not authorized(os.environ,sys.platform):raise SystemExit('approved_fresh_hosted_qualification_required')
 base=Path(__file__).resolve().parent;repo=base.parents[1];sys.path.insert(0,str(repo/'scripts'));import observe_agent as obs
 env=obs.clean_environment(os.environ);ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
 r=dict(schema='bnet-two-hosts-g1-1',source_commit=os.environ['GITHUB_SHA'],run_id=os.environ['GITHUB_RUN_ID'],allowed_hosts=sorted(HOSTS),installer_launched=False,status='stopped',stage='prepare',firewall_prepared=False,firewall_applied=False,firewall_verified=False,firewall_restored=False,management_exception_scope='runner_listener_worker_only_not_target_installers',proxy_binary_sha256=None,baseline_direct={},direct_denied={},http_allowed={},other_authority_denied=False,wrong_sni_denied=False,proxy_log_counts={},tls_certificates_changed=False,raw_state_exported=False,all_traffic_blocked_proven=False,error_code=None)
 def write():
  out=Path('output/two-hosts-g1.json');out.parent.mkdir(exist_ok=True);out.write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
 with tempfile.TemporaryDirectory(prefix='bnet-two-hosts-g1-',dir=os.environ['RUNNER_TEMP'],ignore_cleanup_errors=True) as tmp:
  work=Path(tmp);config=work/'proxy.json';log=work/'proxy-private.jsonl';proxy=None;prepared=False
  exe=base/'dist/TwoHostProxy.exe'
  def gate(action):
   p=subprocess.run([str(ps),'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(base/'firewall_gate.ps1'),'-Action',action,'-Work',str(work),'-ProxyExe',str(exe),'-Config',str(config)],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=60,check=False)
   if len(p.stdout)>8192:raise ValueError('firewall_helper_output_limit')
   try:v=json.loads(p.stdout.decode('utf-8-sig'))
   except (ValueError,UnicodeError):raise ValueError('firewall_helper_protocol_failed')
   if p.returncode!=0:raise ValueError('firewall_helper_failed')
   return v
  try:
   if not exe.is_file():raise ValueError('proxy_binary_missing')
   r['proxy_binary_sha256']=hashlib.sha256(exe.read_bytes()).hexdigest()
   pins={host:public_ips(host) for host in HOSTS};negative=public_ips('example.com')[0]
   baseline={h:next((ip for ip in pins[h] if connect(ip,80)),None) for h in HOSTS}
   r['baseline_direct']={h:ip is not None for h,ip in baseline.items()};r['baseline_direct']['negative_fixture']=connect(negative,443)
   if not all(r['baseline_direct'].values()):raise ValueError('network_baseline_not_healthy')
   # A fixed loopback port is tested before any firewall change.
   port=18731;cfg=validated_config(dict(hosts=pins,port=port,seconds=150,log=str(log)));config.write_text(json.dumps(cfg),encoding='utf-8')
   proxy=subprocess.Popen([str(exe),str(config)],cwd=work,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   for _ in range(60):
    if log.exists() and 'proxy_ready' in log.read_text():break
    if proxy.poll() is not None:raise ValueError('proxy_start_failed')
    time.sleep(.5)
   else:raise ValueError('proxy_ready_timeout')
   result=gate('Prepare');prepared=result.get('prepared') is True;r['firewall_prepared']=prepared;write()
   r['stage']='apply';result=gate('Apply');r['firewall_applied']=result.get('verified') is True;write()
   if not r['firewall_applied']:raise ValueError('firewall_not_applied')
   r['stage']='probe'
   r['direct_denied']={h:not connect(ip,80) for h,ip in baseline.items()};r['direct_denied']['negative_fixture']=not connect(negative,443)
   for host in sorted(HOSTS):
    head,_=request(port,('HEAD http://'+host+'/ HTTP/1.1\r\nHost: '+host+'\r\nConnection: close\r\n\r\n').encode())
    r['http_allowed'][host]=bool(re.match(rb'HTTP/1\.[01] [1-5][0-9][0-9]',head) and not head.startswith(b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0'))
   head,_=request(port,b'HEAD http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n');r['other_authority_denied']=head.startswith(b'HTTP/1.1 403')
   incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO();tls=ssl.create_default_context().wrap_bio(incoming,outgoing,server_hostname='example.com')
   try:tls.do_handshake()
   except ssl.SSLWantReadError:pass
   head,tail=request(port,b'CONNECT us.version.battle.net:443 HTTP/1.1\r\nHost: us.version.battle.net:443\r\n\r\n',outgoing.read());r['wrong_sni_denied']=head.startswith(b'HTTP/1.1 200') and (not tail or tail.startswith(b'HTTP/1.1 403'))
   r['stage']='verify';r['firewall_verified']=gate('Verify').get('verified') is True
   if all(r['direct_denied'].values()) and all(r['http_allowed'].values()) and r['other_authority_denied'] and r['wrong_sni_denied'] and r['firewall_verified']:r['status']='qualified_proxy_and_ipv4_gate'
   else:r['error_code']='qualification_probe_failed'
  except Exception as exc:
   text=str(exc);r['error_code']=text if type(exc) is ValueError and re.fullmatch('[a-z_]{1,80}',text) else 'qualification_operation_failed'
  finally:
   r['stage']='restore'
   if prepared:
    try:r['firewall_restored']=gate('Restore').get('restored_modified_fields') is True
    except Exception:r['firewall_restored']=False
    if not r['firewall_restored']:r['status']='stopped';r['error_code']='firewall_restore_not_verified'
   if proxy is not None:
    proxy.terminate()
    try:proxy.wait(timeout=5)
    except subprocess.TimeoutExpired:proxy.kill()
   if log.exists():
    counts={}
    for line in log.read_text(encoding='utf-8').splitlines():
     try:x=json.loads(line)
     except ValueError:continue
     k=x.get('kind','')+':'+x.get('reason','')
     if re.fullmatch('[a-z_:]{1,130}',k):counts[k]=counts.get(k,0)+1
    r['proxy_log_counts']=counts
    if r['status']=='qualified_proxy_and_ipv4_gate' and not counts.get('refused_or_failed:tls_sni_rejected'):
     r['status']='stopped';r['error_code']='wrong_sni_refusal_not_confirmed'
   r['stage']='complete';write();print(json.dumps(dict(status=r['status'],error_code=r['error_code'],firewall_restored=r['firewall_restored'])))
if __name__=='__main__':main()
