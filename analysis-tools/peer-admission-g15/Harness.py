"""Local instrumented upstream only; never contacts Battle.net or an external IP."""
import collections,json,os,socket,socketserver,subprocess,sys,threading,time,uuid
from pathlib import Path
import domain_proxy as proxy
import peer_guard
if os.name!='nt' or os.environ.get('BNET_PEER_G15')!='lab: approved peer admission G15a 20261025' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':raise SystemExit('fresh_hosted_qualification_required')
ROOT=Path(sys.argv[1]);EXE=Path(sys.argv[2]);ARCH=sys.argv[3]
POLICY=ROOT/'peers.json';LOG=ROOT/'proxy-private.jsonl';RESULT=Path('output')/('peer-g15-'+ARCH+'.json')
LOCK=threading.Lock();COUNTER={'connections':0,'bytes':0,'dial_attempts':0};SERVERS=[]
def save_policy(rows,expired=False):
 v={'expires_unix':time.time()+(-5 if expired else 300),'peers':rows};temp=POLICY.with_suffix('.tmp');temp.write_text(json.dumps(v),encoding='utf-8');os.replace(temp,POLICY)
def counters():
 with LOCK:return dict(COUNTER)
class Sink(socketserver.BaseRequestHandler):
 def handle(self):
  with LOCK:COUNTER['connections']+=1
  self.request.settimeout(4)
  try:
   if self.server.destination_port==443:
    h=proxy.exact(self.request,5);b=proxy.exact(self.request,int.from_bytes(h[3:5],'big'));data=h+b
   else:
    data=bytearray()
    while not data.endswith(b'\r\n\r\n') and len(data)<32768:data.extend(proxy.exact(self.request,1))
   with LOCK:COUNTER['bytes']+=len(data)
   self.request.sendall(b'\x15' if self.server.destination_port==443 else b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
  except Exception:pass

def launch_server(cls,address,handler,config=None,destination_port=80):
 s=cls(address,handler);s.destination_port=destination_port
 if config:s.config=config;s.transparent_http=True
 SERVERS.append(s);threading.Thread(target=s.serve_forever,daemon=True).start();return s

def wait_file(path,seconds=15):
 end=time.monotonic()+seconds
 while time.monotonic()<end and not path.exists():time.sleep(.02)
 if not path.exists():raise RuntimeError('client_receipt_timeout')

report={'schema':'bnet-peer-g15a-1','source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'architecture':ARCH,'status':'stopped','installer_launched':False,'real_upstream_contacted':False,'full_firewall_integration_tested':False,'socket_duplication_proven_safe':False,'all_process_creation_intercepted':False,'https_payload_classified':False,'cases':[],'error_code':None}
original_dial=socket.create_connection;original_owner=peer_guard.owner
try:
 save_policy([])
 # The real connect() code is exercised, but its network dial is constrained by
 # this qualification-only harness to counting loopback sinks. Main proxy has no such hook.
 sinks={p:launch_server(proxy.Server,('127.0.0.1',0),Sink,destination_port=p) for p in (80,443,1119)}
 def fixture_dial(address,*args,**kwargs):
  if address[0]!='1.1.1.1' or address[1] not in sinks:raise RuntimeError('unexpected_test_destination')
  with LOCK:COUNTER['dial_attempts']+=1
  return original_dial(('127.0.0.1',sinks[address[1]].server_address[1]),*args,**kwargs)
 socket.create_connection=fixture_dial
 config=proxy.validated_config({'hosts':{h:['1.1.1.1'] for h in proxy.HOSTS},'port':18731,'seconds':300,'log':str(LOG),'peer_policy':str(POLICY),'transparent':True})
 bindings={}
 for family,cls,ip in [('ipv4',proxy.Server,'127.0.0.1'),('ipv6',proxy.IPv6Server,'::1')]:
  for proto,port,handler in [('http',80,proxy.Handler),('version_http',1119,proxy.Handler),('tls',443,proxy.TransparentTLSHandler)]:
   bindings[family,proto]=launch_server(cls,(ip,0),handler,config,port)
 def case(family,mode,decision,policy_variant='normal',revoke=False,lookup_fault=False):
  key=uuid.uuid4().hex;ready=ROOT/(key+'.ready');go=ROOT/(key+'.go');binding_mode='http' if mode.startswith('connect') else mode
  s=bindings[family,binding_mode];ip=s.server_address[0];before=counters();p=None
  try:
   p=subprocess.Popen([str(EXE),mode,ip,str(s.server_address[1]),str(ready),str(go)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
   wait_file(ready);identity=json.loads(ready.read_text(encoding='utf-8-sig'));entry=dict(identity)
   if policy_variant=='wrong_pid':entry['pid']+=1
   if policy_variant=='wrong_creation':entry['created']+=1
   if policy_variant=='wrong_image':entry['image']=str(ROOT/'not-the-peer.exe')
   rows=[] if decision=='deny' and policy_variant=='normal' and not lookup_fault and not revoke else [entry]
   save_policy(rows,expired=policy_variant=='expired')
   if lookup_fault:
    def ambiguous(_):raise ValueError('peer_owner_not_unique')
    peer_guard.owner=ambiguous
   go.write_text('go')
   if revoke:
    wait_file(Path(str(ready)+'.paused'));save_policy([]);Path(str(go)+'.continue').write_text('go')
   stdout,_=p.communicate(timeout=20)
   if p.returncode:raise RuntimeError('client_fixture_failed')
   v=json.loads(stdout);time.sleep(.12);after=counters();dial_attempts=after['dial_attempts']-before['dial_attempts'];connections=after['connections']-before['connections'];byte_count=after['bytes']-before['bytes']
   if decision=='allow':passed=(dial_attempts==1 and connections==1 and byte_count>0 and (v['http200'] if mode in ('http','version_http') else v['result']=='fixture_tls_marker'))
   else:passed=(dial_attempts==0 and connections==0 and byte_count==0 and not v['http200'] and (not v['connect200'] or revoke))
   report['cases'].append({'family':family,'mode':mode,'decision':decision,'policy_variant':policy_variant,'revoked_after_connect200':revoke,'owner_lookup_fault_injected':lookup_fault,'upstream_dial_attempts':dial_attempts,'upstream_connections':connections,'upstream_bytes':byte_count,'passed':passed})
   if not passed:raise RuntimeError('peer_admission_assertion_failed')
  finally:
   peer_guard.owner=original_owner;save_policy([])
   if p and p.poll() is None:p.kill();p.communicate(timeout=5)
 for family in ('ipv4','ipv6'):
  for mode in ('http','version_http','tls','connect'):
   case(family,mode,'deny');case(family,mode,'allow')
  for variant in ('wrong_pid','wrong_creation','wrong_image','expired'):case(family,'version_http','deny',variant)
  case(family,'connect_paused','deny',revoke=True)
  case(family,'version_http','deny',lookup_fault=True)
 rows=[json.loads(x) for x in LOG.read_text().splitlines()]
 report['refusal_reasons']=dict(collections.Counter(x['reason'] for x in rows if x['kind']=='refused_or_failed'))
 report['all_negative_zero_upstream']=all(x['upstream_dial_attempts']==x['upstream_connections']==x['upstream_bytes']==0 for x in report['cases'] if x['decision']=='deny')
 report['all_positive_reached_counting_fixture']=all(x['passed'] for x in report['cases'] if x['decision']=='allow')
 report['case_count']=len(report['cases']);report['status']='qualified_loopback_peer_admission_before_forward'
except Exception as exc:report['error_code']=str(exc) if str(exc).replace('_','').isalpha() and len(str(exc))<80 else 'peer_qualification_operation_failed'
finally:
 socket.create_connection=original_dial;peer_guard.owner=original_owner
 for s in SERVERS:s.shutdown();s.server_close()
 RESULT.parent.mkdir(exist_ok=True);RESULT.write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))
if report['status']=='stopped':raise SystemExit(1)
