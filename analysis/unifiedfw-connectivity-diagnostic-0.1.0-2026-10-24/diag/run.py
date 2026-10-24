"""18 sequential authorized attempts, 4 seconds between attempts; no policy API."""
from pathlib import Path
import datetime,hashlib,json,os,subprocess,sys,time,uuid,zipfile
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import ROOT,safe,atomic,verify
from https_common import https_endpoint,verify_dns
ROUNDS=6
GAP=4

def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def orders():
 return [('A','B','REF'),('B','REF','A'),('REF','A','B')]*2

def summarize(rows,completed):
 out={}
 for role in ('A','B','REF'):
  rs=[r for r in rows if r.get('role')==role]
  out[role]={'attempts':len(rs),'valid_echoes':sum(r.get('handshake_ok') is True and r.get('probe_valid') is True for r in rs),'failures':[{'round':r['round'],'stage':r.get('stage'),'error':r.get('error'),'error_code':r.get('error_code')} for r in rs if not r.get('handshake_ok') or not r.get('probe_valid')]}
 expected=[(i,role) for i,roles in enumerate(orders()) for role in roles]
 actual=[(r.get('round'),r.get('role')) for r in rows]
 good=completed and actual==expected and all(r.get('probe_valid') is True and r.get('handshake_ok') is True and r.get('connected') is True and r.get('tls_verified') is True and r.get('http_status')==200 for r in rows)
 return {'outcome':'all_18_attempts_succeeded' if good else 'incomplete_or_failures_observed','roles':out,'not_a_firewall_or_VPN_acceptance_test':True}

def child(role,req,out):
 if role=='REF':
  ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
  return [str(ps),'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(ROOT/'diag/reference.ps1'),'-Request',str(req),'-Output',str(out)]
 return [str(ROOT/'runtime'/('python.exe' if role=='A' else 'pythonw.exe')),'-I',str(ROOT/'diag/probe.py'),'--request',str(req),'--output',str(out)]

def export(job,report):
 target=safe(ROOT/('UnifiedFW-Connectivity-Results-'+job.name[:12]+'.zip'))
 parts={'result.json':json.dumps(report,ensure_ascii=False,indent=2).encode(),'BUILD-INFO.json':(ROOT/'BUILD-INFO.json').read_bytes()}
 hashes={n:hashlib.sha256(v).hexdigest() for n,v in parts.items()}
 with zipfile.ZipFile(target,'x',zipfile.ZIP_DEFLATED) as z:
  for n,v in parts.items():z.writestr(n,v)
  z.writestr('report-sha256.json',json.dumps(hashes,indent=2))
 return target

def run():
 verify()
 if os.name!='nt':raise ValueError('Windows_required')
 print('Connectivity Diagnostic 0.1.0: NO firewall, VPN or route changes. No administrator needed.')
 print('Run time usually 1-3 minutes, worst case about 8 minutes. No background service.');print('18 sequential fresh HTTPS connections; 4-second gaps; same 3-second TCP budget as 0.8.0. No retries.')
 print('Keep VPN state unchanged. Do not run other lab tests in parallel. Ctrl+C stops diagnostics safely.')
 url=input('Full HTTPS PHP URL: ').strip();address=input('Selected public IPv4: ').strip();cfg=https_endpoint(url,address)
 label=input('Current VPN state (type ON or OFF; tool will not change it): ').strip()
 if label not in ('ON','OFF'):raise ValueError('VPN_label_ON_or_OFF_required')
 if input('Type I CONTROL THIS TEST ENDPOINT: ')!='I CONTROL THIS TEST ENDPOINT':raise ValueError('cancelled')
 state=safe(ROOT/'private-state');state.mkdir(exist_ok=True)
 lock=(state/'diagnostic.lock').open('a+b')
 import msvcrt
 lock.seek(0,2)
 if lock.tell()==0:lock.write(b'0');lock.flush()
 lock.seek(0)
 try:msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
 except OSError:lock.close();raise ValueError('another_diagnostic_is_running')
 job=safe(state/'jobs'/uuid.uuid4().hex);job.mkdir(parents=True)
 report={'schema':'unifiedfw-connectivity-diagnostic-1','started_utc':utc(),'endpoint':cfg,'vpn_state_user_label':label,'completed':False,'rows':[],'errors':[],'firewall_mutation_attempted':False,'vpn_or_route_changes_attempted':False,'protection_verified':False,'planned_attempts':18,'gap_seconds':GAP,'automatic_retries':0,'tcp_connect_timeout_seconds':3,'per_child_deadline_seconds':20,'independent_reference_process':'Windows PowerShell .NET SslStream; default certificate validation'}
 try:
  report['programs']=[{'role':role,'path':str(ROOT/'runtime'/name),'sha256':hashlib.sha256((ROOT/'runtime'/name).read_bytes()).hexdigest()} for role,name in [('A','python.exe'),('B','pythonw.exe')]]
  report['dns_ipv4']=verify_dns(cfg);atomic(job/'result.json',report)
  for i,roles in enumerate(orders()):
   for role in roles:
    q={'url':url,'address':address,'challenge':{'kind':'unifiedfw-traffic-1','nonce':uuid.uuid4().hex+uuid.uuid4().hex,'request_id':uuid.uuid4().hex,'role':role}}
    stem=q['challenge']['request_id'];req=job/(stem+'-request.json');out=job/(stem+'-probe.json');atomic(req,q)
    started=utc();clock=time.monotonic()
    cp=None
    try:
     cp=subprocess.run(child(role,req,out),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
     if cp.returncode!=0 or not out.is_file() or out.stat().st_size>16384:raise ValueError('child_execution_or_output_failure; see_local_stderr')
     row=json.loads(out.read_text('utf-8-sig'))
     if row.get('request_id')!=stem or row.get('role')!=role:raise ValueError('child_response_identity')
     if cp.stderr:(job/(stem+'-stderr.txt')).write_bytes(cp.stderr[:16384])
    except (OSError,ValueError,subprocess.TimeoutExpired) as e:
     if cp is not None and cp.stderr:(job/(stem+'-stderr.txt')).write_bytes(cp.stderr[:16384])
     row={'role':role,'request_id':stem,'probe_valid':False,'connected':False,'tls_verified':False,'handshake_ok':False,'stage':'child_execution','error':str(e)[:250],'error_code':None,'child_stderr_excerpt':cp.stderr.decode('utf-8','replace')[-2048:] if cp is not None else None}
    row.update(round=i,started_utc=started,ended_utc=utc(),child_wall_ms=round((time.monotonic()-clock)*1000,1));report['rows'].append(row)
    atomic(job/'result.json',report)
    print(str(len(report['rows']))+'/18',role,'OK' if row.get('handshake_ok') else 'FAIL',row.get('stage'),row.get('error') or '',flush=True)
    if len(report['rows'])<18:time.sleep(GAP)
  report['completed']=True
 except KeyboardInterrupt:report['errors'].append('user_interrupted_diagnostic_no_rules_to_restore')
 except Exception as e:report['errors'].append(type(e).__name__+':'+str(e)[:300])
 finally:
  report['ended_utc']=utc();report['classification']=summarize(report['rows'],report['completed']);atomic(job/'result.json',report)
  print(json.dumps(report['classification'],indent=2));print('REPORT ZIP:',export(job,report),flush=True)
  lock.seek(0);msvcrt.locking(lock.fileno(),msvcrt.LK_UNLCK,1);lock.close()
 return 0 if report['classification']['outcome']=='all_18_attempts_succeeded' else 1
if __name__=='__main__':
 try:code=run()
 except Exception as e:print('ERROR:',e);code=1
 input('Press Enter to close. ');raise SystemExit(code)
