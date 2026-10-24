"""Bounded 126-probe no-policy control. One long-lived PowerShell REF process."""
from pathlib import Path
import datetime,hashlib,json,os,subprocess,sys,uuid,zipfile
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import ROOT,safe,atomic,verify,previous_test
from https_common import https_endpoint,verify_dns
PHASES=('baseline','wl_allows','wl_denies','wl_allows_bl_A','wl_allows_bl_B','wl_allows_bl_both','wl_denies_bl_A')
SEGMENTS=('during_control','after_restore_control')
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def schedule():
 return [(p,s,r,role) for p in PHASES for s in SEGMENTS for r,roles in enumerate((('REF','A','B'),('B','A','REF'),('REF','A','B'))) for role in roles]
def summarize(report):
 rows=report.get('rows',[]);problems=[]
 if report.get('completed') is not True or report.get('errors'):problems.append('run_incomplete_or_controller_error')
 if [(r.get('phase'),r.get('control_segment'),r.get('round'),r.get('role')) for r in rows]!=schedule():problems.append('schedule_or_count_mismatch')
 if [r.get('pacing_sequence') for r in rows]!=list(range(126)):problems.append('sequence_mismatch')
 if rows and rows[0].get('gap_since_previous_probe_ms') is not None:problems.append('unexpected_first_gap')
 for r in rows[1:]:
  gap=r.get('gap_since_previous_probe_ms')
  if type(gap) not in (int,float) or not 4000<=gap<86400000:problems.append('pacing_not_verified');break
 if not report.get('controller_pid') or any(r.get('controller_pid')!=report['controller_pid'] for r in rows):problems.append('controller_identity_mismatch')
 failures=[{'sequence':r.get('pacing_sequence'),'phase':r.get('phase'),'segment':r.get('control_segment'),'round':r.get('round'),'role':r.get('role'),'stage':r.get('stage'),'error':r.get('error'),'error_code':r.get('error_code')} for r in rows if not (r.get('probe_valid') is True and r.get('connected') is True and r.get('tls_verified') is True and r.get('handshake_ok') is True and type(r.get('http_status')) is int and r.get('http_status')==200)]
 if failures:problems.append('allowed_probe_failures')
 return dict(outcome='all_126_attempts_succeeded' if not problems else 'incomplete_or_failures_observed',validation_problems=problems,failures=failures,attempts_by_role={role:sum(r.get('role')==role for r in rows) for role in ('A','B','REF')},not_a_firewall_or_VPN_acceptance_test=True)
def endpoint_from_latest():
 candidates=sorted((ROOT/'private-state/coexistence-jobs').glob('*/result.json'),key=lambda p:p.stat().st_mtime,reverse=True)
 for p in candidates:
  p=safe(p)
  if p.stat().st_size>33554432:raise ValueError('previous_result_size_limit')
  v=json.loads(p.read_text('utf-8-sig'))
  if v.get('read_only') is True:continue
  e=v.get('endpoint',{});cfg=https_endpoint(e.get('https_url'),e.get('address'))
  binding=previous_test(cfg)
  if binding['previous_report_sha256']!=hashlib.sha256(p.read_bytes()).hexdigest():raise ValueError('previous_report_changed_during_admission')
  return cfg,binding
 raise ValueError('no_previous_081_test_in_this_folder')
def export(job,report):
 target=safe(ROOT/('UnifiedFW-Control126-Results-'+job.name[:12]+'.zip'))
 parts={'result.json':json.dumps(report,ensure_ascii=False,indent=2).encode(),'BUILD-INFO.json':(ROOT/'BUILD-INFO.json').read_bytes(),'CONTROL126-BUILD-INFO.json':(ROOT/'CONTROL126-BUILD-INFO.json').read_bytes()}
 with zipfile.ZipFile(target,'x',zipfile.ZIP_DEFLATED) as z:
  for name,value in parts.items():z.writestr(name,value)
  z.writestr('report-sha256.json',json.dumps({n:hashlib.sha256(v).hexdigest() for n,v in parts.items()},indent=2))
 return target

def run():
 verify()
 if os.name!='nt':raise ValueError('Windows_required')
 cfg,binding=endpoint_from_latest()
 print('CONTROL 126 - NO firewall, VPN, route, hosts or trust changes. No administrator needed.')
 print('Same original 0.8.1 runtime paths; 126 sequential attempts; one long-lived PowerShell REF.')
 print('4-second end-to-start gaps; 3-second TCP budget; zero retries. Usually 10-15 minutes; failures may make it longer.')
 print('Do NOT run other labs or change VPN/policy during this test. This is not a no-leak or protection test.')
 print('Endpoint from your latest restored test:',cfg['url'],cfg['address'])
 print('Previous Restore is a historical record, NOT a live policy check. Endpoint must still be active.')
 if input('If this is your endpoint and VPN remains unchanged, type START: ').strip()!='START':raise ValueError('cancelled')
 state=safe(ROOT/'private-state');state.mkdir(exist_ok=True)
 lock=safe(state/'control126.lock').open('a+b')
 import msvcrt
 lock.seek(0,2)
 if lock.tell()==0:lock.write(b'0');lock.flush()
 lock.seek(0)
 try:msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
 except OSError:lock.close();raise ValueError('another_control126_is_running')
 job=safe(state/'control126-jobs'/uuid.uuid4().hex);job.mkdir(parents=True)
 report={'schema':'unifiedfw-control126-result-1','started_utc':utc(),'completed':False,'rows':[],'errors':[],'firewall_mutation_attempted':False,'vpn_or_route_changes_attempted':False,'protection_verified':False}
 child=None
 try:
  dns=verify_dns(cfg)
  programs=[dict(role=r,path=str(safe(ROOT/'runtime'/n)),sha256=hashlib.sha256(safe(ROOT/'runtime'/n).read_bytes()).hexdigest()) for r,n in [('A','python.exe'),('B','pythonw.exe')]]
  q=dict(schema='unifiedfw-control126-request-1',https_url=cfg['url'],address=cfg['address'],programs=programs)
  req=job/'request.json';out=job/'controller-result.json';atomic(req,q)
  ps=safe(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
  # Deliberately no overall deadline/automatic kill. Each A/B child retains the original 12s budget.
  cmd=[str(ps),'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(ROOT/'control126/controller.ps1'),'-Request',str(req),'-Output',str(out)]
  interrupted=False
  try:
   child=subprocess.Popen(cmd);rc=child.wait()
  except KeyboardInterrupt:
   interrupted=True
   # Console Ctrl+C is shared with the controller; let it flush its finally block.
   try:rc=child.wait(timeout=15)
   except subprocess.TimeoutExpired:
    child.terminate();rc=child.wait()
  if out.is_file() and out.stat().st_size<=4194304:report=json.loads(out.read_text('utf-8-sig'))
  else:report['errors'].append('controller_output_missing_or_oversized')
  report.update(same_path_binding=binding,dns_ipv4=dns,controller_exit_code=rc,vpn_state_user_assertion='unchanged',comparability_limits=['No native Apply/Restore or policy inventory delays','No live route observation or packet capture','Elevation is not requested; effective controller elevation is recorded and may differ from prior admin lab','All 126 connections expected allowed; no block rules','Same count/order/runtime paths/transport budgets/REF process lifetime; not an identical causal experiment'])
  if interrupted:report['completed']=False;report['errors'].append('user_interrupted_no_rules_to_restore')
  if rc!=0:report['errors'].append('controller_nonzero_exit')
 except Exception as e:report['completed']=False;report['errors'].append(type(e).__name__+':'+str(e)[:300])
 finally:
  report['exported_utc']=utc();report['classification']=summarize(report);atomic(job/'result.json',report)
  try:
   print(json.dumps(report['classification'],indent=2));print('REPORT ZIP:',export(job,report),flush=True)
  finally:lock.seek(0);msvcrt.locking(lock.fileno(),msvcrt.LK_UNLCK,1);lock.close()
 return 0 if report['classification']['outcome']=='all_126_attempts_succeeded' else 1
if __name__=='__main__':
 try:code=run()
 except Exception as e:print('ERROR:',e);code=1
 input('Press Enter to close. ');raise SystemExit(code)
