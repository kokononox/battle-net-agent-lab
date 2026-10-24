"""Explicit scoped policy lab with operation tracing. Never kills its controller."""
from pathlib import Path
import argparse,ctypes,hashlib,json,os,subprocess,sys,time,uuid,zipfile
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import ROOT,safe,atomic,verify,previous_test
# These base-package modules are verified by the pinned original 0.8.1 manifest.
def load_base():
 global build_coexistence_request,https_endpoint,verify_dns
 sys.path[:0]=[str(ROOT/'app'),str(ROOT/'lab')]
 from coexistence import build_coexistence_request
 from https_common import https_endpoint,verify_dns

def read_bounded(path,limit=33554432):
 p=safe(path)
 if p.stat().st_size>limit:raise ValueError('local_report_size_limit')
 return json.loads(p.read_text('utf-8-sig'))
def prior_binding():
 candidates=sorted((ROOT/'private-state/coexistence-jobs').glob('*/result.json'),key=lambda p:p.stat().st_mtime,reverse=True)
 for p in candidates:
  v=read_bounded(p)
  if v.get('read_only') is True:continue
  e=v.get('endpoint',{});cfg=https_endpoint(e.get('https_url'),e.get('address'));binding=previous_test(cfg)
  if binding['previous_report_sha256']!=hashlib.sha256(safe(p).read_bytes()).hexdigest():raise ValueError('previous_report_changed_during_admission')
  return cfg,binding
 raise ValueError('no_previous_081_test_in_this_folder')
def control_binding(cfg,binding):
 candidates=sorted((ROOT/'private-state/control126-jobs').glob('*/result.json'),key=lambda p:p.stat().st_mtime,reverse=True)
 if not candidates:raise ValueError('latest_control126_report_required_in_this_folder')
 p=safe(candidates[0]);r=read_bounded(p,4194304);rows=r.get('rows',[])
 if r.get('schema')!='unifiedfw-control126-result-1' or r.get('completed') is not True or r.get('errors')!=[] or r.get('controller_exit_code')!=0 or r.get('classification',{}).get('outcome')!='all_126_attempts_succeeded' or len(rows)!=126:raise ValueError('latest_control126_not_successful_do_not_fallback_to_older_report')
 if r.get('firewall_mutation_attempted') is not False or r.get('vpn_or_route_changes_attempted') is not False:raise ValueError('control_scope_not_verified')
 endpoint=r.get('endpoint',{})
 if endpoint.get('url')!=cfg['url'] or endpoint.get('address')!=cfg['address'] or endpoint.get('port')!=443:raise ValueError('control_endpoint_changed')
 programs=r.get('programs',[])
 def norm(s):return str(Path(s)).replace('/','\\').casefold()
 expected={role:norm(ROOT/'runtime'/name) for role,name in [('A','python.exe'),('B','pythonw.exe')]}
 if len(programs)!=2 or {p.get('role'):norm(p.get('path','')) for p in programs}!=expected:raise ValueError('control_runtime_paths_changed')
 for program in programs:
  f=ROOT/'runtime'/('python.exe' if program['role']=='A' else 'pythonw.exe')
  if hashlib.sha256(safe(f).read_bytes()).hexdigest()!=program.get('sha256'):raise ValueError('control_runtime_hash_changed')
 expected_rows=[(p,s,i,role) for p in ('baseline','wl_allows','wl_denies','wl_allows_bl_A','wl_allows_bl_B','wl_allows_bl_both','wl_denies_bl_A') for s in ('during_control','after_restore_control') for i,roles in enumerate((('REF','A','B'),('B','A','REF'),('REF','A','B'))) for role in roles]
 if [(r.get('phase'),r.get('control_segment'),r.get('round'),r.get('role')) for r in rows]!=expected_rows:raise ValueError('control_order_invalid')
 if not r.get('controller_pid') or any(row.get('controller_pid')!=r['controller_pid'] for row in rows):raise ValueError('control_reference_identity_invalid')
 for i,row in enumerate(rows):
  if row.get('pacing_sequence')!=i or any(row.get(k) is not True for k in ('probe_valid','connected','tls_verified','handshake_ok')) or row.get('http_status')!=200:raise ValueError('control_rows_not_all_successful')
  if i and (type(row.get('gap_since_previous_probe_ms')) not in (int,float) or not 4000<=row['gap_since_previous_probe_ms']<1e12):raise ValueError('control_pacing_invalid')
 # The initial 0.8.1 test must be exactly the one to which this control was bound.
 # After a trace082 test exists, require manual review instead of silently reusing this old control.
 if r.get('same_path_binding',{}).get('previous_report_sha256')!=binding['previous_report_sha256']:raise ValueError('coexistence_history_changed_after_control; review_latest_result_before_another_test')
 return dict(control_report_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),same_control_endpoint_and_runtime_paths=True,control126_pass_checked=True)
def export(jobs):
 members={}
 for job in jobs:
  for name,limit in [('result.json',33554432),('operation-trace.jsonl',8388608),('stdout.txt',65536),('stderr.txt',65536),('trace-admission.json',1048576)]:
   p=safe(job/name)
   if not p.exists():continue
   if p.stat().st_size>limit:raise ValueError('export_size_limit:'+name)
   members[job.name+'/'+name]=p.read_bytes()
 for name in ('BUILD-INFO.json','TRACE082-BUILD-INFO.json'):members[name]=safe(ROOT/name).read_bytes()
 members['report-sha256.json']=json.dumps({n:hashlib.sha256(v).hexdigest() for n,v in members.items()},indent=2).encode()
 dest=safe(ROOT/('UnifiedFW-Trace082-Results-'+uuid.uuid4().hex[:12]+'.zip'))
 with zipfile.ZipFile(dest,'x',zipfile.ZIP_DEFLATED) as z:
  for name,data in members.items():z.writestr(name,data)
 return dest

def controller(cfg,readonly,jobs,binding,control,dns):
 job=safe(ROOT/'private-state/coexistence-jobs'/uuid.uuid4().hex);job.mkdir(parents=True);jobs.append(job)
 q=build_coexistence_request(cfg['address'],443,https_url=cfg['url']);atomic(job/'request.json',q)
 atomic(job/'trace-admission.json',dict(previous=binding,control=control,dns_ipv4=dns,addon_version='0.8.2-trace-overlay'))
 ps=safe(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
 args=[str(ps),'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(ROOT/'trace082/coexistence-manage.ps1'),'-Request',str(job/'request.json'),'-Output',str(job/'result.json')]
 if readonly:args.append('-ReadOnly')
 with (job/'stdout.txt').open('xb') as stdout,(job/'stderr.txt').open('xb') as stderr:
  process=subprocess.Popen(args,stdout=stdout,stderr=stderr);last=None
  # Never impose an overall deadline, terminate, or retry the firewall controller.
  while process.poll() is None:
   try:
    try:
     progress=read_bounded(job/'result.json').get('progress')
     if progress!=last:print('Progress:',progress,flush=True);last=progress
    except (OSError,ValueError):pass
    time.sleep(1)
   except KeyboardInterrupt:print('Do NOT close this window. Waiting for controller and its Restore; no automatic kill or restart.',flush=True)
 if not (job/'result.json').exists():raise ValueError('result_missing_session_status_unknown; use_original_Open_Lab_RESTORE_not_blind_reapply')
 r=read_bounded(job/'result.json');print('Controller exit:',process.returncode,'Outcome:',r.get('classification',{}).get('outcome'),'Restore:',r.get('restore_verified'),'Trace:',r.get('instrumentation',{}).get('trace_write_ok'),flush=True)
 return r,process.returncode

def run(mode):
 verify();load_base()
 if os.name!='nt' or not ctypes.windll.shell32.IsUserAnAdmin():raise ValueError('explicit_Run_as_administrator_on_Windows_required')
 if os.environ.get('SESSIONNAME','').upper().startswith('RDP'):raise ValueError('local_console_required_not_RDP')
 cfg,binding=prior_binding();control=control_binding(cfg,binding);dns=verify_dns(cfg)
 print('Trace082 scoped coexistence LAB. NOT a production GUI or no-leak certification.')
 print('Original 0.8.1 core, runtime paths, TLS, rule scope, pacing and timeouts retained.')
 print('Trace file contains local paths/IPs/profile details through result rows; review before sharing.')
 print('Endpoint from your tested package:',cfg['url'],cfg['address'])
 jobs=[]
 try:
  print('Running READ-ONLY route/config preflight. No endpoint requests or new rules in this stage.')
  pre,code=controller(cfg,True,jobs,binding,control,dns)
  if code or not pre.get('completed') or pre.get('classification',{}).get('outcome')!='ready_for_scoped_test' or pre.get('instrumentation',{}).get('trace_write_ok') is not True:raise ValueError('preflight_not_ready; full_test_not_started')
  if mode=='preflight':return 0
  print('PRE-FLIGHT PASSED. Next stage temporarily creates scoped Block rules for only the TWO bundled EXEs, ONE IPv4, TCP443.')
  print('Maximum 126 attempts; 4-second gaps; no retries. Usually 10-15 minutes, can take longer. Keep VPN and window open; no parallel labs.')
  print('Strict owned-image Restore only. Never force-delete or remove journals. Logging cannot guarantee recovery after power loss or forced close.')
  if input('If this endpoint is yours and active, type TEST SCOPED TRACE: ')!='TEST SCOPED TRACE':raise ValueError('cancelled_no_full_test_rules')
  r,code=controller(cfg,False,jobs,binding,control,dns)
  return 0 if code==0 and r.get('completed') is True and r.get('restore_verified') is True and r.get('classification',{}).get('outcome')=='passed' and r.get('instrumentation',{}).get('trace_write_ok') is True else 1
 finally:
  if jobs:print('REPORT ZIP:',export(jobs),flush=True)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--mode',choices=['preflight','test'],required=True);a=p.parse_args()
 try:code=run(a.mode)
 except Exception as e:print('ERROR:',e);code=1
 input('Press Enter to close. ');raise SystemExit(code)
