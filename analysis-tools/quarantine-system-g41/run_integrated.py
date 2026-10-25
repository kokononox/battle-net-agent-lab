"""Synthetic finish/cancel/controller-crash integration. Fixed canary, no payload."""
import argparse,base64,ctypes as C,hashlib,ipaddress,json,os,socket,subprocess,sys,time,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import ROOT,context,save,read,wait_file
from windows_store import WindowsStore
from coordinator import clean_env
import native as n

def probe(ip):
 try:
  with socket.create_connection((ip,443),3):return True
 except OSError:return False

def ensure_watchdog_exit(c):
 who=c.get('watchdog_identity')
 if not who:return False
 h=n.K.OpenProcess(0x1000|0x100000,False,who['pid'])
 if not h:return True
 try:
  from ctypes import wintypes as W
  ft=W.FILETIME();other=[W.FILETIME() for _ in range(3)]
  if not n.K.GetProcessTimes(h,C.byref(ft),*[C.byref(v) for v in other]):return False
  if ((ft.dwHighDateTime<<32)|ft.dwLowDateTime)!=who['created']:return True
  return n.K.WaitForSingleObject(h,15000)==0
 finally:n.K.CloseHandle(h)

def fallback(pointer):
 roots=read(pointer).get('roots',[]) if Path(pointer).exists() else []
 okay=True
 for root in roots:
  try:
   c=context(root)
   from recovery import recover
   result=recover(c,'fallback');okay=okay and result['firewall_restored'] and result['job_active_zero']
  except Exception:okay=False
 return okay

def run(report,pointer):
 if os.name!='nt' or os.environ.get('BNET_G41')!='lab: approved synthetic system isolation G41' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':raise RuntimeError('fresh_hosted_required')
 evidence={'schema':'quarantine_system_g41_v1','source_commit':os.environ.get('GITHUB_SHA'),'run_id':os.environ.get('GITHUB_RUN_ID'),'status':'incomplete','scenarios':[],'canary_host':'us.version.battle.net','canary_port':443,'canary_application_payload_sent':False,'installer_executed':False,'battlenet_payload_downloaded':False,'private_captures_published':False,'management_exceptions_are_ci_only':True,'original_production_recovery_changed':False,'error_code':None}
 roots=[];save(pointer,{'roots':roots})
 try:
  ips=sorted({x[4][0] for x in socket.getaddrinfo('us.version.battle.net',443,socket.AF_INET,socket.SOCK_STREAM) if ipaddress.ip_address(x[4][0]).is_global})
  ip=next((candidate for candidate in ips[:8] if probe(candidate)),None)
  if ip is None:raise RuntimeError('healthy_canary_unavailable')
  for mode in ('finish','cancel','error'):
   root=Path(os.environ['ProgramData'])/'BNetOnlineG41'/uuid.uuid4().hex
   helper=os.environ['G41_STORE_HELPER'];WindowsStore(root/'quarantine',helper)
   c={'root':str(root),'job_name':'Global\\BNetOnlineG41_'+root.name,'mode':mode,'canary_ip':ip,'helper':helper}
   save(root/'config.json',c);roots.append(str(root));save(pointer,{'roots':roots})
   child=subprocess.Popen([sys.executable,'-I',str(ROOT/'coordinator.py'),str(root)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=clean_env())
   code=child.wait(timeout=240)
   case=wait_file(root/'case-result.json',5);recovered=wait_file(root/'recovery-result.json',170)
   watchdog_exit=ensure_watchdog_exit(context(root));post=probe(ip)
   row={'mode':mode,'coordinator_exit_code':code,'case':case,'recovery':recovered,'watchdog_exited':watchdog_exit,'post_restore_connected':post}
   row['passed']=(code==(23 if mode=='error' else 0) and case['error_code'] is None and case['baseline_connected'] and case['blocked_connected'] is False and case['gate_before'] and case['gate_after'] and case['fixture_alive_during_gate'] and case['capture_blocked'] and case['private_capture_stored'] and case['private_marker_retained'] and case['public_marker_absent'] and case['credential_redacted'] and recovered['job_active_zero'] and recovered['firewall_restored'] and recovered['fingerprint_match'] and recovered['active_before_termination']>0 and recovered['reason']==('controller_exit' if mode=='error' else mode) and watchdog_exit and post)
   evidence['scenarios'].append(row)
   if not row['passed']:raise RuntimeError('integration_case_failed')
  evidence['status']='three_synthetic_scenarios_verified'
 except Exception as exc:
  text=str(exc);evidence['error_code']=text if text.replace('_','').isalpha() and len(text)<80 else 'integration_failed'
 finally:
  evidence['fallback_scoped_recovery_ok']=fallback(pointer)
  evidence['source_sha256']={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(ROOT.iterdir()) if f.is_file()}
  save(report,evidence)
  print('G41_EVIDENCE_B64='+base64.b64encode(json.dumps(evidence,separators=(',',':')).encode()).decode())
 return evidence['status']=='three_synthetic_scenarios_verified' and evidence['fallback_scoped_recovery_ok']
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--report',type=Path,default=Path('output/g41-evidence.json'));p.add_argument('--pointer',type=Path,default=Path('output/g41-private-pointer.json'));p.add_argument('--fallback-only',action='store_true');a=p.parse_args()
 if a.fallback_only:raise SystemExit(0 if fallback(a.pointer) else 2)
 raise SystemExit(0 if run(a.report,a.pointer) else 2)
