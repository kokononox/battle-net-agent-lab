import json
import os
from pathlib import Path
import re
import sys
import threading

def main():
 if sys.platform!='win32' or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_OS')!='Windows' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.environ.get('GITHUB_RUN_ATTEMPT')!='1' or os.environ.get('PRIVACY_TLS_ONCE')!='tls-20261018-d2':raise SystemExit('fresh_hosted_once_required')
 root=Path(__file__).resolve().parents[1];sys.path.insert(0,str(root/'privacy-network'));sys.path.insert(0,str(root/'scripts'))
 import observe_agent as obs
 import native_tcp
 import frida
 from packet_meta import host
 from monitor import Monitor
 from selftest import run_selftest
 import harness
 run=os.environ.get('GITHUB_RUN_ID','');source=os.environ.get('GITHUB_SHA','')
 if not run.isdigit() or not re.fullmatch('[a-f0-9]{40}',source):raise SystemExit('identity')
 report={'schema':'bnet-live-tls-buffer-observation-1','source_commit':source,'run_id':run,'scope':'fresh_vm_startup_no_login_game_or_install_action','tool_version':frida.__version__,'selftest':{'passed':False,'stage':'not_started','loopback_only':True,'synthetic_events_excluded_from_real_evidence':True},'bootstrap_pin_match':None,'processes':[],'events':[],'monitor_stats':{'snapshots':0,'errors':0,'process_limit_hit':False,'dropped_events':0},'status':'not_started','error_code':None,
 'limits':{'raw_values_headers_bodies_exported':False,'paths_exported':False,'tls_verification_changed':False,'api_results_or_buffers_modified':False,'plaintext_is_api_input_not_proof_of_delivery':True,'field_names_are_hints_not_hardware_value_proof':True,'only_known_exported_apis_observed':True,'late_attach_and_event_caps_can_miss_data':True,'loaded_module_not_proof_of_use':True,'instrumentation_can_change_timing_or_behavior':True,'full_update_or_transfer_test':False}}
 out=Path('output');out.mkdir(exist_ok=True);monitor=None;thread=None
 original_fetch=obs.fetch_setup
 def pinned_fetch(destination):
  result=original_fetch(destination);report['bootstrap_pin_match']=result['sha256']=='de5d32d4ea5eed5a9e120027fb68b370976dbfecc8f2a8f91305977f0b87fcaf'
  if not report['bootstrap_pin_match']:
   destination.unlink(missing_ok=True);raise obs.LabError('bootstrap_pin_mismatch_refused')
  return result
 obs.fetch_setup=pinned_fetch
 try:
  if frida.__version__!='17.24.2':raise obs.LabError('tool_version_mismatch')
  report['selftest']=run_selftest(frida,obs.clean_environment(os.environ))
  if not report['selftest']['passed']:raise obs.LabError('owned_loopback_selftest_failed')
  monitor=Monitor(obs,native_tcp.snapshot,frida,host);thread=threading.Thread(target=monitor.run,daemon=True);thread.start()
  harness.main();report['status']='collector_returned'
 except Exception as exc:
  report['status']='stopped';report['error_code']=str(exc) if isinstance(exc,obs.LabError) and re.fullmatch('[a-z0-9_]{1,100}',str(exc)) else 'bounded_instrumentation_failed'
 finally:
  if monitor is not None:
   monitor.stop.set()
   if thread is not None:thread.join(timeout=30)
   if thread is not None and thread.is_alive():report['status']='stopped';report['error_code']='monitor_stop_timeout'
   monitor.finish();report.update(monitor.result())
  data=json.dumps(report,indent=2).encode()
  if len(data)>1024*1024:raise SystemExit('report_limit')
  (out/'live-tls-metadata.json').write_bytes(data)
 print(json.dumps({'status':report['status'],'processes':len(report['processes']),'buffer_events':len(report['events']),'selftest_passed':report['selftest']['passed']}))
if __name__=='__main__':main()
