"""One bounded observation of the current Level3-only whitelist. No policy setters."""
import ctypes,datetime,hashlib,json,os,re,subprocess,sys,time
from pathlib import Path
from safepaths import safe_path
BASE=Path(__file__).resolve().parents[1]

def integrity():
 m=json.loads((BASE/'MANIFEST-SHA256.json').read_text())
 if not isinstance(m,dict) or len(m)>4096:raise ValueError('manifest_invalid')
 for name,h in m.items():
  if not re.fullmatch(r'[A-Za-z0-9_./-]{1,220}',name) or '..' in name.split('/') or name.startswith('/'):raise ValueError('manifest_path')
  p=safe_path(BASE/name)
  if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=h:raise ValueError('package_integrity_failed')

def mutex():
 k=ctypes.WinDLL('kernel32',use_last_error=True)
 k.CreateMutexW.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_wchar_p];k.CreateMutexW.restype=ctypes.c_void_p
 h=k.CreateMutexW(None,False,'Global\\LocalRetailPrivacyObserverU1')
 if not h or ctypes.get_last_error()==183:raise ValueError('another_observer_running')
 return h

def compile_helper():
 app=safe_path(BASE/'app');source=app/'authenticode_native.cs';entry=app/'authverify_entry.cs'
 dest=safe_path(app/'AuthVerify.exe')
 # Always compile the packaged sources; never trust an unrelated preexisting EXE.
 if dest.exists():dest.unlink()
 exe=safe_path(Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe')
 r=subprocess.run([str(exe),'/nologo','/target:exe','/platform:x64','/out:'+str(dest),str(source),str(entry)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40,creationflags=0x08000000)
 if r.returncode or not dest.exists():raise ValueError('native_helper_compile_failed')
 # Native verifier must refuse this unsigned owned executable.
 from core import signature
 sig=signature(dest)
 if sig['valid'] or sig['blizzard']:raise ValueError('native_verifier_negative_control_failed')
 return {'compiled_locally':True,'negative_unsigned_control_passed':True,'positive_blizzard_test':'checked_per_target_before_attach','sha256':hashlib.sha256(dest.read_bytes()).hexdigest()}

def save(report):
 out=safe_path(BASE/'output');out.mkdir(exist_ok=True)
 raw=(json.dumps(report,ensure_ascii=True,indent=2)+'\n').encode()
 if len(raw)>8*1024**2:raise ValueError('report_size_limit')
 path=safe_path(out/('content-result-'+str(time.time_ns())+'.json'))
 with path.open('xb') as f:f.write(raw)
 print('\nREPORT:',str(path))
 print('Send only this JSON. No automatic upload occurred.')

def main():
 report={'schema':'level3-content-check-1','version':'0.1.3','started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'preflight','error_code':None,'native_helper':None,'native_selftest':None,'state_before':None,'policy_before':None,'state_after':None,'policy_after':None,'state_unchanged_at_endpoints':None,'policy_unchanged_at_endpoints':None,'hardware_reference_categories_available':[],'ready_announced':False,'user_resume_marker':False,'user_final_state':'not_recorded','observation':None,'audit':None,'findings':None,'limits':{'passive_not_prevention':True,'zero_hardware_transmission_proven':False,'only_download_proven':False,'no_firewall_hosts_dns_vpn_or_tls_settings_changed':True,'no_online_dns_lookup_requested':True,'no_game_files_read_or_written':True,'no_blizzard_processes_launched_paused_or_terminated':True,'no_service_task_or_resident_component_installed':True,'all_programs_all_interfaces_audited':False,'udp_http2_quic_custom_tls_fully_covered':False,'signature_checks_may_contact_certificate_services':True,'pre_tls_sspi_not_bound_to_remote_ip':True,'late_attach_first_requests_may_be_missed':True,'sampling_can_miss_connections':True,'literal_or_key_absence_not_absence_of_hardware_data':True,'local_api_acceptance_not_server_receipt':True,'raw_payloads_header_values_urls_tls_keys_exported':False,'ram_paging_or_zeroization_guaranteed':False,'concurrent_stream_order_and_tls_context_reuse_not_fully_tracked':True,'endpoint_policy_comparison_not_continuous_proof':True,'injection_can_affect_stability_and_timing':True,'automatic_update_pause_on_exit':False,'native_windows_qualification_completed_by_builder':False}}
 c=None;refs={};lock=None
 try:
  if sys.platform!='win32' or ctypes.sizeof(ctypes.c_void_p)!=8:raise ValueError('windows_x64_required')
  if not ctypes.windll.shell32.IsUserAnAdmin():raise ValueError('run_start_as_administrator')
  lock=mutex();integrity()
  from core import NAMES,WOW,snapshot
  if snapshot(NAMES|WOW)['processes']:raise ValueError('close_battlenet_agent_and_game_then_retry')
  print('Level3 Content Check 0.1.3 - OBSERVE ONLY, NOT A PRIVACY FIREWALL.')
  print('Keep the existing whitelist APPLIED. No DNS/firewall/hosts change will be made.')
  print('Read-only hooks can affect stability. Keep WoW CLOSED and automatic updates OFF.')
  print('Actual CPU/BIOS values are matched in memory, not included in the report.')
  print('This test does NOT prevent a first disclosure. Certificate validation may use the network.')
  if input('Confirm update paused, backup available, game closed, and accept observation: type START: ').strip()!='START':
   report['status']='cancelled';return
  from policy import state,policy_snapshot
  report['state_before']=state();report['policy_before']=policy_snapshot(report['state_before'])
  print('Active Level3-domain + configured-IP snapshot found. Rule complements match stored IPs.')
  if report['state_before']['configured_manual_ips']:
   print('Manual IPs:',len(report['state_before']['configured_manual_ips']),'- domain ownership NOT verified; no DNS refresh performed.')
  print('This is NOT certification of outside-VPN protection or the full firewall policy.')
  report['native_helper']=compile_helper()
  import frida
  if frida.__version__!='17.24.2':raise ValueError('unexpected_frida_version')
  from native_selftest import run
  print('Running owned-loopback hook/content/destination self-test...')
  report['native_selftest']=run(frida)
  if not report['native_selftest']['passed']:raise ValueError('native_loopback_selftest_failed_do_not_resume')
  # Self-test has no TLS/SSPI positive control: never report full TLS coverage.
  if snapshot(NAMES|WOW)['processes']:raise ValueError('processes_opened_before_observer_ready_retry')
  from hardware import references
  from observer import ContentCollector,findings
  refs=references();report['hardware_reference_categories_available']=sorted(refs)
  c=ContentCollector(frida,refs);c.start();report['status']='waiting_for_agent'
  print('\nOpen Battle.net manually now. Stay signed out if the updater allows it. Keep update PAUSED.')
  print('Wait for READY here before resuming. Timeout 180 seconds. Do NOT launch the game.')
  deadline=time.monotonic()+180
  while time.monotonic()<deadline and not c.ready():
   if snapshot(WOW)['processes']:raise ValueError('game_running_stop_observation')
   time.sleep(.5)
  if not c.ready():raise ValueError('agent_hooks_not_ready_do_not_resume')
  report['ready_announced']=True
  print('\nREADY - partial observation only, not proof of no telemetry.')
  print('Resume the update manually, then return here and press Enter to mark the test window.')
  ans=input('Enter after Resume, or Q to stop without a test window: ').strip().lower()
  if ans=='q':report['status']='cancelled_after_attach';return
  report['user_resume_marker']=True;c.phase='after_user_resume_marker';report['status']='observing'
  print('Observe about 60 seconds, then PAUSE the update yourself and press Q here.')
  print('Maximum observation: 120 seconds. Timer/Q stops observation ONLY, NOT the update.')
  import msvcrt
  deadline=time.monotonic()+120;next_check=0
  while time.monotonic()<deadline:
   if msvcrt.kbhit() and msvcrt.getwch().lower()=='q':report['end_reason']='user_q';break
   if time.monotonic()>=next_check:
    if snapshot(WOW)['processes']:raise ValueError('game_running_observer_stopping')
    next_check=time.monotonic()+2
   time.sleep(.1)
  else:report['end_reason']='observation_time_limit'
  c.close();report['status']='observation_ended'
  print('Observation ended. It did NOT pause the update. Pause it manually now if still running.')
  report['user_final_state']={'1':'reported_paused','2':'reported_finished','3':'reported_error'}.get(input('State: 1 Paused, 2 Finished, 3 Error, other Unknown: ').strip(),'unknown')
 except KeyboardInterrupt:report['status']='interrupted';report['error_code']='user_interrupted'
 except Exception as e:
  if hasattr(e,'diagnostic'):report['policy_read_diagnostic']=e.diagnostic
  report['status']='stopped';report['error_code']=str(e) if isinstance(e,ValueError) and re.fullmatch('[a-z0-9_]{1,100}',str(e)) else 'local_preflight_or_observation_failed'
  print('\nSTOP:',report['error_code'])
  print('Do not Resume to bypass this error. If the update is running, pause it yourself.')
 finally:
  if c:
   try:
    c.close();report['observation']=c.report();report['audit']=c.audit_report()
    from observer import findings
    manual=report['state_before']['configured_manual_ips']
    for request in report['audit']['requests']:
     request['peer_in_configured_manual_ips']=(request['remote_address'] in manual) if request['remote_address'] else None
    report['findings']=findings(report['audit'],report['state_before']['active_allowed_ips'])
    report['findings']['configured_manual_ip_count']=len(manual)
    report['findings']['manual_ip_domain_ownership_verified']=False
   except Exception:report['status']='stopped';report['error_code']='collector_finalize_failed'
  refs.clear()
  if report['state_before']:
   try:
    from policy import state,policy_snapshot
    report['state_after']=state()
    report['state_unchanged_at_endpoints']=report['state_before']==report['state_after']
    report['policy_after']=policy_snapshot(report['state_after'])
    report['policy_unchanged_at_endpoints']=report['policy_before']==report['policy_after']
   except Exception as e:
    report['end_policy_error']='state_or_policy_unavailable_or_mismatched'
    if hasattr(e,'diagnostic'):report['end_policy_diagnostic']=e.diagnostic
  if report['findings']:
   f=report['findings'];print('\nReadable Level3 requests:',f['target_readable_requests'])
   print('Bound to allowed IP:',f['target_requests_bound_to_allowed_ip'])
   print('Hardware literal finding:',f['target_finding'])
   print('OVERALL: INCOMPLETE COVERAGE. No zero-telemetry / only-download verdict.')
  save(report)

if __name__=='__main__':main()
