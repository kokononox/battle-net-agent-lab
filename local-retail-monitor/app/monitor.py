"""Interactive local observer; no automatic Update/Pause/Play or game-file writes."""
import argparse
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from core import Collector,NAMES,WOW,cpu_reference,snapshot,versions
from hosts_guard import HostsGuard,safe_path,resolve

BASE=Path(__file__).resolve().parents[1]
LIMITS={
 'no_update_or_game_operation_requested':True,'no_battlenet_process_launched_or_terminated':True,
 'no_process_spawn_gating_or_lifecycle_control':True,'no_game_file_writes':True,
 'raw_headers_urls_payloads_keys_or_logs_exported':False,'automatic_report_upload':False,
 'server_receipt_proven':False,'whole_update_completion_proven':False,'zero_telemetry_guaranteed':False,
 'late_attach_can_miss_first_requests':True,'sampling_can_miss_connections':True,
 'host_hints_not_cryptographic_network_binding':True,'local_api_success_not_server_receipt':True,
 'http2_openssl_quic_or_app_encoding_coverage_complete':False,
 'injection_can_change_timing_or_cause_instability':True,'cpu_literal_absence_not_hardware_data_absence':True,
 'signature_validation_may_contact_certificate_services':True,
 'tls_context_reuse_and_concurrent_order_not_fully_tracked':True,
 'host_hint_not_complete_http_request_proof':True,
}

def integrity():
    manifest=BASE/'MANIFEST-SHA256.json'
    if not manifest.exists():raise ValueError('package_manifest_missing')
    r=json.loads(manifest.read_text(encoding='utf-8'))
    if type(r) is not dict or len(r)>4096:raise ValueError('manifest_invalid')
    for name,h in r.items():
        if not re.fullmatch(r'[A-Za-z0-9_./-]{1,200}',name) or '..' in name.split('/') or name.startswith('/'):raise ValueError('manifest_path')
        path=safe_path(BASE/name)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=h:raise ValueError('package_integrity_failed')

def write_report(out,report):
    from validate import validate
    validate(report)
    b=(json.dumps(report,indent=2)+'\n').encode()
    if len(b)>2*1024**2:raise ValueError('report_size_limit')
    safe_path(out);out.parent.mkdir(parents=True,exist_ok=True)
    with out.open('xb') as f:f.write(b)

def single_instance():
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    api.CreateMutexW.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_wchar_p]
    api.CreateMutexW.restype=ctypes.c_void_p
    handle=api.CreateMutexW(None,False,'Global\\LocalRetailPrivacyObserverU1')
    if not handle:raise ValueError('single_instance_guard_failed')
    if ctypes.get_last_error()==183:raise ValueError('monitor_already_running_do_not_restore_hosts')
    return handle

def main():
    a=argparse.ArgumentParser();a.add_argument('--selftest-only',action='store_true');a.add_argument('--restore-only',action='store_true');args=a.parse_args()
    if sys.platform!='win32' or ctypes.sizeof(ctypes.c_void_p)!=8:raise ValueError('windows_x64_required')
    integrity()
    if not ctypes.windll.shell32.IsUserAnAdmin():raise ValueError('run_start_monitor_as_administrator')
    state=safe_path(BASE/'PRIVATE-RECOVERY');state.mkdir(exist_ok=True)
    hosts=Path(os.environ['SystemRoot'])/'System32'/'drivers'/'etc'/'hosts'
    guard=HostsGuard(hosts,state/'hosts-recovery.json')
    if args.restore_only:
        print('Restore only:',guard.restore_status if not guard.journal.exists() else guard.restore());return
    if guard.journal.exists():
        print('STOP: previous hosts recovery is pending. No new observation will start.')
        print('Restoration result:',guard.restore());return
    import frida
    if frida.__version__!='17.24.2':raise ValueError('unexpected_frida_version')
    from selftest import run
    print('Local Privacy Monitor U1 - observation, NOT a privacy firewall.')
    print('It NEVER clicks Update/Pause/Play, signs in, edits game files or uploads reports.')
    print('Read-only API hooks can affect timing or stability. No anti-cheat/game process is attached.')
    print('Keep WoW CLOSED, game updates PAUSED and automatic game updates OFF.')
    print('Self-test uses only an owned loopback worker. Certificate checks may contact certificate services.')
    test=run(frida)
    if args.selftest_only:
        target=safe_path(BASE/'selftest-to-share.json')
        with target.open('x',encoding='utf-8') as f:json.dump(test,f,indent=2)
        print('SELFTEST PASS' if test['passed'] else 'SELFTEST FAILED')
        if not test['passed']:raise ValueError('selftest_failed')
        return
    if not test['passed']:raise ValueError('selftest_failed_do_not_resume_update')
    if snapshot(NAMES|WOW)['processes']:
        raise ValueError('close_battlenet_agent_and_wow_first_no_processes_closed_by_tool')
    root=Path(input('WoW folder containing .build.info [G:\\World of Warcraft]: ').strip().strip('"') or r'G:\World of Warcraft')
    before=versions(root)
    if not before['retail_versions']:raise ValueError('retail_build_info_not_confirmed')
    print('Observed Retail versions:',', '.join(before['retail_versions']))
    print('Confirm: backup exists; automatic game updates OFF; no game/account login; update is paused.')
    if input('Type CONFIRM, or anything else to stop: ').strip()!='CONFIRM':return
    print('1. Observe only (hosts unchanged)\n2. Temporarily block ONLY telemetry-in.battle.net (H1 test)')
    mode=input('Choose 1 or 2: ').strip()
    if mode not in ('1','2'):return
    if mode=='2' and input('Type BLOCK to allow this one temporary hosts change: ').strip()!='BLOCK':return
    now=datetime.datetime.now(datetime.timezone.utc)
    report={'schema':'local-retail-privacy-observer-1','version':'U1','started_utc':now.isoformat(),
        'mode':'observe_only' if mode=='1' else 'block_telemetry','selftest':test,
        'initial_versions':before,'final_versions':None,'user_preconditions_confirmed':True,
        'ready_was_announced':False,'user_final_state':'not_recorded','status':'not_started','error_code':None,
        'hosts':{'changed_by_tool':False,'restored':False,'restore_status':'not_needed','resolution_after_apply':'not_tested','resolution_at_end':'not_tested'},
        'observation':None,'limits':LIMITS,'cpu_reference_available':False}
    collector=None
    out=BASE/'output'/('report-'+now.strftime('%Y%m%dT%H%M%SZ')+'.json')
    try:
        if snapshot(NAMES|WOW)['processes']:raise ValueError('close_battlenet_agent_and_wow_before_test')
        if mode=='2':guard.apply()
        else:guard.at_launch=resolve()
        report['hosts']['resolution_after_apply']=guard.at_launch
        needle=cpu_reference();report['cpu_reference_available']=needle is not None
        collector=Collector(frida,needle);collector.start();report['status']='waiting_for_agent'
        print('Now open Battle.net yourself. Keep game update PAUSED and stay signed out.')
        print('Waiting up to 180 seconds for a verified signed Agent with HTTP + SSPI hooks. DO NOT resume yet.')
        deadline=time.monotonic()+180
        while time.monotonic()<deadline and not collector.ready():time.sleep(.3)
        if not collector.ready():raise ValueError('agent_hooks_not_ready_do_not_resume_update')
        if snapshot(WOW)['processes']:raise ValueError('wow_running_do_not_resume')
        collector.phase='user_update_window'
        report['ready_was_announced']=True;report['status']='observing'
        print('READY FOR OBSERVATION ONLY - not a zero-telemetry guarantee.')
        print('You may now manually resume Update if you choose. Initializing and downloading are both observed.')
        print('No automatic Pause or cancellation. Maximum window: 4 hours.')
        print('After update is finished OR manually paused, press Q here. Do not launch WoW while attached.')
        import msvcrt
        started=time.monotonic()
        while time.monotonic()-started<4*3600:
            if msvcrt.kbhit() and msvcrt.getwch().lower()=='q':break
            time.sleep(.2)
        collector.close()
        print('API observation has now stopped; this program did not pause the update.')
        print('Before ending observation/restoring hosts: ensure Update is finished or manually paused.')
        print('1. Finished  2. Paused  3. Error/stopped  4. Unknown')
        answer=input('State (your answer, not independently proven): ').strip()
        report['user_final_state']={'1':'reported_finished','2':'reported_paused','3':'reported_error_or_stopped'}.get(answer,'unknown')
        report['status']='observation_ended'
    except KeyboardInterrupt:
        report['status']='interrupted';report['error_code']='user_interrupted'
    except Exception as exc:
        report['status']='stopped';report['error_code']=str(exc) if isinstance(exc,ValueError) and re.fullmatch('[a-z0-9_]{1,100}',str(exc)) else 'local_observation_failed'
        print('STOP: observation failed or a prerequisite was not met. Do not resume Update for this test.')
    finally:
        if collector:
            collector.close();report['observation']=collector.report()
        report['final_versions']=versions(root)
        report['hosts']['resolution_at_end']=resolve()
        restore=guard.restore()
        report['hosts'].update(changed_by_tool=guard.changed,restored=guard.restored,restore_status=restore)
        write_report(out,report)
        print('Local shareable report:',str(Path('output')/out.name))
        print('Hosts restoration:',restore)
        if restore=='needs_manual_attention_journal_kept':
            print('ATTENTION: hosts changed or recovery failed; private recovery journal was kept. Do not delete it.')
        print('Send ONLY the report JSON, never PRIVATE-RECOVERY or game/account files.')
        print('Observation has ended. Restored hosts no longer blocks telemetry for ongoing Battle.net activity.')

if __name__=='__main__':
    try:
        _mutex=single_instance() if sys.platform=='win32' else None
        main()
    except Exception as exc:
        print('STOP:',str(exc) if isinstance(exc,ValueError) and re.fullmatch('[a-z0-9_]{1,100}',str(exc)) else 'preflight_failed')
        print('No permission to resume Update has been given.');sys.exit(1)
