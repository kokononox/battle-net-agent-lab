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
from hosts_guard import HostsGuard,safe_path,resolve,TARGET,EXTRA_TARGETS,trial_targets

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

def schedule_plan():
    # Baseline first, followed by exactly ONE extra per stage. No accumulated
    # extra blocks; telemetry baseline remains unchanged across every stage.
    return (None,)+EXTRA_TARGETS

def main(args,scheduled_trial=None):
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
    print('Local Privacy Monitor U2 - observation, NOT a privacy firewall.')
    print('It NEVER clicks Update/Pause/Play, signs in, edits game files or uploads reports.')
    print('Read-only API hooks can affect timing or stability. No anti-cheat/game process is attached.')
    print('Keep WoW CLOSED, game updates PAUSED and automatic game updates OFF.')
    print('Self-test uses only an owned loopback worker. Certificate checks may contact certificate services.')
    test=run(frida)
    if args.selftest_only:
        target=safe_path(BASE/('selftest-to-share-'+str(time.time_ns())+'.json'))
        with target.open('x',encoding='utf-8') as f:json.dump(test,f,indent=2)
        print('Self-test report:',target.name)
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
    print('1. Observe only (hosts unchanged)\n2. Baseline: temporarily block telemetry-in.battle.net')
    print('3. Trial: keep telemetry baseline blocked + ONE selected extra hostname')
    mode=('2' if scheduled_trial['extra'] is None else '3') if scheduled_trial else input('Choose 1, 2 or 3: ').strip()
    if mode not in ('1','2','3'):return
    extra=None
    if mode=='3':
        print('One extra target per run. This tests download dependency, NOT whether a host sends telemetry.')
        for i,t in enumerate(EXTRA_TARGETS,1):print(str(i)+'. '+t)
        chosen=str(EXTRA_TARGETS.index(scheduled_trial['extra'])+1) if scheduled_trial else input('Extra target number (anything else stops): ').strip()
        if chosen not in {str(i) for i in range(1,len(EXTRA_TARGETS)+1)}:return
        extra=EXTRA_TARGETS[int(chosen)-1]
        print('WARNING: version/CDN targets may prevent startup or stall downloads. No files are repaired or rolled back.')
    targets=trial_targets(extra) if mode!='1' else ()
    if targets:
        print('This run blocks ONLY these exact hostnames:',', '.join(targets))
        if input('Type BLOCK to allow this temporary hosts change: ').strip()!='BLOCK':return
        guard=HostsGuard(hosts,state/'hosts-recovery.json',targets=targets)
    now=datetime.datetime.now(datetime.timezone.utc)
    report={'schema':'local-retail-privacy-observer-2','version':'U2','started_utc':now.isoformat(),
        'mode':{'1':'observe_only','2':'block_telemetry','3':'block_one_extra'}[mode],'selftest':test,
        'experiment':{'baseline_target':TARGET,'selected_extra_target':extra,'blocked_targets':list(targets),
            'resolution_after_apply':{},'resolution_before_restore':{},
            'dependency_result_user_reported':'not_recorded','control_caveat':'progress_and_cache_differ_between_runs',
            'schedule_index':scheduled_trial['index'] if scheduled_trial else None,
            'window_seconds':scheduled_trial['seconds'] if scheduled_trial else None,
            'window_end_reason':'not_started'},
        'initial_versions':before,'final_versions':None,'user_preconditions_confirmed':True,
        'ready_was_announced':False,'user_final_state':'not_recorded','status':'not_started','error_code':None,
        'hosts':{'changed_by_tool':False,'restored':False,'restore_status':'not_needed','resolution_after_apply':'not_tested','resolution_at_end':'not_tested'},
        'observation':None,'limits':LIMITS,'cpu_reference_available':False}
    collector=None
    out=BASE/'output'/('report-'+now.strftime('%Y%m%dT%H%M%SZ')+'.json')
    try:
        if snapshot(NAMES|WOW)['processes']:raise ValueError('close_battlenet_agent_and_wow_before_test')
        if mode!='1':guard.apply()
        else:guard.at_launch=resolve()
        report['hosts']['resolution_after_apply']=guard.at_launch
        report['experiment']['resolution_after_apply']=dict(guard.resolutions)
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
        if scheduled_trial:
            print('TIMED STAGE:',scheduled_trial['index'],'of',len(schedule_plan()))
            print('Observation window:',scheduled_trial['seconds'],'seconds FROM READY, NOT from the Resume click.')
            print('At the end ONLY OBSERVATION stops. Update DOES NOT pause automatically.')
            print('When prompted, manually Pause/finish and EXIT Battle.net including the tray before the next stage.')
        print('After update is finished OR manually paused, press Q here. Do not launch WoW while attached.')
        import msvcrt
        started=time.monotonic()
        window=scheduled_trial['seconds'] if scheduled_trial else 4*3600
        report['experiment']['window_end_reason']='time_limit'
        while time.monotonic()-started<window:
            if msvcrt.kbhit() and msvcrt.getwch().lower()=='q':
                report['experiment']['window_end_reason']='user_q';break
            time.sleep(.2)
        collector.close()
        print('API observation has now stopped; this program did not pause the update.')
        print('Before ending observation/restoring hosts: ensure Update is finished or manually paused.')
        print('1. Finished  2. Paused  3. Error/stopped  4. Unknown')
        answer=input('State (your answer, not independently proven): ').strip()
        report['user_final_state']={'1':'reported_finished','2':'reported_paused','3':'reported_error_or_stopped'}.get(answer,'unknown')
        print('Download behavior during this run (your observation, not automatically proven):')
        print('1. Continued/progressed  2. Stalled  3. Error  4. Unknown/not resumed')
        behavior=input('Behavior: ').strip()
        report['experiment']['dependency_result_user_reported']={'1':'reported_progress','2':'reported_stall','3':'reported_error'}.get(behavior,'unknown')
        if scheduled_trial:
            print('TIMED STAGE ENDED. Manually ensure Update is paused/finished, then EXIT Battle.net from tray.')
            print('The schedule will not kill processes or start another block until they are closed.')
            while snapshot(NAMES|WOW)['processes']:
                if input('Processes still open. Close them and Enter to recheck, or STOP to end schedule: ').strip().upper()=='STOP':
                    report['experiment']['window_end_reason']='user_stopped_schedule'
                    break
        report['status']='observation_ended'
    except KeyboardInterrupt:
        report['status']='interrupted';report['error_code']='user_interrupted'
    except Exception as exc:
        report['status']='stopped';report['error_code']=str(exc) if isinstance(exc,ValueError) and re.fullmatch('[a-z0-9_]{1,100}',str(exc)) else 'local_observation_failed'
        print('STOP: observation failed or a prerequisite was not met. Do not resume Update for this test.')
    finally:
        # Restoration is independent of read-only game snapshot or collector/report errors.
        try:
            if collector:
                collector.close();report['observation']=collector.report()
        except Exception:
            report['status']='stopped';report['error_code']='collector_cleanup_failed'
        finally:
            try:
                report['hosts']['resolution_at_end']=guard.check_resolution() if targets else resolve()
                report['experiment']['resolution_before_restore']=dict(guard.resolutions)
            except Exception:report['hosts']['resolution_at_end']='other_or_failed'
            restore=guard.restore()
            report['hosts'].update(changed_by_tool=guard.changed,restored=guard.restored,restore_status=restore)
        try:report['final_versions']=versions(root)
        except Exception:report['final_versions']={'status':'unreadable_or_unrecognized','retail_versions':[]}
        write_report(out,report)
        print('Local shareable report:',str(Path('output')/out.name))
        print('Hosts restoration:',restore)
        if restore=='needs_manual_attention_journal_kept':
            print('ATTENTION: hosts changed or recovery failed; private recovery journal was kept. Do not delete it.')
        print('Send ONLY the report JSON, never PRIVATE-RECOVERY or game/account files.')
        print('Observation has ended. Restored hosts no longer blocks telemetry for ongoing Battle.net activity.')
    return report

def run_schedule(args):
    print('SCHEDULE: baseline telemetry block, then six independent single-extra trials.')
    print('Each window is 120 seconds from READY; not an exact Resume-click timestamp.')
    print('NO automatic Update/Pause/Exit. Manual process closure and BLOCK consent are required at EACH stage.')
    print('Stop if the update finishes; do not reset or roll back game files to repeat a stage.')
    print('Changing files/cache and retries mean this is screening, NOT a controlled proof of necessity or telemetry.')
    if input('Type SCHEDULE to begin, anything else exits: ').strip()!='SCHEDULE':return
    for index,extra in enumerate(schedule_plan(),1):
        print('\n===== SCHEDULE STAGE',index,'/',len(schedule_plan()),'=====')
        print('Extra target:',extra or '(none - telemetry-only baseline)')
        result=main(args,scheduled_trial={'index':index,'extra':extra,'seconds':120})
        if result is None or result['hosts']['restore_status']=='needs_manual_attention_journal_kept':
            print('SCHEDULE STOPPED: stage not completed or recovery attention required.');return
        if result['user_final_state']=='reported_finished':
            print('SCHEDULE STOPPED: user reports update finished. No game reset or extra downloads requested.');return
        if result['experiment']['window_end_reason']=='user_stopped_schedule':
            print('SCHEDULE STOPPED by user.');return
        if snapshot(NAMES|WOW)['processes']:
            print('SCHEDULE STOPPED: processes are still open; no next target applied.');return
        # A failed READY is an outcome, NOT permission to resume or an automatic
        # attribution of failure to this hostname. Advancing needs fresh consent.
        print('Stage result:',result['status'],'/',result['experiment']['dependency_result_user_reported'])
        if index==len(schedule_plan()):break
        if extra is None and (not result['ready_was_announced'] or result['experiment']['dependency_result_user_reported']!='reported_progress'):
            print('SCHEDULE STOPPED: baseline progress not established. Extra-target comparisons would be misleading.');return
        if input('Type NEXT for the next independent stage, anything else ends: ').strip()!='NEXT':return
    print('SCHEDULE COMPLETE for available stages. Send output/report-*.json; never PRIVATE-RECOVERY.')

if __name__=='__main__':
    try:
        parser=argparse.ArgumentParser()
        group=parser.add_mutually_exclusive_group()
        group.add_argument('--selftest-only',action='store_true')
        group.add_argument('--restore-only',action='store_true')
        group.add_argument('--schedule',action='store_true')
        args=parser.parse_args()
        _mutex=single_instance() if sys.platform=='win32' else None
        if args.schedule:run_schedule(args)
        else:main(args)
    except Exception as exc:
        print('STOP:',str(exc) if isinstance(exc,ValueError) and re.fullmatch('[a-z0-9_]{1,100}',str(exc)) else 'preflight_failed')
        print('No permission to resume Update has been given.');sys.exit(1)
