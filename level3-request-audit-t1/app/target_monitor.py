"""T1: existing BAT06 profile, read-only hosts, attach-only outgoing input audit."""
import argparse,ctypes,datetime,hashlib,json,os,sys,time
from pathlib import Path
from core import NAMES,WOW,cpu_reference,snapshot,versions
from hosts_guard import safe_path
from monitor import integrity,single_instance,LIMITS
from request_audit import AuditCollector,probe,profile_ok,validate_audit
BASE=Path(__file__).resolve().parents[1]

def hosts_hash():
    p=safe_path(Path(os.environ['SystemRoot'])/'System32/drivers/etc/hosts')
    if p.stat().st_size>1048576:raise ValueError('hosts_too_large')
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main(args):
    if sys.platform!='win32' or ctypes.sizeof(ctypes.c_void_p)!=8:raise ValueError('windows_x64_required')
    integrity()
    if not ctypes.windll.shell32.IsUserAnAdmin():raise ValueError('run_as_administrator')
    handle=single_instance() # Kept alive through process exit; shared across observer versions.
    import frida
    if frida.__version__!='17.24.2':raise ValueError('unexpected_frida_version')
    print('Level3 Request Audit T1.1 - NOT a privacy firewall. Outgoing HTTP/1 inputs only.')
    print('No hosts/game writes, clicks, uploads, TLS changes, or Blizzard process lifecycle control.')
    print('Read-only hooks can affect stability. Close WoW; keep updates paused and automatic updates OFF.')
    print('Existing BAT06 blocks PERSIST after this tool exits; it does not restore or alter them.')
    print('Certificate validation can contact certificate services. No raw requests or TLS keys are saved.')
    from selftest import run
    test=run(frida)
    if args.selftest_only:
        out=BASE/('selftest-to-share-'+str(time.time_ns())+'.json');out.write_text(json.dumps(test,indent=2)+'\n')
        if not test['passed']:raise ValueError('owned_selftest_failed')
        print('SELFTEST PASS');return
    if not test['passed']:raise ValueError('owned_selftest_failed_do_not_resume')
    if snapshot(NAMES|WOW)['processes']:raise ValueError('close_battlenet_agent_and_wow_first')
    print('Apply only 06-All-Except-Level3.bat yourself first. Other observers must be closed.')
    dns=probe()
    if not profile_ok(dns):
        from request_audit import BLOCKED,TARGET
        for host,state in dns.items():
            expected={'public_only'} if host==TARGET else {'sink_only','explicit_hosts_sink_windows_no_data'}
            if state not in expected:print('MISMATCH:',host,'state='+state)
        raise ValueError('bat06_resolution_not_confirmed_do_not_resume')
    root=Path(input('Game folder [G:\\World of Warcraft]: ').strip().strip('"') or r'G:\World of Warcraft')
    before=versions(root)
    if not before['retail_versions']:raise ValueError('retail_version_not_found')
    if input('Confirm backup available, signed out, paused, auto updates OFF. Type CONFIRM: ').strip()!='CONFIRM':return
    start=datetime.datetime.now(datetime.timezone.utc)
    report={'schema':'level3-request-audit-1','started_utc':start.isoformat(),'selftest':test,
        'initial_versions':before,'final_versions':None,'ready':False,'status':'waiting',
        'error_code':None,'dns_before':dns,'dns_ready':None,'dns_after':None,'hosts_sha256_before':hosts_hash(),
        'hosts_sha256_after':None,'hosts_changed_by_tool':False,'hosts_hash_unchanged':None,
        'user_final_state':'not_recorded','user_download_behavior':'not_recorded',
        'observation':None,'audit':None,'limits':dict(LIMITS,received_bytes_measured=False,external_hosts_blocks_persist=True)}
    collector=AuditCollector(frida,cpu_reference())
    try:
        if snapshot(NAMES|WOW)['processes']:raise ValueError('close_battlenet_agent_and_wow_first')
        collector.start()
        print('Open Battle.net YOURSELF now, signed out and PAUSED. Wait for READY. Do not start WoW.')
        deadline=time.monotonic()+180
        while time.monotonic()<deadline and not collector.ready():
            if snapshot(WOW)['processes']:raise ValueError('wow_running_stop_observation')
            time.sleep(.5)
        if not collector.ready():raise ValueError('agent_hooks_not_ready_do_not_resume')
        report['dns_ready']=probe()
        if not profile_ok(report['dns_ready']) or hosts_hash()!=report['hosts_sha256_before']:raise ValueError('profile_changed_do_not_resume')
        if snapshot(WOW)['processes']:raise ValueError('wow_running_do_not_resume')
        collector.phase='user_update_window';report['ready']=True;report['status']='observing'
        print('READY - observation only, NOT a no-telemetry guarantee.')
        print('You may manually Resume. After 60-120 seconds manually Pause; then press Q here.')
        print('Maximum observation 10 minutes. Timer/Q NEVER pauses update. Do not launch WoW.')
        import msvcrt
        deadline=time.monotonic()+600;nextcheck=0
        while time.monotonic()<deadline:
            if msvcrt.kbhit() and msvcrt.getwch().lower()=='q':break
            if time.monotonic()>nextcheck:
                if snapshot(WOW)['processes']:raise ValueError('wow_running_observation_stopped')
                nextcheck=time.monotonic()+2
            time.sleep(.2)
        report['status']='observation_ended'
    except Exception as exc:
        report['status']='stopped';report['error_code']=str(exc) if isinstance(exc,ValueError) and str(exc).replace('_','').isalnum() and len(str(exc))<100 else 'observation_failed'
        print('STOP:',report['error_code'])
    finally:
        collector.close();report['audit']=validate_audit(collector.audit_report());report['observation']=collector.report()
        report['hosts_sha256_after']=hosts_hash();report['hosts_hash_unchanged']=report['hosts_sha256_before']==report['hosts_sha256_after']
        report['final_versions']=versions(root);report['dns_after']=probe()
        print('Observer detached. This tool did NOT pause update. Manually ensure paused or finished.')
        try:
            answer=input('1 Paused, 2 Finished, 3 Error/stopped, 4 Unknown: ').strip()
            report['user_final_state']={'1':'reported_paused','2':'reported_finished','3':'reported_error'}.get(answer,'unknown')
            answer=input('Download: 1 Progressed, 2 Stalled, 3 Error, 4 Unknown: ').strip()
            report['user_download_behavior']={'1':'reported_progress','2':'reported_stall','3':'reported_error'}.get(answer,'unknown')
        except (EOFError,KeyboardInterrupt):pass
        raw=(json.dumps(report,indent=2)+'\n').encode()
        if len(raw)>4*1024**2:raise ValueError('report_size_limit')
        out=safe_path(BASE/'output'/('level3-audit-'+start.strftime('%Y%m%dT%H%M%SZ')+'-'+str(time.time_ns())+'.json'))
        out.parent.mkdir(exist_ok=True)
        with out.open('xb') as f:f.write(raw)
        print('Report saved locally:',out.name)
        print('Existing BAT06 hosts entries are STILL present; no automatic restoration occurred.')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--selftest-only',action='store_true')
    try:main(p.parse_args())
    except KeyboardInterrupt:print('Stopped by user; no update or hosts change requested.');sys.exit(1)
    except Exception as exc:
        print('STOP:',str(exc) if isinstance(exc,ValueError) else 'initialization_failed');sys.exit(1)
