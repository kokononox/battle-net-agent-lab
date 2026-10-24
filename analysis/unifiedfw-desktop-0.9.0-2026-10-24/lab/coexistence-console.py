"""Explicit preflight/scoped test; progress polling has no controller timeout."""
from pathlib import Path
import argparse,ctypes,json,os,subprocess,sys,time,uuid
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'app'),str(ROOT/'lab')]
from console import verify_package
from coexistence import build_coexistence_request
from state import assert_local_tree,atomic_json
from traffic_common import endpoint

def run(preflight):
    verify_package()
    if os.name!='nt' or not ctypes.windll.shell32.IsUserAnAdmin():raise ValueError('run_as_administrator_on_Windows')
    if os.environ.get('SESSIONNAME','').upper().startswith('RDP'):raise ValueError('local_console_required_not_RDP')
    print('Unified Firewall 0.8.0 — SCOPED coexistence LAB, NOT global whitelist or kill-switch.')
    print('Preflight reads route/config only; it sends NO endpoint probes and creates NO firewall rules.')
    print('Endpoint must be a server you control, distinct from the VPN server IP, routed through SSTP.')
    print('No VPN routes/settings, firewall profiles, other apps, hosts or DNS are changed.')
    address=input('Authorized endpoint public IPv4: ').strip();text=input('TCP test port [39443]: ').strip() or '39443'
    if not text.isdecimal():raise ValueError('numeric_port_required')
    address,port=endpoint(address,int(text))
    if not preflight:
        print('Maximum 126 fresh TCP attempts. Only bundled python.exe/pythonw.exe, one IPv4 and one port.')
        print('Keep VPN connected. Route change aborts and attempts journaled Restore. Keep window open.')
        if input('Type I CONTROL THIS TEST ENDPOINT: ')!='I CONTROL THIS TEST ENDPOINT':raise ValueError('cancelled_no_rules_or_connections')
        if input('Type TEST SCOPED COEXISTENCE: ')!='TEST SCOPED COEXISTENCE':raise ValueError('cancelled_no_rules_or_connections')
    q=build_coexistence_request(address,port);job=assert_local_tree(ROOT/'private-state/coexistence-jobs'/uuid.uuid4().hex);job.mkdir(parents=True)
    request=job/'request.json';output=job/'result.json';atomic_json(request,q)
    ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    args=[str(ps),'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(ROOT/'lab/coexistence-manage.ps1'),'-Request',str(request),'-Output',str(output)]
    if preflight:args.append('-ReadOnly')
    print('Result:',output,flush=True);last=None
    with (job/'stdout.txt').open('wb') as stdout,(job/'stderr.txt').open('wb') as stderr:
        process=subprocess.Popen(args,stdout=stdout,stderr=stderr)
        # No timeout, process.kill(), or automatic reapply of the firewall controller.
        while process.poll() is None:
            try:
                progress=json.loads(output.read_text('utf-8-sig')).get('progress')
                if progress!=last:print('Progress:',progress,flush=True);last=progress
            except (OSError,ValueError):pass
            time.sleep(1)
    if not output.exists():raise ValueError('result_missing_session_state_unknown_use_Open_Lab_RESTORE_not_blind_reapply')
    r=json.loads(output.read_text('utf-8-sig'));print(json.dumps({k:v for k,v in r.items() if k not in ('phases','environment','selected_route')},indent=2))
    print('Now run Export-Lab-Results.cmd and type EXPORT. Do not run simultaneous tests.')
    return process.returncode
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');a=parser.parse_args()
    try:code=run(a.preflight)
    except Exception as e:print('ERROR:',e);code=1
    input('Press Enter to close. ');raise SystemExit(code)
