"""Explicit cPanel HTTPS endpoint check, route preflight, and scoped native test."""
from pathlib import Path
import argparse,ctypes,json,os,subprocess,sys,time,uuid
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'app'),str(ROOT/'lab')]
from console import verify_package
from coexistence import build_coexistence_request
from https_common import https_endpoint,verify_dns,probe_https
from state import atomic_json,assert_local_tree

def run(mode):
    verify_package()
    if mode!='check':
        if os.name!='nt' or not ctypes.windll.shell32.IsUserAnAdmin():raise ValueError('run_as_administrator_on_Windows')
        if os.environ.get('SESSIONNAME','').upper().startswith('RDP'):raise ValueError('local_console_required_not_RDP')
    print('Unified Firewall 0.8.1 — cPanel HTTPS/PHP LAB; not protection certification.')
    print('TLS name/chain validation ON. Direct selected IPv4:443; no HTTP proxy, redirects or fallback IP.')
    print('PHP endpoint must be uploaded to a site you control. No credentials are requested.')
    if mode=='check':print('ONE endpoint request only; no firewall/VPN/route changes. No administrator needed.')
    if mode=='preflight':print('Route/config reads and IPv4 DNS lookup only. No endpoint request or firewall rules.')
    url=input('Full HTTPS URL of uploaded .php file: ').strip();address=input('Selected public IPv4 of that website: ').strip()
    cfg=https_endpoint(url,address)
    try:resolved=verify_dns(cfg)
    except (OSError,ValueError) as error:
        job=assert_local_tree(ROOT/'private-state/https-check-jobs'/uuid.uuid4().hex);job.mkdir(parents=True)
        report=dict(schema='unifiedfw-https-endpoint-check-1',action='DNS_selection_check_stopped_before_endpoint_request',completed=True,endpoint=cfg,classification=dict(outcome='inconclusive'),errors=[str(error)[:300]],firewall_mutation_attempted=False,endpoint_request_attempted=False,vpn_route_verified=False,protection_verified=False)
        atomic_json(job/'result.json',report);print(json.dumps(report,indent=2));print('Export-Lab-Results.cmd -> EXPORT');return 1
    print('DNS includes selected IP. Only',address,':443 will be dialed; other resolved IPs will NOT be tried.')
    if mode!='preflight':
        if input('Type I CONTROL THIS TEST ENDPOINT: ')!='I CONTROL THIS TEST ENDPOINT':raise ValueError('cancelled_no_endpoint_request_or_rules')
    if mode=='check':
        job=assert_local_tree(ROOT/'private-state/https-check-jobs'/uuid.uuid4().hex);job.mkdir(parents=True)
        challenge=dict(kind='unifiedfw-traffic-1',nonce=uuid.uuid4().hex+uuid.uuid4().hex,request_id=uuid.uuid4().hex,role='A')
        probe=probe_https(url,address,challenge)
        r=dict(schema='unifiedfw-https-endpoint-check-1',action='one_https_endpoint_check_no_firewall_changes',completed=True,endpoint=cfg,dns_ipv4=resolved,probe=probe,classification=dict(outcome='endpoint_ready' if probe['handshake_ok'] else 'inconclusive'),firewall_mutation_attempted=False,independent_reference_tested=False,vpn_route_verified=False,protection_verified=False)
        atomic_json(job/'result.json',r);print(json.dumps(r,indent=2));print('Export-Lab-Results.cmd -> EXPORT')
        return 0 if probe['handshake_ok'] else 1
    if mode=='test':
        print('PACED HTTPS: at least 4 seconds between attempts across all phases; no retries; allow about 10-15 minutes.');print('Temporary blocks: TWO bundled images, ONE IPv4, TCP 443 only. Maximum 126 attempts.')
        print('Requires SSTP-selected route distinct from VPN server IP. Keep VPN and window open.')
        if input('Type TEST SCOPED COEXISTENCE: ')!='TEST SCOPED COEXISTENCE':raise ValueError('cancelled_no_rules_or_endpoint_request')
    q=build_coexistence_request(address,443,https_url=url);job=assert_local_tree(ROOT/'private-state/coexistence-jobs'/uuid.uuid4().hex);job.mkdir(parents=True)
    request=job/'request.json';output=job/'result.json';atomic_json(request,q)
    ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    args=[str(ps),'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(ROOT/'lab/coexistence-manage.ps1'),'-Request',str(request),'-Output',str(output)]
    if mode=='preflight':args.append('-ReadOnly')
    print('Result:',output,flush=True);last=None
    with (job/'stdout.txt').open('wb') as stdout,(job/'stderr.txt').open('wb') as stderr:
        process=subprocess.Popen(args,stdout=stdout,stderr=stderr)
        # Never time out or kill the firewall controller.
        while process.poll() is None:
            try:
                progress=json.loads(output.read_text('utf-8-sig')).get('progress')
                if progress!=last:print('Progress:',progress,flush=True);last=progress
            except (OSError,ValueError):pass
            time.sleep(1)
    if not output.exists():raise ValueError('result_missing_session_state_unknown_use_Open_Lab_RESTORE_not_blind_reapply')
    r=json.loads(output.read_text('utf-8-sig'));print(json.dumps({k:v for k,v in r.items() if k not in ('phases','environment','selected_route')},indent=2))
    print('Wait for completion; then Export-Lab-Results.cmd -> EXPORT. Never run parallel tests.')
    return process.returncode
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--mode',choices=['check','preflight','test'],required=True);args=parser.parse_args()
    try:code=run(args.mode)
    except Exception as e:print('ERROR:',e);code=1
    input('Press Enter to close. ');raise SystemExit(code)
