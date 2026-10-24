"""Explicit Windows-only traffic lab. Requires a user-controlled challenge server."""
from pathlib import Path
import ctypes,hashlib,json,os,subprocess,sys,uuid
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'));sys.path.insert(0,str(ROOT/'lab'))
from state import atomic_json,assert_local_tree,inspect_file
from policy import new_config,program_id,blacklist_entry,compile_plan,windows_path
from console import verify_package
from traffic_common import endpoint

def build_request(address,port,root=ROOT,inspector=inspect_file):
    address,port=endpoint(address,port);programs=[]
    for role,name in (('A','python.exe'),('B','pythonw.exe')):
        path=windows_path(str(root/'runtime'/name));programs.append(dict(role=role,id=program_id(path),path=path,sha256=inspector(Path(path)),enabled=True))
    owner=uuid.uuid4().hex;phases=[]
    for name,roles in (('only_A',('A',)),('only_B',('B',)),('both',('A','B'))):
        c=new_config();c['programs']=[{k:v for k,v in p.items() if k!='role'} for p in programs]
        c['blacklist']=[blacklist_entry([p['id'] for p in programs if p['role'] in roles],address,'TCP',port)]
        q=dict(schema='unified-lab-request-1',mode='blacklist_only',legacy_imports=[],legacy_acknowledged=False,programs=c['programs'],plan=compile_plan(c,owner))
        phases.append(dict(name=name,request=q))
    return dict(schema='unifiedfw-traffic-request-1',address=address,port=port,programs=programs,phases=phases)

def run():
    verify_package()
    if os.name!='nt' or not ctypes.windll.shell32.IsUserAnAdmin():raise ValueError('run_Traffic_Test_cmd_as_administrator_on_Windows')
    if os.environ.get('SESSIONNAME','').upper().startswith('RDP'):raise ValueError('local_console_required_not_RDP')
    print('Unified Firewall 0.7.0 — legacy DIRECT IPv4 TCP traffic LAB, NOT a protection certification.')
    print('Start server/echo-server.py on a server you control, reachable on an unprivileged TCP port.')
    print('Temporary rules affect ONLY bundled python.exe/pythonw.exe, exact server IPv4 and port.')
    print('Three phases: block A only, block B only, block both. Each restores before continuing.')
    print('No global VPN whitelist, kill-switch, firewall profile or other-app rule is changed.')
    address=input('Public IPv4 of your authorized test server (no domain): ').strip()
    text=input('TCP test port [39443]: ').strip() or '39443'
    if not text.isdecimal():raise ValueError('numeric_port_required')
    address,port=endpoint(address,int(text))
    if input('Type I CONTROL THIS TEST ENDPOINT: ')!='I CONTROL THIS TEST ENDPOINT':raise ValueError('cancelled_no_rules_or_connections')
    if input('Type TEST TEMPORARY BLOCKS to start: ')!='TEST TEMPORARY BLOCKS':raise ValueError('cancelled_no_rules_or_connections')
    q=build_request(address,port);job=assert_local_tree(ROOT/'private-state/traffic-jobs'/uuid.uuid4().hex);job.mkdir(parents=True)
    req=job/'request.json';out=job/'result.json';atomic_json(req,q)
    print('Running; may take several minutes. Keep this window open. Result:',out)
    ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    # NO timeout/kill on the firewall controller; only individual network probes are bounded.
    c=subprocess.run([str(ps),'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(ROOT/'lab/traffic-manage.ps1'),'-Request',str(req),'-Output',str(out)],capture_output=True)
    (job/'stderr.txt').write_bytes(c.stderr);(job/'stdout.txt').write_bytes(c.stdout)
    if not out.exists():raise ValueError('result_missing_session_state_unknown_use_051_060_RESTORE_not_blind_reapply')
    r=json.loads(out.read_text('utf-8-sig'))
    print(json.dumps({k:v for k,v in r.items() if k not in ('phases','environment')},indent=2,ensure_ascii=False))
    print('Export-Lab-Results.cmd includes this traffic result. A passed result is NOT a VPN/no-leak certificate.')
    return 0 if r.get('classification',{}).get('outcome')=='passed' and r.get('restore_verified') is True else 1
if __name__=='__main__':
    try:code=run()
    except Exception as e:print('ERROR:',e);code=1
    input('Press Enter to close. ');raise SystemExit(code)
