"""Explicit administrator lab console. Never auto-elevates or runs from preview API."""
from pathlib import Path
import ctypes,hashlib,json,os,subprocess,sys,uuid
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
from state import Store,atomic_json,assert_local_tree,locked
from policy import PolicyError

def verify_package():
    manifest=json.loads((ROOT/'MANIFEST-SHA256.json').read_text('utf-8'))
    for name,expected in manifest.items():
        p=Path(name)
        if p.is_absolute() or '..' in p.parts:raise PolicyError('manifest_path')
        full=assert_local_tree(ROOT/p)
        if not full.is_file() or hashlib.sha256(full.read_bytes()).hexdigest()!=expected:raise PolicyError('package_integrity_failed: '+name)

def request_for(store,legacy_ack=False):
    state=store.read();c=state['config']
    if c['mode']=='full_isolation':raise PolicyError('full_isolation_is_not_implemented_do_not_use_as_kill_switch')
    if c['legacy_imports'] and legacy_ack is not True:raise PolicyError('legacy_imports_unresolved_no_automatic_migration')
    if any(p['enabled'] for p in c['programs']):state,_=store.verified_programs()
    from policy import compile_plan
    plan=compile_plan(state['config'],state['owner'])
    if not plan['rules']:raise PolicyError('no_rules_to_apply')
    return dict(schema='unified-lab-request-1',mode=state['config']['mode'],legacy_imports=state['config']['legacy_imports'],legacy_acknowledged=legacy_ack,programs=[p for p in state['config']['programs'] if p['enabled']],plan=plan)

def selftest_request():
    from policy import new_config,program_id,blacklist_entry,compile_plan
    from state import inspect_file
    c=new_config()
    for name in ('python.exe','pythonw.exe'):
        path=str(ROOT/'runtime'/name);pid=program_id(path)
        c['programs'].append(dict(id=pid,path=path,sha256=inspect_file(Path(path)),enabled=True))
        c['blacklist'].append(blacklist_entry([pid],'1.1.1.1','TCP',9))
    owner=uuid.uuid4().hex
    return dict(schema='unified-lab-request-1',mode='blacklist_only',legacy_imports=[],legacy_acknowledged=False,programs=c['programs'],plan=compile_plan(c,owner))

def native(action,request=None):
    if os.name!='nt':raise PolicyError('windows_required')
    if not ctypes.windll.shell32.IsUserAnAdmin():raise PolicyError('run_Open_Lab_as_administrator_explicitly')
    assert_local_tree(ROOT)
    if str(ROOT).startswith('\\\\'):raise PolicyError('local_package_directory_required')
    job=assert_local_tree(ROOT/'private-state/lab-jobs'/uuid.uuid4().hex);job.mkdir(parents=True)
    req=job/'request.json';out=job/'result.json'
    if request is not None:atomic_json(req,request)
    ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    args=[str(ps),'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(ROOT/'lab/manage.ps1'),'-Action',action,'-Output',str(out)]
    if request is not None:args+=['-Request',str(req)]
    # NEVER impose a timeout on a firewall mutation. Journal survives interruption;
    # an interrupted session must be restored, not assumed automatically reverted.
    completed=subprocess.run(args,capture_output=True)
    (job/'stderr.txt').write_bytes(completed.stderr)
    print('Result file:',out)
    if not out.exists():raise PolicyError('native_result_missing_changes_unknown_if_apply_restore; inspect_stderr_and_session')
    result=json.loads(out.read_text('utf-8-sig'))
    print(json.dumps({k:v for k,v in result.items() if k not in ('session',)},indent=2,ensure_ascii=False))
    return 0 if result.get('ok') and completed.returncode==0 else 1

def run():
    verify_package()
    if os.name!='nt':raise PolicyError('windows_required')
    print('Unified Firewall 0.5.0 LAB — NOT A FINAL SECURITY RELEASE')
    print('STATUS: reads Windows policy/VPN and session (no firewall mutation).')
    print('APPLY LAB: REAL blocking rules. May disconnect programs/VPN. No outside-VPN protection.')
    print('RESTORE: removes only exact unchanged rules recorded in the protected journal.')
    print('SELFTEST LAB: briefly blocks package python.exe/pythonw.exe to 1.1.1.1 TCP port 9, then restores; no packets are sent.')
    print('Full isolation/kill-switch: DISABLED. Stop legacy tools first. Local console only; NOT RDP.')
    action=input('Type STATUS, SELFTEST LAB, APPLY LAB, RESTORE, or EXIT: ').strip()
    if action=='EXIT':return 0
    if action=='STATUS':return native('status')
    if action=='RESTORE':return native('restore')
    if action=='SELFTEST LAB':
        if input('Confirm real temporary test rules by typing TEST RULES: ')!='TEST RULES':raise PolicyError('cancelled_no_changes')
        return native('selftest',selftest_request())
    if action!='APPLY LAB':raise PolicyError('cancelled_no_changes')
    print('Apply is an explicit LAB TEST, not a protection certification. Keep local admin access.')
    if input('Confirm by typing I ACCEPT LAB NETWORK CHANGES: ')!='I ACCEPT LAB NETWORK CHANGES':raise PolicyError('cancelled_no_changes')
    store=Store(ROOT/'private-state')
    # Hold config lock while validating, compiling AND applying: do not race UI edits.
    with locked(store.lock):
        # _read instead of recursive lock acquisition; verified_programs uses read().
        # Snapshot first under lock, then inspect each program directly.
        state=store._read()
        class Snapshot:
            def read(self):return state
            def verified_programs(self):
                for p in state['config']['programs']:
                    if p['enabled']:
                        checked=store.inspector(p['path'])
                        if checked['path'].casefold()!=p['path'].casefold() or checked['sha256']!=p['sha256']:raise PolicyError('program_binary_changed_reselect_required')
                return state,[p for p in state['config']['programs'] if p['enabled']]
        legacy_ack=False
        if state['config']['legacy_imports']:
            print('Imported configuration detected. Old tools must be stopped AND restored first.')
            print('No rules are adopted/deleted. Windows guard will also reject known enabled legacy rules.')
            legacy_ack=input('Only after restoring old tools, type OLD TOOLS RESTORED: ')=='OLD TOOLS RESTORED'
        request=request_for(Snapshot(),legacy_ack=legacy_ack)
        print('Mode:',request['mode'],'Rules:',len(request['plan']['rules']))
        print('Whitelist/blacklist overlap notices:',json.dumps(request['plan']['overlaps'],ensure_ascii=False))
        return native('apply',request)
if __name__=='__main__':
    try:code=run()
    except Exception as e:print('ERROR:',e);code=1
    input('Press Enter to close (files and journal are retained). ')
    raise SystemExit(code)
