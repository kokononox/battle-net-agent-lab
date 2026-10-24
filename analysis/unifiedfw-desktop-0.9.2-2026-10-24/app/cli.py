"""File request/response API for WinForms. No HTTP listener and no live firewall adapter."""
from pathlib import Path
import argparse,json,os,subprocess,sys,uuid
sys.path.insert(0,str(Path(__file__).resolve().parent))
from policy import PolicyError,decision
from state import Store,atomic_json,assert_local_tree
from legacy import stage_blacklist,stage_whitelist
BASE=Path(__file__).resolve().parents[1]

def observe(store,ids,seconds,job):
    if type(seconds) is not int or not 1<=seconds<=120:raise PolicyError('invalid_duration')
    if os.name!='nt':raise PolicyError('live_observation_requires_windows')
    state,programs=store.verified_programs(ids)
    plan=job/'observation-request.json';output=job/'observation.json'
    atomic_json(plan,dict(programs=programs,seconds=seconds,stop_path=str(job/'stop.txt'),parent_pid=os.getpid()))
    ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    try:
        r=subprocess.run([str(ps),'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(BASE/'app/observe.ps1'),'-Request',str(plan),'-Output',str(output)],capture_output=True,timeout=seconds+45,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    except subprocess.TimeoutExpired as e:raise PolicyError('observation_timeout_no_policy_changes') from e
    if r.returncode or not output.is_file():
        (job/'collector-error.txt').write_bytes(r.stderr[:16384]);raise PolicyError('observation_failed_see_collector_error_no_policy_changes')
    if output.stat().st_size>16777216:raise PolicyError('observation_output_too_large')
    raw=json.loads(output.read_text('utf-8-sig'))
    if raw.get('schema')!='unified-multiprogram-observation-1':raise PolicyError('invalid_observation_schema')
    return dict(observation=raw,state=state)

def handle(store,action,payload,job):
    generation=payload.get('generation')
    if action=='load':return dict(state=store.read())
    if action=='register':return dict(state=store.register(payload.get('paths'),generation))
    if action=='remove_programs':return dict(state=store.remove(payload.get('program_ids'),generation))
    if action=='configure':return dict(state=store.configure(payload.get('mode'),payload.get('whitelist'),generation))
    if action=='add_blacklist':return dict(state=store.add_blacklist(payload.get('program_ids'),payload.get('target'),payload.get('protocol'),payload.get('port'),generation))
    if action=='delete_blacklist':return dict(state=store.delete_blacklist(payload.get('entry_ids'),generation))
    if action=='preview':return dict(plan=store.preview(),state=store.read())
    if action=='decision':
        s=store.read();return dict(decision=decision(s['config'],payload.get('program_id'),payload.get('address'),payload.get('port'),payload.get('protocol'),payload.get('interface')),state=s)
    if action=='import_blacklist':return dict(state=stage_blacklist(store,payload.get('path'),generation))
    if action=='import_whitelist':return dict(state=stage_whitelist(store,payload.get('path'),generation))
    if action=='observe':return observe(store,payload.get('program_ids'),payload.get('seconds',30),job)
    if action in ('apply','restore','hosts_apply'):raise PolicyError('live_mutation_disabled_in_development_build')
    raise PolicyError('unknown_action')

def main():
    p=argparse.ArgumentParser();p.add_argument('--request',required=True);p.add_argument('--response',required=True);a=p.parse_args()
    jobs=assert_local_tree(BASE/'private-state/jobs');jobs.mkdir(parents=True,exist_ok=True)
    request=assert_local_tree(a.request);response=assert_local_tree(a.response)
    for path in (request,response):
        if jobs.resolve() not in path.resolve().parents:raise PolicyError('job_path_outside_package')
    job=request.parent
    if response.parent!=job:raise PolicyError('job_response_scope')
    try:
        if request.stat().st_size>1048576:raise PolicyError('request_too_large')
        raw=json.loads(request.read_text('utf-8-sig'))
        if not isinstance(raw,dict) or set(raw)!={'action','payload'} or not isinstance(raw['payload'],dict):raise PolicyError('request_schema')
        result=handle(Store(BASE/'private-state'),raw['action'],raw['payload'],job)
        atomic_json(response,dict(ok=True,**result))
    except (PolicyError,OSError,ValueError,TypeError,KeyError) as e:
        code=str(e)
        if len(code)>160 or '\n' in code:code='operation_failed_no_policy_changes'
        atomic_json(response,dict(ok=False,error=code,firewall_changed=False))
        return 1
    return 0
if __name__=='__main__':raise SystemExit(main())
