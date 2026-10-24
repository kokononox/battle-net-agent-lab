"""Owned x86/x64 fixtures ONLY. This entrypoint cannot download/launch Battle.net."""
import collections
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
HERE=Path(__file__).resolve().parent
sys.path.append(str(HERE.parent/'prelogin-wire-h2'))
from manager import Manager
from native_identity import identity
from process_handle import Process
from capture import Capture
from correlate import analyze
from validate import validate
BRANCH='refs/heads/research/prelogin-telemetry-wow-data-provenance'
MARKERS={'large_recv':('recv','recv','LARGE_RECV'), 'multibuffer_recv':('recv','WSARecv','MULTIBUFFER_RECV'), 'async_recv':('recv','WSARecv','ASYNC_RECV'),'async_send':('send','WSASend','ASYNC_SEND'),'async_bound_recv':('recv','WSARecv','BOUND_RECV'),'async_tp_recv':('recv','WSARecv','TP_RECV')}
def marker(s):return ('SYNTHETIC_H3_'+s+'_ONLY_').ljust(96,'Z').encode('ascii')
def fixture(frida,arch,env):
    result={'architecture':arch,'passed':False,'stage':'compile','error_type':None,'fixture_exit_code':None,
            'root_child_instrumented':False,'bitness_confirmed':False,'negative_encryption_observed':False,
            'linked_probe_requests':0,'http_responses_linked':0,'collector_errors':0,'dropped_events':0,'collector_fatal':False,
            'completed_operations':0,'pending_socket_events':0,'unlinked_immediate_socket_events':0,'diagnostics':{},'observations':{},'capture_issues':{},'packet_count':0,
            'witness':{k:False for k in ['large_recv','multibuffer_recv','pending_recv','false_completion_checked','async_recv','async_send','bound_callback_recv','threadpool_recv']},
            'hook_checks':{k:False for k in MARKERS}}
    manager=None;capture=None;code=None
    try:
        with tempfile.TemporaryDirectory(prefix='h3-owned-',dir=os.environ['RUNNER_TEMP']) as tmp:
            work=Path(tmp);exe=work/'NativeProbe.exe'
            compiler=Path(os.environ['SystemRoot'])/'Microsoft.NET'/'Framework64'/'v4.0.30319'/'csc.exe'
            args=[str(compiler),'/nologo','/warn:0','/target:exe','/main:NativeProbe','/platform:'+arch,'/out:'+str(exe),str(HERE/'native_probe.cs'),str(HERE/'socket_fixture.cs'),str(HERE/'callback_fixture.cs')]
            p=subprocess.run(args,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
            if p.returncode or not exe.is_file():return result
            digest=hashlib.sha256(exe.read_bytes()).hexdigest();ids={}
            def verify(pid,recheck=False):
                info=identity(pid)
                if Path(info['path']).resolve()!=exe.resolve():raise RuntimeError('fixture_image')
                if recheck:
                    if ids[pid]!=info['creation']:raise RuntimeError('fixture_pid_reused')
                    return {}
                if hashlib.sha256(exe.read_bytes()).hexdigest()!=digest:raise RuntimeError('fixture_changed')
                ids[pid]=info['creation']
                return {'process_name':'owned_fixture.exe','sha256':digest,'image_bytes':exe.stat().st_size}
            manager=Manager(frida,verify);capture=Capture(work,env)
            try:
                result['stage']='capture';capture.start()
                result['stage']='spawn';pid=manager.spawn([exe],env,work);h=Process(manager,pid)
                try:result['stage']='wait';code=h.wait(timeout=100)
                finally:h.close()
                time.sleep(.5)
            finally:manager.close();packets=capture.finish()
            result['stage']='analyze'
            witness=Path(str(exe)+'.witness.json')
            if witness.is_file() and witness.stat().st_size<1024:
                w=json.loads(witness.read_text())
                if set(w)==set(result['witness']) and all(type(v) is bool for v in w.values()):result['witness']=w
            review=analyze(manager.inputs,packets)
            result['linked_probe_requests']=sum(r['destination']=='example.com' and r['packet_bytes_linked'] for r in review['requests'])
            result['http_responses_linked']=sum(r['http_response_status'] is not None for r in review['requests'])
            result['capture_issues']=packets['issues']
            for key,(kind,api,text) in MARKERS.items():
                matches=[e for e in manager.inputs if e['pid']==pid and e['kind']==kind and e.get('api')==api and e.get('accepted_bytes')==96 and e.get('raw')==marker(text) and e.get('complete') and not e.get('ambiguous')]
                result['hook_checks'][key]=len(matches)==1 and (not key.startswith('async_') or matches[0].get('completion_proven') is True)
            result['negative_encryption_observed']=any(e['kind']=='encrypt' and e['return_code']!=0 and e['before']==b'SYNTHETIC_INVALID_CONTEXT_NOT_TARGET' for e in manager.inputs)
            rows=list(manager.rows.values())
            result['root_child_instrumented']=len(rows)==2 and all(r['instrumented_before_resume'] and r['child_gating_enabled'] for r in rows)
            result['bitness_confirmed']=len(rows)==2 and all(r['pointer_bits']==(32 if arch=='x86' else 64) for r in rows)
            result['stage']='complete'
    except Exception as e:
        result['error_type']=type(e).__name__ if type(e).__name__ in ('OSError','RuntimeError','TimeoutExpired','ValueError') else 'Exception'
    finally:
        result['fixture_exit_code']=code
        if manager:
            rows=list(manager.rows.values());result['collector_errors']=sum(r['script_errors'] for r in rows)
            d=collections.Counter()
            for r in rows:d.update(r['diagnostics'])
            o=collections.Counter()
            for r in rows:o.update(r['observations'])
            result['observations']=dict(o)
            result['diagnostics']=dict(d);result['dropped_events']=manager.dropped;result['collector_fatal']=manager.fatal
            result['completed_operations']=sum(r['completed_operations'] for r in rows)
            result['pending_socket_events']=sum(e.get('asynchronous') is True and not e.get('completion_proven') and not e.get('immediate_completion') for e in manager.inputs)
            result['unlinked_immediate_socket_events']=sum(e.get('asynchronous') is True and not e.get('completion_proven') and e.get('immediate_completion') is True for e in manager.inputs)
        if capture:result['packet_count']=capture.meta['packets']
        result['passed']=bool(code==0 and result['root_child_instrumented'] and result['bitness_confirmed'] and result['negative_encryption_observed'] and all(result['witness'].values()) and all(result['hook_checks'].values()) and result['linked_probe_requests']==2 and result['http_responses_linked']==2 and result['completed_operations']>=4 and not result['collector_errors'] and not result['dropped_events'] and not result['collector_fatal'])
    return result

def main():
    allowed=(sys.platform=='win32' and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1' and os.environ.get('GITHUB_REF')==BRANCH and os.environ.get('BNET_H3_FIXTURE')=='owned-only-20261024-d5')
    if not allowed:raise SystemExit('hosted_once_fixture_only_required')
    import frida
    if frida.__version__!='17.24.2':raise SystemExit('pinned_frida_required')
    # Small environment, no GitHub credentials inherited by fixture processes.
    names={'SYSTEMROOT','WINDIR','PATH','TEMP','TMP','COMSPEC','PATHEXT','PROGRAMFILES','PROGRAMFILES(X86)','PROGRAMDATA','USERPROFILE','LOCALAPPDATA','APPDATA','ALLUSERSPROFILE','HOMEDRIVE','HOMEPATH','NUMBER_OF_PROCESSORS','PROCESSOR_ARCHITECTURE','PROCESSOR_IDENTIFIER'}
    env={k:v for k,v in os.environ.items() if k.upper() in names}
    report={'schema':'bnet-h3-owned-fixtures-5','source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],
            'target_launched':False,'game_download_requested':False,'raw_values_exported':False,'tls_validation_changed':False,
            'scope':'owned_loopback_and_example_com_only','async_scope':'event_and_registered_win32_callbacks_only',
            'diagnostic_counters_partial':True,'iocp_supported':False,'callback_supported':False,'all_network_paths_covered':False,'passed':False,'fixtures':[]}
    report['fixtures']=[fixture(frida,arch,env) for arch in ('x64','x86')]
    report['passed']=all(x['passed'] for x in report['fixtures'])
    validate(report);out=Path('output');out.mkdir(exist_ok=True)
    (out/'prelogin-h3-fixtures.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'owned_fixture_gate_passed':report['passed'],'target_launched':False}))
if __name__=='__main__':main()
