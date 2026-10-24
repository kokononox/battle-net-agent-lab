"""One-shot hosted Windows, native wire gate before any signed target startup.
No account login, game download, Install click, CA/keylog changes or raw artifacts.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.append(str(ROOT/'analysis-tools'/'prelogin-wire-h2'))
from manager import Manager
from native_identity import identity
from process_handle import Process
from capture import Capture
from correlate import analyze
from target_validate import validate
from fixture_only import fixture
from validate import validate as validate_fixture

PIN='f4643a2086c0cecb1ab68cc601bf38c1a0a6f7ef5914ad03375cc9449385bec6'
BRANCH='refs/heads/research/prelogin-telemetry-wow-data-provenance'


def gate(frida,env):
    r={'schema':'bnet-h3-owned-fixtures-4','source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],
       'target_launched':False,'game_download_requested':False,'raw_values_exported':False,'tls_validation_changed':False,
       'scope':'owned_loopback_and_example_com_only','async_scope':'event_and_registered_win32_callbacks_only',
       'iocp_supported':False,'callback_supported':False,'all_network_paths_covered':False,'passed':False,'fixtures':[]}
    r['fixtures']=[fixture(frida,arch,env) for arch in ('x64','x86')]
    r['passed']=all(x['passed'] for x in r['fixtures'])
    validate_fixture(r)
    return r


def main():
    allowed=(sys.platform=='win32' and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_OS')=='Windows' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1' and os.environ.get('GITHUB_REF')==BRANCH and os.environ.get('BNET_WIRE_H3')=='approved-wire-h3-20261024-e1')
    if not allowed:raise SystemExit('fresh_hosted_once_required')
    source=os.environ.get('GITHUB_SHA','');run=os.environ.get('GITHUB_RUN_ID','')
    if not re.fullmatch('[0-9a-f]{40}',source) or not run.isdigit():raise SystemExit('run_identity')
    out=Path('output');out.mkdir(exist_ok=True)
    report={'schema':'bnet-prelogin-wire-h3-target-1','source_commit':source,'run_id':run,
            'status':'not_started','error_code':None,'selftest':None,'bootstrap_pin_match':None,
            'target_launched':False,'async_scope':'event_and_registered_win32_callbacks_only','processes':[],'requests':[],'parse_states':{},
            'network_linked_hardware_requests':0,'request_count':0,
            'capture':None,'collector_errors':0,'dropped_events':0,'collector_fatal':False,
            'limits':{'server_storage_proven':False,'all_network_paths_covered':False,
                      'raw_values_exported':False,'login_performed':False,'game_download_requested':False,
                      'install_action_requested':False,'tls_validation_changed':False,
                      'sspi_http1_only':True,'all_async_completion_methods_supported':False,
                      'circular_capture_can_drop_early_packets':True}}
    import frida
    import observe_agent as obs
    manager=None;capture=None;handles=[];images={};ids={};setup_path=None
    original_popen=subprocess.Popen;original_fetch=obs.fetch_setup
    env=obs.clean_environment(os.environ)
    def verify(pid,recheck=False):
        info=identity(pid);path=Path(info['path'])
        if recheck:
            if ids[pid]!=(info['creation'],str(path).lower()):raise obs.LabError('pid_identity_changed')
            return {}
        if path.name.lower() not in obs.NAMES or obs.is_reparse(path) or not 0<path.stat().st_size<=128*1024*1024:raise obs.LabError('image_refused')
        signature=obs.signature(path,env)
        if not signature['accepted_for_execution']:raise obs.LabError('signature_refused')
        data=path.read_bytes();digest=hashlib.sha256(data).hexdigest()
        if sum(map(len,images.values()))+len(data)>256*1024*1024:raise obs.LabError('image_budget')
        images[digest]=data;ids[pid]=(info['creation'],str(path).lower())
        return {'process_name':path.name.lower(),'sha256':digest,'image_bytes':len(data),
                'authenticode_valid':True,'expected_blizzard_publisher':True}
    def fetch(destination):
        nonlocal setup_path
        result=original_fetch(destination);report['bootstrap_pin_match']=result['sha256']==PIN
        if not report['bootstrap_pin_match']:
            destination.unlink(missing_ok=True);raise obs.LabError('bootstrap_pin_mismatch_refused')
        setup_path=destination.resolve();return result
    def launch(argv,*args,**kwargs):
        if setup_path is not None and isinstance(argv,(list,tuple)) and len(argv)==1 and Path(argv[0]).resolve()==setup_path:
            if handles:raise obs.LabError('duplicate_setup_refused')
            pid=manager.spawn(argv,kwargs['env'],kwargs['cwd']);h=Process(manager,pid);handles.append(h);report['target_launched']=True;return h
        return original_popen(argv,*args,**kwargs)
    try:
        if frida.__version__!='17.24.2':raise RuntimeError('frida_version')
        report['status']='native_gate';report['selftest']=gate(frida,env)
        if not report['selftest']['passed']:
            report['status']='native_gate_failed_no_installer';report['error_code']='native_gate_failed';return
        if obs.snapshot(env).get('processes'):raise RuntimeError('preexisting_processes')
        import winreg
        cpu=None
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as key:cpu=winreg.QueryValueEx(key,'ProcessorNameString')[0].strip()[:160]
        except OSError:pass
        with tempfile.TemporaryDirectory(prefix='h3-real-',dir=os.environ['RUNNER_TEMP']) as tmp:
            capture=Capture(tmp,env);capture.start();manager=Manager(frida,verify)
            obs.fetch_setup=fetch;subprocess.Popen=launch
            try:
                base=obs.observe(out,90,advance_language=True,advance_install=False)
                report['status']='observation_complete' if base['status']!='stopped' else 'target_stopped'
                if base['error_code']=='bootstrap_pin_mismatch_refused':report['error_code']='bootstrap_pin_mismatch_refused'
            finally:
                subprocess.Popen=original_popen;obs.fetch_setup=original_fetch
                manager.close();packets=capture.finish();report['capture']=capture.meta
            from classify import Classifier
            report.update(analyze(manager.inputs,packets,Classifier(images,cpu)))
            rows=list(manager.rows.values());report['collector_errors']=sum(x['script_errors'] for x in rows)
            report['dropped_events']=manager.dropped;report['collector_fatal']=manager.fatal
            report['processes']=[{'name':r['process_name'] if r['process_name'] in obs.NAMES else 'other','sha256':r['sha256'],
                                  'instrumented_before_resume':r['instrumented_before_resume'],'script_errors':r['script_errors'],'pointer_bits':r['pointer_bits'],
                                  'diagnostics':r['diagnostics'],'observations':r['observations'],
                                  'completed_operations':r['completed_operations'],
                                  'unresolved_async_events':sum(e.get('pid')==r['pid'] and e.get('asynchronous') is True and not e.get('completion_proven') and not e.get('immediate_completion') for e in manager.inputs),
                                  'unlinked_immediate_events':sum(e.get('pid')==r['pid'] and e.get('asynchronous') is True and not e.get('completion_proven') and e.get('immediate_completion') is True for e in manager.inputs)} for r in rows]
            # Fail closed for a bounded/incomplete collector: no elevated verdict.
            if manager.fatal or manager.dropped or report['collector_errors']:
                report['status']='collector_incomplete'
                report['network_linked_hardware_requests']=0
                for r in report['requests']:r.update(socket_send_linked=False,packet_bytes_linked=False,http_response_status=None)
    except Exception:
        report['status']='stopped';report['error_code']='bounded_h3_failed'
    finally:
        subprocess.Popen=original_popen;obs.fetch_setup=original_fetch
        if manager and not manager.stop.is_set():manager.close()
        if capture and capture.active:
            try:capture.finish()
            except Exception:pass
        for h in handles:h.close()
        validate(report)
        (out/'prelogin-wire-h3-target.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'status':report['status'],'target_launched':report['target_launched'],'wire_linked_hardware_requests':report['network_linked_hardware_requests']}))


if __name__=='__main__':main()
