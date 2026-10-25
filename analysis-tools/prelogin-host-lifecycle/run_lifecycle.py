"""Two bounded bootstrap startups on ONE disposable runner, config untouched.
No Install click, reboot, uninstall, login, game download or identifier export.
The frozen H3 entrypoint performs the first clean startup plus native gate;
only a tracking classifier wrapper observes private host_id values in memory.
"""
import hashlib,json,os,re,sys,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(HERE.parent/'prelogin-wire-h3'))
sys.path.append(str(HERE.parent/'prelogin-wire-h2'))
from identity_compare import Tracking,compare,eligible
from phase_diagnostics import blank_debug,collect_diagnostics,error_kind
from validate_lifecycle import validate,LIMITS
import target_run as first
from manager import Manager
from native_identity import identity
from process_handle import Process
from capture_diagnostics import Capture
from correlate import analyze
from target_validate import load as load_first
BRANCH='refs/heads/research/prelogin-telemetry-wow-data-provenance'

def blank():
    return dict(launched=False,completed=False,bootstrap_pin_match=False,instrumented_processes=0,
        collector_errors=0,dropped_events=0,collector_fatal=False,request_count=0,hardware_requests=0,
        wire_linked_hardware_requests=0,host_id_observations=0,host_id_unique=0,invalid_host_id_events=0,
        all_processes_instrumented=False,language_status='not_observed')

def fold_analysis(p,a,t):
    p.update(request_count=a['request_count'],hardware_requests=sum(x['hardware_payload_verified'] for x in a['requests']),
        wire_linked_hardware_requests=a['network_linked_hardware_requests'],**t.summary())
    if p['collector_errors'] or p['dropped_events'] or p['collector_fatal']:p['wire_linked_hardware_requests']=0

def second_start(frida,env,setup,p,trackers,diag):
    import observe_agent as obs
    from classify import Classifier
    from language_step import run as language_run
    import native_gui
    images={};ids={};manager=None;capture=None;handle=None
    # Recheck original download before launch, and pin both agent mapping and root.
    diag['stage']='pin'
    if obs.is_reparse(setup) or hashlib.sha256(setup.read_bytes()).hexdigest()!=first.PIN:raise RuntimeError('pin')
    if not obs.signature(setup,env)['accepted_for_execution']:raise RuntimeError('signature')
    p['bootstrap_pin_match']=True
    def verify(pid,recheck=False):
        info=identity(pid);path=Path(info['path'])
        if recheck:
            if ids[pid]!=(info['creation'],str(path).lower()):raise RuntimeError('identity')
            return {}
        helper=path.name.lower()=='agenthelper.exe'
        if path.name.lower() not in obs.NAMES and not helper:
            from refused_image import inspect_refused
            diag['refusal_reason']='unexpected_image_name'
            diag['refused_image']=inspect_refused(path,env,obs.is_reparse)
            raise RuntimeError('image')
        if obs.is_reparse(path):
            diag['refusal_reason']='reparse_or_missing_image';raise RuntimeError('image')
        if not 0<path.stat().st_size<=128*1024*1024:
            diag['refusal_reason']='image_size';raise RuntimeError('image')
        sig=obs.signature(path,env)
        if not sig['accepted_for_execution']:
            diag['refusal_reason']='image_signature';raise RuntimeError('signature')
        data=path.read_bytes();digest=hashlib.sha256(data).hexdigest()
        if helper:
            from approved_helper import decision
            parent_id=manager.rows[pid]['parent_pid'];parent_row=manager.rows.get(parent_id,{})
            parent_info=identity(parent_id);parent_path=Path(parent_info['path'])
            old_parent=ids.get(parent_id)
            creation_matches=bool(old_parent and old_parent[0]==parent_info['creation'])
            path_matches=bool(old_parent and old_parent[1]==str(parent_path).lower())
            parent_image_matches=False
            if not obs.is_reparse(parent_path) and 0<parent_path.stat().st_size<=128*1024*1024:
                parent_digest=hashlib.sha256(parent_path.read_bytes()).hexdigest()
                parent_sig=obs.signature(parent_path,env)
                parent_image_matches=parent_digest==parent_row.get('sha256') and parent_sig['accepted_for_execution'] is True
            # Same Windows process creation + exact trusted parent image. An updater
            # pathname change alone is not PID reuse; it remains diagnostic.
            parent_matches=creation_matches and parent_image_matches
            policy=decision(path,parent_path,parent_row,digest,sig,env,parent_matches,obs.is_reparse,identity_diagnostics=dict(parent_creation_matches=creation_matches,parent_path_matches=path_matches,parent_live_image_pinned=parent_image_matches))
            diag['helper_decisions'].append(policy)
            if not policy['approved']:
                from refused_image import inspect_refused
                diag['refusal_reason']='helper_policy_refused';diag['refused_image']=inspect_refused(path,env,obs.is_reparse)
                raise RuntimeError('helper_policy')
        if sum(map(len,images.values()))+len(data)>256*1024*1024:raise RuntimeError('budget')
        images[digest]=data;ids[pid]=(info['creation'],str(path).lower())
        return dict(process_name=path.name.lower(),sha256=digest,image_bytes=len(data),authenticode_valid=True,expected_blizzard_publisher=True)
    # Read CPU solely to preserve existing hardware decoder behavior; not exported.
    cpu=None
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as k:cpu=winreg.QueryValueEx(k,'ProcessorNameString')[0].strip()[:160]
    except OSError:pass
    with tempfile.TemporaryDirectory(prefix='host-lifecycle-',dir=os.environ['RUNNER_TEMP']) as tmp:
        try:
            diag['stage']='capture';capture=Capture(tmp,env);capture.start();manager=Manager(frida,verify)
            diag['stage']='spawn'
            pid=manager.spawn([setup],env,setup.parent);handle=Process(manager,pid);p['launched']=True
            diag['stage']='observe'
            start=time.monotonic();inspected=False
            while time.monotonic()-start<90:
                if manager.fatal:raise RuntimeError('collector')
                if not inspected and time.monotonic()-start>=5:
                    inspected=True
                    def advance(targets):
                        r=language_run(targets,pid,setup,authorized=True)
                        p['language_status']='continued' if r['status']=='continued' else ('not_language_page' if r['status']=='page_not_language' else 'other')
                    # Only verified owned processes. The language helper additionally
                    # requires root PID, signed expected setup and exact language page.
                    native_gui.inspect(set(manager.owned),round(time.monotonic()-start,2),on_visible_targets=advance)
                time.sleep(.25)
            p['completed']=True
        except Exception as exc:
            diag['error_type']=error_kind(type(exc).__name__)
        finally:
            if manager:manager.close()
            if handle:handle.close()
            if manager:
                rows=list(manager.rows.values());collect_diagnostics(p,diag,manager)
            try:packets=capture.finish() if capture else {'runs':[]}
            except Exception as exc:
                diag['error_type']=error_kind(type(exc).__name__);p['completed']=False;packets={'runs':[]}
            if manager:
                tracker=Tracking(Classifier(images,cpu));trackers.append(tracker)
                try:fold_analysis(p,analyze(manager.inputs,packets,tracker),tracker)
                except Exception as exc:
                    diag['error_type']=error_kind(type(exc).__name__);p['completed']=False;p['wire_linked_hardware_requests']=0
            if diag['error_type'] is not None:p['completed']=False;p['wire_linked_hardware_requests']=0
            else:diag['stage']='complete'
            # All failure diagnostics are retained, never an exception string.


def main():
    if not (sys.platform=='win32' and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_OS')=='Windows' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1' and os.environ.get('GITHUB_EVENT_NAME')=='push' and os.environ.get('GITHUB_REF')==BRANCH and os.environ.get('BNET_HOST_LIFECYCLE')=='approved-host-lifecycle-20261024-a10'):raise SystemExit('fresh_hosted_once_required')
    report=dict(schema='bnet-host-lifecycle-7',source_commit=os.environ['GITHUB_SHA'],run_id=os.environ['GITHUB_RUN_ID'],status='stopped',error_code=None,first_native_gate_passed=False,same_machine=True,configuration_preserved=True,second_start_clean_processes=False,comparison=None,phases=[],storage_scans=[],second_diagnostics=blank_debug(),limits=dict(LIMITS))
    trackers=[];original_analyze=first.analyze;old_flag=os.environ.get('BNET_WIRE_H3')
    def observe_first(events,packets,classifier):
        tracker=Tracking(classifier);trackers.append(tracker)
        return original_analyze(events,packets,tracker)
    out=Path('output');out.mkdir(exist_ok=True)
    try:
        import frida,observe_agent as obs
        if frida.__version__!='17.24.2':raise RuntimeError('frida')
        first.analyze=observe_first
        # Explicit authorized delegation to the unchanged guarded first-startup driver.
        os.environ['BNET_WIRE_H3']='approved-wire-h3-20261024-e7'
        first.main()
        a=load_first((out/'prelogin-wire-h3-target.json').read_bytes())
        report['first_native_gate_passed']=bool(a['selftest'] and a['selftest']['passed'])
        p=blank();report['phases'].append(p)
        p.update(launched=a['target_launched'],completed=a['status']=='observation_complete',bootstrap_pin_match=a['bootstrap_pin_match'] is True,instrumented_processes=len(a['processes']),all_processes_instrumented=bool(a['processes']) and all(x['instrumented_before_resume'] for x in a['processes']),collector_errors=a['collector_errors'],dropped_events=a['dropped_events'],collector_fatal=a['collector_fatal'])
        if len(trackers)==1:fold_analysis(p,a,trackers[0])
        if not eligible(p):report.update(status='inconclusive',error_code='first_phase_ineligible');return
        env=obs.clean_environment(os.environ)
        from storage_scan import scan
        report['storage_scans'].append(scan(trackers[0].values,env,'after_first',trackers[0].delegate.images))
        for _ in range(20):
            if not obs.snapshot(env).get('processes'):break
            time.sleep(.5)
        if obs.snapshot(env).get('processes'):raise RuntimeError('remaining_processes')
        report['second_start_clean_processes']=True
        # Same bootstrapper, exact original location and untouched machine/config.
        setup=Path(os.environ['RUNNER_TEMP'])/('bnet-observe-'+os.environ['GITHUB_RUN_ID']+'-1')/'Battle.net-Setup.exe'
        p=blank();report['phases'].append(p);second_start(frida,env,setup,p,trackers,report['second_diagnostics'])
        if len(trackers)==2 and eligible(p):report['storage_scans'].append(scan(trackers[1].values,env,'after_second',trackers[1].delegate.images))
        result=compare(trackers[0],trackers[1],report['phases']) if len(trackers)==2 else None
        report['comparison']=result
        report['status']=('same_host_id_after_process_restart' if result else 'changed_host_id_after_process_restart') if result is not None else 'inconclusive'
        if result is None:report['error_code']='second_phase_ineligible'
    except Exception:
        report.update(status='stopped',error_code='bounded_lifecycle_failed',comparison=None)
        # No elevated partial wire claims after an interrupted phase.
        for p in report['phases']:
            if not p['completed']:p['wire_linked_hardware_requests']=0
    finally:
        first.analyze=original_analyze
        if old_flag is None:os.environ.pop('BNET_WIRE_H3',None)
        else:os.environ['BNET_WIRE_H3']=old_flag
        validate(report);(out/'prelogin-host-lifecycle.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'status':report['status'],'phase_count':len(report['phases']),'private_identifier_exported':False}))
if __name__=='__main__':main()
