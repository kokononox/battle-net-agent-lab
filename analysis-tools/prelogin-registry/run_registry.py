"""Fresh guarded prelogin lifecycle, plus baseline and passive fixed-key API trace."""
import json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(HERE.parent/'prelogin-host-lifecycle'));sys.path.insert(0,str(HERE.parent/'prelogin-wire-h3'));sys.path.append(str(HERE.parent/'prelogin-wire-h2'))
from validate_registry import validate,blank
KEY=r'Software\Blizzard Entertainment\Blizzard Error'
def baseline():
    import winreg
    r=dict(status='error',value_present=False,valid_uuid=False)
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,KEY,0,winreg.KEY_READ) as k:v,t=winreg.QueryValueEx(k,'UserUUID')
        from registry_events import UUID
        r.update(status='present',value_present=True,valid_uuid=bool(t==winreg.REG_SZ and isinstance(v,str) and UUID.fullmatch(v.encode('ascii',errors='replace'))))
    except FileNotFoundError:r['status']='absent'
    except OSError:pass
    return r

def main():
    if not(sys.platform=='win32' and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1' and os.environ.get('GITHUB_EVENT_NAME')=='push' and os.environ.get('GITHUB_REF')=='refs/heads/research/prelogin-telemetry-wow-data-provenance' and os.environ.get('BNET_REGISTRY_TRACE')=='approved-registry-trace-a11'):raise SystemExit('fresh_hosted_once_required')
    r=blank(os.environ['GITHUB_SHA'],os.environ['GITHUB_RUN_ID']);out=Path('output');out.mkdir(exist_ok=True)
    import run_lifecycle as lifecycle,trace_manager
    old_first=lifecycle.first.Manager;old_second=lifecycle.Manager;old_tracking=lifecycle.Tracking;old_flag=os.environ.get('BNET_HOST_LIFECYCLE');trackers=[]
    class Tracking(old_tracking):
        def __init__(self,delegate):super().__init__(delegate);trackers.append(self)
    try:
        import frida,observe_agent as obs
        if frida.__version__!='17.24.2':raise RuntimeError('frida')
        from native_gate import fixture
        env=obs.clean_environment(os.environ)
        r['native_gate']=[fixture(frida,a,env) for a in ('x64','x86')]
        if not all(x['passed'] for x in r['native_gate']):r['status']='native_gate_failed_no_target';return
        trace_manager.REGISTRY_MANAGERS.clear();r['baseline_before_target']=baseline()
        if r['baseline_before_target']['status']=='error':r['status']='baseline_failed_no_target';return
        lifecycle.first.Manager=trace_manager.Manager;lifecycle.Manager=trace_manager.Manager;lifecycle.Tracking=Tracking
        os.environ['BNET_HOST_LIFECYCLE']='approved-host-lifecycle-20261024-a10'
        lifecycle.main()
        from validate_lifecycle import load
        result=load((out/'prelogin-host-lifecycle.json').read_bytes());r['lifecycle_comparison']=result['comparison'];r['target_launched']=any(x['launched'] for x in result['phases'])
        for i,m in enumerate(trace_manager.REGISTRY_MANAGERS):
            values=trackers[i].values if i<len(trackers) else set();t=m.registry.summary(values)
            t['phase']=('first','second')[i] if i<2 else 'other';t['wire_linked_hardware_requests']=result['phases'][i]['wire_linked_hardware_requests'] if i<len(result['phases']) else 0
            t['all_processes_registry_ready']=bool(m.rows) and all(p in m.registry.ready for p in m.rows)
            t['wire_collector_clean']=not m.fatal and not m.dropped and all(x['script_errors']==0 for x in m.rows.values())
            r['phases'].append(t)
        r['baseline_after_target']=baseline()
        clean=len(r['phases'])==2 and result['comparison'] is not None and all(p['errors']==p['limits']==0 and p['all_processes_registry_ready'] and p['wire_collector_clean'] and p['wire_linked_hardware_requests']>0 for p in r['phases'])
        r['status']='observation_complete' if clean else 'inconclusive'
        if clean:
            r['registry_read_equals_wire_host_id']=all(any(x['operation']=='read' and x['status']==0 and x['equals_wire_host_id'] and x['process_sha256']=='b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5' for x in p['records']) for p in r['phases'])
            r['successful_matching_write_observed']=any(x['operation']=='write' and x['status']==0 and x['equals_wire_host_id'] for p in r['phases'] for x in p['records'])
    except Exception:r['status']='stopped'
    finally:
        lifecycle.first.Manager=old_first;lifecycle.Manager=old_second;lifecycle.Tracking=old_tracking
        if old_flag is None:os.environ.pop('BNET_HOST_LIFECYCLE',None)
        else:os.environ['BNET_HOST_LIFECYCLE']=old_flag
        if r['status']!='observation_complete':r['registry_read_equals_wire_host_id']=False;r['successful_matching_write_observed']=False
        validate(r);(out/'prelogin-registry-runtime.json').write_text(json.dumps(r,indent=2)+'\n')
        print(json.dumps({'status':r['status'],'registry_read_equals_wire_host_id':r['registry_read_equals_wire_host_id']}))
if __name__=='__main__':main()
