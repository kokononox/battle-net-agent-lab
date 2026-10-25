"""x86/x64 owned synthetic registry fixture; no target key writes or networking."""
import hashlib,os,subprocess,tempfile,time
from pathlib import Path
from trace_manager import Manager
from native_identity import identity
from process_handle import Process
SYN=b'abcdefab-abcd-4abc-abcd-abcdefabcdef'
def fixture(frida,arch,env):
    r=dict(architecture=arch,passed=False,exit_code=None,instrumented=False,bitness_confirmed=False,read_a=False,read_w=False,get_w=False,write_w=False,size_only_not_uuid=False,errors=0,limits=0)
    manager=None
    try:
        with tempfile.TemporaryDirectory(prefix='owned-registry-',dir=os.environ['RUNNER_TEMP']) as tmp:
            work=Path(tmp);exe=work/'RegistryProbe.exe';compiler=Path(os.environ['SystemRoot'])/'Microsoft.NET'/'Framework64'/'v4.0.30319'/'csc.exe'
            p=subprocess.run([str(compiler),'/nologo','/warn:0','/target:exe','/platform:'+arch,'/out:'+str(exe),str(Path(__file__).with_name('registry_probe.cs'))],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
            if p.returncode or not exe.is_file():return r
            digest=hashlib.sha256(exe.read_bytes()).hexdigest();ids={}
            def verify(pid,recheck=False):
                info=identity(pid)
                if Path(info['path']).resolve()!=exe.resolve() or hashlib.sha256(exe.read_bytes()).hexdigest()!=digest:raise RuntimeError('fixture_image')
                if recheck:
                    if ids[pid]!=info['creation']:raise RuntimeError('identity')
                    return {}
                ids[pid]=info['creation'];return dict(process_name='owned_fixture.exe',sha256=digest,image_bytes=exe.stat().st_size)
            manager=Manager(frida,verify)
            try:
                pid=manager.spawn([exe],env,work);h=Process(manager,pid)
                try:r['exit_code']=h.wait(timeout=40)
                finally:h.close()
                time.sleep(.5)
            finally:manager.close()
            es=manager.registry.values
            for k,api in [('read_a','RegQueryValueExA'),('read_w','RegQueryValueExW'),('get_w','RegGetValueW'),('write_w','RegSetValueExW')]:r[k]=any(x['api']==api and x['label']=='probe' and x['status']==0 and x['value']==SYN for x in es)
            r['size_only_not_uuid']=any(x['api']=='RegQueryValueExW' and x['status']==0 and x['value'] is None for x in es)
            rows=list(manager.rows.values());r['instrumented']=len(rows)==1 and rows[0]['instrumented_before_resume'];r['bitness_confirmed']=len(rows)==1 and rows[0]['pointer_bits']==(32 if arch=='x86' else 64)
            r['errors']=manager.registry.errors+sum(x['script_errors'] for x in rows);r['limits']=manager.registry.limits+manager.dropped+int(manager.fatal)
            r['passed']=r['exit_code']==0 and all(r[k] for k in ('instrumented','bitness_confirmed','read_a','read_w','get_w','write_w','size_only_not_uuid')) and r['errors']==r['limits']==0
    except Exception:pass
    finally:
        if manager and not manager.stop.is_set():manager.close()
    return r
