"""x86/x64 owned synthetic registry fixture; no target key writes or networking."""
import hashlib,os,subprocess,tempfile,time
from pathlib import Path
from trace_manager import Manager
from native_identity import identity
from process_handle import Process
SYN=b'abcdefab-abcd-4abc-abcd-abcdefabcdef'
def fixture(frida,arch,env):
    r=dict(architecture=arch,passed=False,exit_code=None,instrumented=False,bitness_confirmed=False,read_a=False,read_w=False,get_w=False,write_w=False,size_only_not_uuid=False,read_w_main_frame=False,write_w_main_frame=False,accurate_stack_captured=False,scope_diagnostics=dict(verified_image_found=False,process_main_matches_verified_image=False,direct_caller_found=False),errors=0,limits=0)
    manager=None
    try:
        with tempfile.TemporaryDirectory(prefix='owned-registry-',dir=os.environ['RUNNER_TEMP']) as tmp:
            work=Path(tmp);exe=work/'RegistryProbe.exe'
            vswhere=Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio'/'Installer'/'vswhere.exe'
            vs=subprocess.check_output([str(vswhere),'-latest','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],timeout=15).decode().strip()
            vc=Path(vs)/'VC'/'Auxiliary'/'Build'/'vcvarsall.bat'
            if not vc.is_file():return r
            script=work/'build.cmd';source=Path(__file__).with_name('registry_probe.cpp')
            script.write_text('@echo off\ncall "'+str(vc)+'" '+arch+' >nul\nif errorlevel 1 exit /b 1\ncl /nologo /W4 /WX /Od /Oy- /Zi /GS /EHsc "'+str(source)+'" advapi32.lib /link /OUT:"'+str(exe)+'" /DEBUG /PDB:"'+str(work/'probe.pdb')+'"\n')
            result=subprocess.run([os.environ['COMSPEC'],'/d','/c',str(script)],cwd=work,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90)
            if result.returncode or not exe.is_file():return r
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
            r['scope_diagnostics']=dict(verified_image_found=bool(es) and all(x['image_scope']=='verified' for x in es),process_main_matches_verified_image=bool(es) and all(x['process_main_matches_verified_image'] for x in es),direct_caller_found=any(x['caller_rva'] is not None for x in es))
            r['read_w_main_frame']=any(x['api']=='RegQueryValueExW' and x['status']==0 and x['value']==SYN and x['verified_image_stack_rvas'] for x in es)
            r['write_w_main_frame']=any(x['api']=='RegSetValueExW' and x['status']==0 and x['value']==SYN and x['verified_image_stack_rvas'] for x in es)
            r['accurate_stack_captured']=bool(es) and all(x['stack_status']=='captured' for x in es)
            rows=list(manager.rows.values());r['instrumented']=len(rows)==1 and rows[0]['instrumented_before_resume'];r['bitness_confirmed']=len(rows)==1 and rows[0]['pointer_bits']==(32 if arch=='x86' else 64)
            r['errors']=manager.registry.errors+sum(x['script_errors'] for x in rows);r['limits']=manager.registry.limits+manager.dropped+int(manager.fatal)
            r['passed']=r['exit_code']==0 and all(r[k] for k in ('instrumented','bitness_confirmed','read_a','read_w','get_w','write_w','size_only_not_uuid','read_w_main_frame','write_w_main_frame','accurate_stack_captured')) and r['errors']==r['limits']==0
    except Exception:pass
    finally:
        if manager and not manager.stop.is_set():manager.close()
    return r
