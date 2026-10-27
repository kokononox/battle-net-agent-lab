"""Owned x86/x64 ordinary-Popen fixtures; no target, registry or network hooks."""
import hashlib,os,subprocess,tempfile
from pathlib import Path
from attach_session import Session,kind
from native_identity import identity

def fixture(frida,device,arch,env):
 r=dict(architecture=arch,passed=False,exit_code=None,attach=None,error_kind=None);handle=None;session=None
 try:
  with tempfile.TemporaryDirectory(prefix='owned-minimal-',dir=os.environ['RUNNER_TEMP']) as tmp:
   work=Path(tmp);exe=work/'MinimalProbe.exe'
   vswhere=Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio'/'Installer'/'vswhere.exe'
   vs=subprocess.check_output([str(vswhere),'-latest','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],env=env,timeout=15).decode().strip()
   vc=Path(vs)/'VC'/'Auxiliary'/'Build'/'vcvarsall.bat'
   if not vc.is_file():raise RuntimeError('compiler_unavailable')
   cmd=work/'build.cmd';source=Path(__file__).with_name('fixture.cpp')
   cmd.write_text('@echo off\ncall "'+str(vc)+'" '+arch+' >nul\nif errorlevel 1 exit /b 1\ncl /nologo /W4 /WX /Od /GS /EHsc "'+str(source)+'" /link /OUT:"'+str(exe)+'"\n')
   build=subprocess.run([os.environ['COMSPEC'],'/d','/c',str(cmd)],env=env,cwd=work,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90)
   if build.returncode or not exe.is_file():raise RuntimeError('compile_failed')
   digest=hashlib.sha256(exe.read_bytes()).hexdigest();handle=subprocess.Popen([str(exe)],env=env,cwd=work,stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   original=None
   def verify():
    nonlocal original
    i=identity(handle.pid);now=(i['creation'],str(Path(i['path']).resolve()).lower())
    if handle.poll() is not None or Path(i['path']).resolve()!=exe.resolve() or hashlib.sha256(exe.read_bytes()).hexdigest()!=digest:raise RuntimeError('fixture_identity')
    if original is not None and original!=now:raise RuntimeError('identity_changed')
    original=now
   session=Session(frida,device)
   try:
    r['attach']=session.start(handle.pid,verify,32 if arch=='x86' else 64)
    handle.stdin.write(b'\n');handle.stdin.flush();handle.stdin.close();r['exit_code']=handle.wait(timeout=10)
   finally:
    session.close()
    if handle.poll() is None:handle.kill();handle.wait(timeout=5)
   r['passed']=r['exit_code']==0 and r['attach']['status']=='ready'
 except Exception as exc:r['error_kind']=kind(exc)
 finally:
  if session:session.close()
  if handle is not None:
   if handle.poll() is None:handle.kill();handle.wait(timeout=5)
   if handle.stdin and not handle.stdin.closed:handle.stdin.close()
 return r
