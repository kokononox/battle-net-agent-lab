"""Build native guard, prove three synthetic stop cases, then run nonfinalizing Agent."""
import json,os,re,subprocess,sys
from pathlib import Path
import guard_report as g
HERE=Path(__file__).resolve().parent

def build(receipt):
 vs=Path(os.environ.get('ProgramFiles(x86)','C:/Program Files (x86)'))/'Microsoft Visual Studio/Installer/vswhere.exe'
 receipt['stage']='vswhere_query'
 result=subprocess.run([str(vs),'-latest','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],capture_output=True,text=True,timeout=20)
 receipt['vswhere_exit_code']=result.returncode
 installation=result.stdout.strip()
 if result.returncode or not installation or '\n'in installation:receipt['stage']='vswhere_refused';raise RuntimeError('build_failed')
 receipt['installation_found']=True
 dev=Path(installation)/'Common7/Tools/VsDevCmd.bat';receipt['devcmd_found']=dev.is_file()
 if not receipt['devcmd_found']:receipt['stage']='devcmd_missing';raise RuntimeError('build_failed')
 out=Path('output').resolve();out.mkdir(exist_ok=True);exe=out/'retail_guard.exe';source=HERE/'guard.cpp';log=out/'retail-guard-build.private.log'
 if any('"'in str(p) or '\n'in str(p) for p in (dev,exe,source,log)):raise RuntimeError('build_failed')
 receipt['stage']='compile'
 batch=Path('output/retail_guard_build.cmd')
 command='@echo off\ncall "'+str(dev)+'" -no_logo -arch=x64 -host_arch=x64 >nul 2>&1\nif errorlevel 1 exit /b 90\nwhere cl >nul 2>&1\nif errorlevel 1 exit /b 91\ncl /nologo /EHsc /std:c++17 /W4 /Fe:"'+str(exe)+'" /Fo:"'+str(out/'retail_guard.obj')+'" "'+str(source)+'" >"'+str(log)+'" 2>&1\nexit /b %errorlevel%\n'
 batch.write_text(command,encoding='utf-8')
 result=subprocess.run([os.environ.get('COMSPEC','cmd.exe'),'/d','/c',str(batch)],capture_output=True,timeout=120);receipt['compiler_exit_code']=result.returncode
 if log.is_file():
  with log.open('rb')as f:text=f.read(65536).decode('utf-8',errors='replace')
  receipt['compiler_error_codes']=sorted(set(re.findall(r'(?:fatal error|error) ((?:C|D)[0-9]{4}|LNK[0-9]{4})',text)))[:8]
  receipt['source_error_lines']=sorted(set(int(x)for x in re.findall(r'guard\.cpp\(([0-9]{1,4})(?:,[0-9]+)?\).*?(?:fatal error|error) ',text)))[:8]
 if result.returncode or not exe.is_file():raise RuntimeError('build_failed')
 receipt['stage']='compiled'
 return exe

def main():
 from run_prepare import authorized
 if not authorized(os.environ,sys.platform):raise SystemExit('fresh_hosted_once_required')
 r=g.blank(os.environ['GITHUB_SHA'],os.environ['GITHUB_RUN_ID']);Path('output').mkdir(exist_ok=True)
 try:
  exe=build(r['build'])
  for mode in ('fixture_timeout','fixture_network','fixture_disk','fixture_phase_timeout','fixture_phase_network'):
   result=subprocess.run([str(exe),mode],timeout=20)
   rec=g.receipt(g.read('output/retail-supervisor-'+mode+'.json'));r['fixtures'][mode]=rec
   if result.returncode or not g.fixture_passed(rec):raise RuntimeError('fixture_failed')
  result=subprocess.run([str(exe),'observe',sys.executable],timeout=270)
  r['observation']=g.receipt(g.read('output/retail-supervisor-observe.json'))
  if result.returncode:raise RuntimeError('native_failed')
  r['status']='completed'
 except Exception as exc:
  name=str(exc) if type(exc)is RuntimeError else 'other'
  r.update(status='refused',error_kind=name if name in {'build_failed','fixture_failed','native_failed'}else 'other')
 finally:
  g.validate(r);Path('output/retail-supervision.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(dict(supervision_status=r['status'],error_kind=r['error_kind'])))
 if r['status']!='completed':raise SystemExit(2)
if __name__=='__main__':main()
