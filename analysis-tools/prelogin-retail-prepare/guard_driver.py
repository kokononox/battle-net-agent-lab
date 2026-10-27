"""Build native guard, prove three synthetic stop cases, then run nonfinalizing Agent."""
import json,os,subprocess,sys
from pathlib import Path
import guard_report as g
HERE=Path(__file__).resolve().parent

def build():
 vs=Path(os.environ.get('ProgramFiles(x86)','C:/Program Files (x86)'))/'Microsoft Visual Studio/Installer/vswhere.exe'
 result=subprocess.run([str(vs),'-latest','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],capture_output=True,text=True,timeout=20)
 installation=result.stdout.strip()
 if result.returncode or not installation or '\n'in installation:raise RuntimeError('build_failed')
 dev=Path(installation)/'Common7/Tools/VsDevCmd.bat';out=Path('output').resolve();out.mkdir(exist_ok=True)
 exe=out/'retail_guard.exe';source=HERE/'guard.cpp'
 if any('"'in str(p) or '\n'in str(p) for p in (dev,exe,source)):raise RuntimeError('build_failed')
 command=f'"{dev}" -no_logo -arch=x64 -host_arch=x64 >nul && cl /nologo /EHsc /std:c++17 /W4 /Fe:"{exe}" /Fo:"{out / "retail_guard.obj"}" "{source}" >nul 2>&1'
 result=subprocess.run(command,shell=True,timeout=120)
 if result.returncode or not exe.is_file():raise RuntimeError('build_failed')
 return exe

def main():
 from run_prepare import authorized
 if not authorized(os.environ,sys.platform):raise SystemExit('fresh_hosted_once_required')
 r=g.blank(os.environ['GITHUB_SHA'],os.environ['GITHUB_RUN_ID']);Path('output').mkdir(exist_ok=True)
 try:
  exe=build()
  for mode in ('fixture_timeout','fixture_network','fixture_disk'):
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
