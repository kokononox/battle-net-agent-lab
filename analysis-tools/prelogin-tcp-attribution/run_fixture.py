"""Fresh Windows: compile trusted fixture, execute only bounded loopback transfer."""
import os,subprocess,sys
from pathlib import Path
import receipt
HERE=Path(__file__).resolve().parent
BRANCH='refs/heads/research/prelogin-telemetry-wow-data-provenance'
def allowed(e,p):
 return p=='win32'and all(e.get(k)==v for k,v in dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1',GITHUB_REF=BRANCH,TCP_CALIBRATION='approved-owned-tcp-t1').items())and not any(e.get(k)for k in ('RETAIL_PREPARE','RETAIL_SUPERVISED'))
def compile_source(name):
 if name not in {'tcp_fixture','tcp_meter'}:raise ValueError('compile_scope')
 out=Path('output').resolve();out.mkdir(exist_ok=True)
 vs=Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio/Installer/vswhere.exe'
 q=subprocess.run([str(vs),'-latest','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],capture_output=True,text=True,timeout=20)
 installation=q.stdout.strip()
 if q.returncode or not installation or '\n'in installation:raise SystemExit('compiler_missing')
 dev=Path(installation)/'Common7/Tools/VsDevCmd.bat';exe=out/(name+'.exe');source=HERE/(name+'.cpp');log=out/(name+'-build.private.log');bat=out/(name+'-build.cmd')
 if any('"'in str(p)or '\n'in str(p)for p in (dev,exe,source,log,bat)):raise SystemExit('build_scope')
 bat.write_text('@echo off\ncall "'+str(dev)+'" -no_logo -arch=x64 -host_arch=x64 >nul 2>&1\nif errorlevel 1 exit /b 90\ncl /nologo /EHsc /std:c++17 /W4 /Fe:"'+str(exe)+'" /Fo:"'+str(out/(name+'.obj'))+'" "'+str(source)+'" >"'+str(log)+'" 2>&1\nexit /b %errorlevel%\n')
 p=subprocess.run([os.environ.get('COMSPEC','cmd.exe'),'/d','/c',str(bat)],capture_output=True,timeout=90)
 if p.returncode or not exe.is_file():
  import re
  codes=sorted(set(re.findall(r'\b(?:C[0-9]{4}|LNK[0-9]{4})\b',log.read_text(errors='replace')[:65536])))
  print({'build_failed':True,'compiler_codes':codes});raise SystemExit(2)
 return exe
def main():
 if not allowed(os.environ,sys.platform):raise SystemExit('calibration_environment_required')
 exe=compile_source('tcp_fixture');out=Path('output').resolve()
 p=subprocess.run([str(exe),os.environ['GITHUB_SHA'],os.environ['GITHUB_RUN_ID']],capture_output=True,timeout=20)
 r=receipt.read(out/'tcp-fixture.json');print({'status':r['status'],'win32_error':r['win32_error']})
 if p.returncode:raise SystemExit(2)
if __name__=='__main__':main()
