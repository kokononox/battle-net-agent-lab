"""Fresh Windows: compile trusted fixture, execute only bounded loopback transfer."""
import os,subprocess,sys,json,re
import build_receipt
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
 text=log.read_text(errors='replace')[:65536] if log.is_file()else ''
 codes=sorted(set(re.findall(r'\b(?:C[0-9]{4}|D[0-9]{4}|LNK[0-9]{4})\b',text)))[:16] if p.returncode else []
 lines=sorted(set(int(n)for n in re.findall(re.escape(name)+r'\.cpp\(([0-9]{1,4})(?:,[0-9]+)?\).*?(?:fatal error|error) ',text)))[:16]
 destination=out/'tcp-build.json'
 record=dict(schema='bnet-tcp-build-1',source_commit=os.environ['GITHUB_SHA'],run_id=os.environ['GITHUB_RUN_ID'],units=[])
 if destination.exists():
  record=build_receipt.validate(json.loads(destination.read_text()))
  if record['source_commit']!=os.environ['GITHUB_SHA']or record['run_id']!=os.environ['GITHUB_RUN_ID']:raise RuntimeError('build_identity')
 record['units']=[u for u in record['units']if u['unit']!=name]
 record['units'].append(dict(unit=name,compiled=p.returncode==0 and exe.is_file(),exit_code=p.returncode,compiler_error_codes=codes,source_error_lines=lines))
 build_receipt.validate(record);destination.write_text(json.dumps(record,indent=2)+'\n')
 if p.returncode or not exe.is_file():raise RuntimeError('build_failed')
 return exe
def main():
 if not allowed(os.environ,sys.platform):raise SystemExit('calibration_environment_required')
 exe=compile_source('tcp_fixture');compile_source('tcp_meter');out=Path('output').resolve()
 p=subprocess.run([str(exe),os.environ['GITHUB_SHA'],os.environ['GITHUB_RUN_ID']],capture_output=True,timeout=20)
 r=receipt.read(out/'tcp-fixture.json');print({'status':r['status'],'win32_error':r['win32_error']})
 if p.returncode:raise SystemExit(2)
if __name__=='__main__':main()
