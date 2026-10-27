"""Compile production guard; run synthetic assertions and a read-only native probe.

Never sets RETAIL_PREPARE/RETAIL_SUPERVISED and never runs the guard or target.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import guard_driver
import guard_report
import counter_report

HERE=Path(__file__).resolve().parent
BRANCH='refs/heads/research/prelogin-telemetry-wow-data-provenance'


def allowed(env, platform):
    return platform=='win32' and all(env.get(k)==v for k,v in dict(
        GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',
        GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1',GITHUB_REF=BRANCH,
        COUNTER_DIAGNOSTIC='approved-counter-diagnostics-d1').items())


def build_extra(name):
    if name not in {'counter_diagnostics_test','counter_probe_win'}:raise ValueError('build_scope')
    vs=Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio/Installer/vswhere.exe'
    q=subprocess.run([str(vs),'-latest','-products','*','-requires',
        'Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],
        capture_output=True,text=True,timeout=20)
    installation=q.stdout.strip()
    if q.returncode or not installation or '\n' in installation:raise RuntimeError('build_failed')
    dev=Path(installation)/'Common7/Tools/VsDevCmd.bat'
    out=Path('output').resolve();source=HERE/(name+'.cpp');exe=out/(name+'.exe')
    log=out/(name+'.private.log');batch=out/(name+'.cmd')
    if any('"' in str(p) or '\n' in str(p) for p in (dev,source,exe,log,batch)):
        raise RuntimeError('build_failed')
    batch.write_text('@echo off\ncall "'+str(dev)+'" -no_logo -arch=x64 -host_arch=x64 >nul 2>&1\n'
        'if errorlevel 1 exit /b 90\ncl /nologo /EHsc /std:c++17 /W4 /Fe:"'+str(exe)+
        '" /Fo:"'+str(out/(name+'.obj'))+'" "'+str(source)+'" >"'+str(log)+'" 2>&1\nexit /b %errorlevel%\n')
    result=subprocess.run([os.environ.get('COMSPEC','cmd.exe'),'/d','/c',str(batch)],
                          capture_output=True,timeout=90)
    if result.returncode or not exe.is_file():raise RuntimeError('build_failed')
    return exe


def main():
    if not allowed(os.environ,sys.platform):raise SystemExit('diagnostic_environment_required')
    if any(os.environ.get(k)for k in ('RETAIL_PREPARE','RETAIL_SUPERVISED')):
        raise SystemExit('target_approval_forbidden')
    r=counter_report.blank(os.environ['GITHUB_SHA'],os.environ['GITHUB_RUN_ID'])
    counter_report.validate(r);Path('output').mkdir(exist_ok=True)
    try:
        guard_driver.build(r['guard_build'])  # compile only, never execute the guard
        test=build_extra('counter_diagnostics_test')
        p=subprocess.run([str(test)],capture_output=True,timeout=10)
        if p.returncode:raise RuntimeError('assertions_failed')
        r['portable_assertions_passed']=True
        exe=build_extra('counter_probe_win')
        p=subprocess.run([str(exe),r['source_commit'],r['run_id']],capture_output=True,timeout=20)
        r['native']=counter_report.native(guard_report.read('output/counter-native.json'))
        if p.returncode:raise RuntimeError('probe_failed')
        r['status']='observed'
    except Exception as exc:
        label=str(exc) if type(exc)is RuntimeError else 'other'
        r['status']=label if label in {'build_failed','assertions_failed','probe_failed'}else 'other'
    finally:
        counter_report.validate(r)
        Path('output/counter-diagnostic-run.json').write_text(json.dumps(r,indent=2)+'\n')
        print(json.dumps(dict(status=r['status'],target_launched=False,transfer_requested=False)))
    if r['status']!='observed':raise SystemExit(2)


if __name__=='__main__':main()
