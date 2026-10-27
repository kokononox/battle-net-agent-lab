"""Rebuild portable runtime recorder after offline QA. No selected target execution."""
from pathlib import Path
import argparse,subprocess,json,hashlib,zipfile
p=argparse.ArgumentParser();p.add_argument('--pwsh',required=True);a=p.parse_args()
r=Path(__file__).resolve().parent;d=r/'package/UFW-RUNTIME-CAPTURE-01';old=r.parent/'program-observer-v01/package/UFW-PROGRAM-OBSERVER-01';ev=r/'evidence'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
unchanged=['Ufw.ProfileReader.psm1','Ufw.InstallerCore.psm1','Ufw.SessionJournal.psm1','ProgramReader.cs','ProgramReview.ps1','CandidateEntry.ps1','ObserverEntry.ps1']
for n in unchanged:assert (d/n).read_bytes()==(old/n).read_bytes(),n
reports={}
for n,count in [('model-tests',718),('observer-regression',645),('candidate-regression',236),('picker-regression',260),('journal-regression',73)]:
 reports[n]=json.loads((ev/(n+'.json')).read_text('utf-8-sig'));assert reports[n]['passed'] and reports[n]['assertions']==count
# Preserve CRLF for Windows launchers/new entrypoints; historic dependencies remain byte-identical.
for n in ['RuntimeCore.ps1','RuntimeEntry.ps1','Run-Runtime.ps1']:(d/n).write_text((d/n).read_text(),newline='\r\n')
deps=unchanged+['RuntimeNative.cs','RuntimeCore.ps1','RuntimeEntry.ps1'];s=(d/'Run-Runtime.ps1').read_text();start=s.index("$hashes=ConvertFrom-Json @'\n")+len("$hashes=ConvertFrom-Json @'\n");end=s.index("\n'@",start)
s=s[:start]+json.dumps({n:sha(d/n) for n in deps},indent=2)+s[end:];(d/'Run-Runtime.ps1').write_text(s,newline='\r\n')
v=subprocess.run([a.pwsh,'-NoLogo','-NoProfile','-File',str(d/'Run-Runtime.ps1')],capture_output=True,text=True,timeout=30)
(ev/'platform-guard.log').write_text(v.stdout+'\n'+v.stderr);assert v.returncode==1
paths=list(d.glob('UFW-RUNTIME-CAPTURE-01-*.json'));assert len(paths)==1
report=json.loads(paths[0].read_text('utf-8-sig'));assert report['code']=='ufw_runtime_windows_required' and report['runtime'] is None and not report['payload_verified'];paths[0].replace(ev/'linux-platform-guard.json')
(d/'evidence').mkdir(exist_ok=True)
for n in reports:(d/'evidence'/(n+'.json')).write_text(json.dumps(reports[n],indent=2)+'\n')
(d/'evidence/linux-platform-guard.json').write_bytes((ev/'linux-platform-guard.json').read_bytes())
(d/'PROVENANCE.json').write_text(json.dumps(dict(base_commit='2d0a2584399c532bf7a34af99efc7606fc37c2c0',byte_unchanged_dependencies={n:sha(d/n) for n in unchanged},new_assertions=718,regression_assertions=1214,Windows_native_executed=False,ready_for_apply=False),indent=2)+'\n')
manifest={p.relative_to(d).as_posix():sha(p) for p in sorted(d.rglob('*')) if p.is_file() and p.name not in ['PAYLOAD-SHA256.json','Run-Runtime.cmd']}
(d/'PAYLOAD-SHA256.json').write_text(json.dumps(manifest,indent=2)+'\n');pin=sha(d/'PAYLOAD-SHA256.json')
cmd=(old/'Run-Observer.cmd').read_text().replace('UFW_OBSERVER_ROOT','UFW_RUNTIME_ROOT').replace(sha(old/'PAYLOAD-SHA256.json'),pin).replace('Run-Observer.ps1','Run-Runtime.ps1')
cmd=cmd.replace("'ObserverEntry.ps1','Run-Runtime.ps1'","'ObserverEntry.ps1','RuntimeCore.ps1','RuntimeEntry.ps1','Run-Runtime.ps1'").replace('Seven package scripts/modules unblocked.','Nine package scripts/modules unblocked.').replace('Passive observation not confirmed.','Runtime capture not confirmed. Do not launch the installer without READY.').replace('Passive Program Observer 0.1 - READ existing candidate; no target execution/firewall change.','Runtime Capture 0.1 - audit consent required; NOT an isolation guarantee.')
assert 'RuntimeEntry.ps1' in cmd and 'Run-Observer.ps1' not in cmd and pin in cmd
(d/'Run-Runtime.cmd').write_text(cmd,newline='\r\n')
v=subprocess.run([a.pwsh,'-NoLogo','-NoProfile','-File',str(r/'Check-Package.ps1')],capture_output=True,text=True,timeout=60)
(ev/'package-check.log').write_text(v.stdout+'\n'+v.stderr)
if v.returncode:raise RuntimeError('package verification failed; inspect evidence/package-check.log')
check=json.loads(v.stdout);assert check['passed'];(ev/'package-check.json').write_text(json.dumps(check,indent=2)+'\n')
z=r/'UFW-RUNTIME-CAPTURE-01.zip'
with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as out:
 for p in sorted(d.rglob('*')):
  if p.is_file():
   info=zipfile.ZipInfo(p.relative_to(d.parent).as_posix(),date_time=(2026,10,27,8,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16;out.writestr(info,p.read_bytes())
with zipfile.ZipFile(z) as out:
 assert out.testzip() is None
 for n,h in manifest.items():assert hashlib.sha256(out.read(d.name+'/'+n)).hexdigest()==h
summary=dict(filename=z.name,sha256=sha(z),bytes=z.stat().st_size,manifest_sha256=pin,new_assertions=718,regression_assertions=1214,package_PS_files_parsed=9,bootstrap_and_ZIP_verified=True,Windows_native_executed=False,administrator_required=True,read_only_candidate=True,maximum_capture_seconds=90,temporary_system_audit_with_explicit_consent=True,native_denied_probe_required_before_READY=True,automatic_target_execution=False,automatic_destination_approval=False,ready_for_apply=False)
(r/'PACKAGE-SUMMARY.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
