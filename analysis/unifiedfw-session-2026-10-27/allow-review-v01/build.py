"""Rebuild and verify standalone read-only aggregate firewall diagnostic."""
from pathlib import Path
import argparse,subprocess,json,hashlib,zipfile,tempfile
p=argparse.ArgumentParser();p.add_argument('--pwsh',required=True);a=p.parse_args()
r=Path(__file__).resolve().parent;d=r/'package/UFW-ALLOW-REVIEW-01';ev=r/'evidence';old=r.parent/'runtime-capture-v01/package/UFW-RUNTIME-CAPTURE-01'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def run(script,*args):
 v=subprocess.run([a.pwsh,'-NoLogo','-NoProfile','-File',str(script),*args],capture_output=True,text=True,timeout=120)
 return v
# Verify unchanged reference functions before relying on parity tests.
s=(old/'RuntimeCore.ps1').read_text();ref=s[s.index('function Get-UfwRuntimeEndpoint('):s.index('function Get-UfwRuntimeProposals(')]
assert (d/'EndpointReference.ps1').read_text()==ref
s=(old/'RuntimeEntry.ps1').read_text();assert (r/'GuardReference.ps1').read_text()==s[s.index('function Get-UfwRuntimeSystemHostPath'):s.index('function Get-UfwRuntimeDeviceMap')]
for name in ['EndpointReference.ps1','AllowReview.ps1','Run-Review.ps1']:(d/name).write_text((d/name).read_text(),newline='\r\n')
v=run(r/'Test-AllowReview.ps1');(ev/'model-tests.log').write_text(v.stdout+'\n'+v.stderr);assert v.returncode==0,'model tests failed'
report=json.loads((ev/'model-tests.json').read_text('utf-8-sig'));assert report['passed']
s=(d/'Run-Review.ps1').read_text();start=s.index("$hashes=ConvertFrom-Json @'\n")+len("$hashes=ConvertFrom-Json @'\n");end=s.index("\n'@",start);s=s[:start]+json.dumps({n:sha(d/n) for n in ['EndpointReference.ps1','AllowReview.ps1']},indent=2)+s[end:];(d/'Run-Review.ps1').write_text(s,newline='\r\n')
v=run(d/'Run-Review.ps1');(ev/'platform-guard.log').write_text(v.stdout+'\n'+v.stderr);assert v.returncode==1
paths=list(d.glob('UFW-ALLOW-REVIEW-01-*.json'));assert len(paths)==1
platform=json.loads(paths[0].read_text('utf-8-sig'));assert platform['code']=='ufw_allow_review_windows_required' and platform['review'] is None and not platform['audit_change_requested'];paths[0].replace(ev/'linux-platform-guard.json')
(d/'evidence').mkdir(exist_ok=True)
for name in ['model-tests.json','linux-platform-guard.json']:(d/'evidence'/name).write_bytes((ev/name).read_bytes())
(d/'PROVENANCE.json').write_text(json.dumps(dict(reference_commit='1e76e2e125069eb8117878943068179d117d681f',runtime_endpoint_function_text_unchanged=True,guard_reference_test_only_not_shipped=True,model_assertions=report['assertions'],Windows_native_executed=False,firewall_audit_mutation=False,installer_execution=False),indent=2)+'\n')
manifest={p.relative_to(d).as_posix():sha(p) for p in sorted(d.rglob('*')) if p.is_file() and p.name not in ['Run-Review.cmd','PAYLOAD-SHA256.json']};(d/'PAYLOAD-SHA256.json').write_text(json.dumps(manifest,indent=2)+'\n');pin=sha(d/'PAYLOAD-SHA256.json')
cmd=(old/'Run-Runtime.cmd').read_text().replace('UFW_RUNTIME_ROOT','UFW_ALLOW_REVIEW_ROOT').replace(sha(old/'PAYLOAD-SHA256.json'),pin).replace('Run-Runtime.ps1','Run-Review.ps1')
start=cmd.index("foreach($n in @(");end=cmd.index(')){Unblock-File',start)
cmd=cmd[:start]+"foreach($n in @('EndpointReference.ps1','AllowReview.ps1','Run-Review.ps1'"+cmd[end:]
cmd=cmd.replace('Nine package scripts/modules unblocked.','Three package scripts unblocked.').replace('Runtime Capture 0.1 - audit consent required; NOT an isolation guarantee.','Allow Review 0.1 - READ ONLY firewall inspection. No installer launch.').replace('Runtime capture not confirmed. Do not launch the installer without READY.','Read-only review incomplete. Do not launch the installer.').replace('no review completed.','no review completed.')
assert pin in cmd and 'Unblock-File' in cmd and 'RuntimeEntry' not in cmd and 'Bypass' not in cmd
(d/'Run-Review.cmd').write_text(cmd,newline='\r\n')
v=run(r/'Check-Package.ps1');(ev/'package-check.log').write_text(v.stdout+'\n'+v.stderr);assert v.returncode==0,'package checks failed';(ev/'package-check.json').write_text(json.dumps(json.loads(v.stdout),indent=2)+'\n')
z=r/'UFW-ALLOW-REVIEW-01.zip'
with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as out:
 for p in sorted(d.rglob('*')):
  if p.is_file():
   info=zipfile.ZipInfo(p.relative_to(d.parent).as_posix(),date_time=(2026,10,27,9,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16;out.writestr(info,p.read_bytes())
with tempfile.TemporaryDirectory() as td:
 with zipfile.ZipFile(z) as out:
  assert out.testzip() is None;out.extractall(td)
 extracted=Path(td)/d.name
 for p in d.rglob('*'):
  if p.is_file():assert p.read_bytes()==(extracted/p.relative_to(d)).read_bytes()
 v=run(r/'Check-Package.ps1','-Root',str(extracted));assert v.returncode==0,'fresh extraction check failed'
(ev/'fresh-extraction-check.json').write_text(json.dumps(dict(passed=True,all_bytes_identical=True,package_verifier_passed=True,Windows_native_executed=False),indent=2)+'\n')
summary=dict(filename=z.name,sha256=sha(z),bytes=z.stat().st_size,model_assertions=report['assertions'],predicate_parity_cases=512,endpoint_parity_cases=18,aggregate_cases=7,package_PS_files_parsed=3,manifest_and_fresh_ZIP_verified=True,Windows_native_executed=False,firewall_audit_mutation=False,target_execution=False,raw_rule_identity_exported=False,runtime_execution_authorized=False,ready_for_apply=False)
(r/'PACKAGE-SUMMARY.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
