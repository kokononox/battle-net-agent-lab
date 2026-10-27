"""Build experimental private inventory reader. No Windows mutation or network calls."""
from pathlib import Path
import argparse, subprocess, json, hashlib, tempfile, zipfile
p=argparse.ArgumentParser();p.add_argument('--pwsh',required=True);a=p.parse_args();r=Path(__file__).resolve().parent;ev=r/'evidence';d=r/'package/UFW-PRIVATE-INVENTORY-01';old=r.parent/'allow-review-v01/package/UFW-ALLOW-REVIEW-01';storage=r.parent/'runtime-capture-v01/package/UFW-RUNTIME-CAPTURE-01'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def run(path,*args):return subprocess.run([a.pwsh,'-NoLogo','-NoProfile','-File',str(path),*args],capture_output=True,text=True,timeout=180)
unchanged=['Ufw.ProfileReader.psm1','Ufw.InstallerCore.psm1','Ufw.SessionJournal.psm1']
for n in unchanged:assert (d/n).read_bytes()==(storage/n).read_bytes(),n
for n in ['InventoryCore.ps1','InventoryEntry.ps1','Run-Inventory.ps1']:(d/n).write_text((d/n).read_text(),newline='\r\n')
v=run(r/'Test-Inventory.ps1');(ev/'model-tests.log').write_text(v.stdout+'\n'+v.stderr);assert v.returncode==0,'inventory tests failed'
model=json.loads((ev/'model-tests.json').read_text('utf-8-sig'));assert model['passed']
# Re-run the previous read-only classifier without modifying its shipped package.
v=run(r.parent/'allow-review-v01/Test-AllowReview.ps1');(ev/'allow-regression.log').write_text(v.stdout+'\n'+v.stderr);assert v.returncode==0,'allow regression failed'
reg=json.loads((r.parent/'allow-review-v01/evidence/model-tests.json').read_text('utf-8-sig'));assert reg['passed'] and reg['assertions']==1617
(ev/'allow-regression.json').write_text(json.dumps(reg,indent=2)+'\n')
s=(d/'Run-Inventory.ps1').read_text();start=s.index("$hashes=ConvertFrom-Json @'\n")+len("$hashes=ConvertFrom-Json @'\n");end=s.index("\n'@",start);s=s[:start]+json.dumps({n:sha(d/n) for n in unchanged+['InventoryCore.ps1','InventoryEntry.ps1']},indent=2)+s[end:];(d/'Run-Inventory.ps1').write_text(s,newline='\r\n')
v=run(d/'Run-Inventory.ps1');(ev/'platform-guard.log').write_text(v.stdout+'\n'+v.stderr);assert v.returncode==1
paths=list(d.glob('UFW-PRIVATE-INVENTORY-01-*.json'));assert len(paths)==1
platform=json.loads(paths[0].read_text('utf-8-sig'));assert platform['code']=='ufw_inventory_windows_required' and platform['inventory'] is None;paths[0].replace(ev/'linux-platform-guard.json')
(d/'evidence').mkdir(exist_ok=True)
for n in ['model-tests.json','allow-regression.json','linux-platform-guard.json']:(d/'evidence'/n).write_bytes((ev/n).read_bytes())
(d/'PROVENANCE.json').write_text(json.dumps(dict(base_commit='3985b9282feee50fe15d53744ce75ce2cdcbad2b',unchanged_dependency_sha256={n:sha(d/n) for n in unchanged},model_assertions=model['assertions'],regression_assertions=1617,Windows_native_executed=False,storage_consent_only=True,native_restore_qualified=False,ready_for_apply=False),indent=2)+'\n')
manifest={p.relative_to(d).as_posix():sha(p) for p in sorted(d.rglob('*')) if p.is_file() and p.name not in ['PAYLOAD-SHA256.json','Run-Inventory.cmd']};(d/'PAYLOAD-SHA256.json').write_text(json.dumps(manifest,indent=2)+'\n');pin=sha(d/'PAYLOAD-SHA256.json')
cmd=(old/'Run-Review.cmd').read_text().replace('UFW_ALLOW_REVIEW_ROOT','UFW_PRIVATE_INVENTORY_ROOT').replace(sha(old/'PAYLOAD-SHA256.json'),pin).replace('Run-Review.ps1','Run-Inventory.ps1')
start=cmd.index('foreach($n in @(');end=cmd.index(')){Unblock-File',start)
cmd=cmd[:start]+"foreach($n in @('Ufw.ProfileReader.psm1','Ufw.InstallerCore.psm1','Ufw.SessionJournal.psm1','InventoryCore.ps1','InventoryEntry.ps1','Run-Inventory.ps1'"+cmd[end:]
cmd=cmd.replace('Three package scripts unblocked.','Six package scripts/modules unblocked.').replace('Allow Review 0.1 - READ ONLY firewall inspection. No installer launch.','Private Inventory 0.1 - READ ONLY policy; storage consent required. No installer launch.').replace('Read-only review incomplete. Do not launch the installer.','Private inventory incomplete. Do not launch the installer or change policy.')
assert pin in cmd and 'Bypass' not in cmd and 'EndpointReference' not in cmd
(d/'Run-Inventory.cmd').write_text(cmd,newline='\r\n')
v=run(r/'Check-Package.ps1');(ev/'package-check.log').write_text(v.stdout+'\n'+v.stderr);assert v.returncode==0,'package verifier failed';(ev/'package-check.json').write_text(json.dumps(json.loads(v.stdout),indent=2)+'\n')
z=r/'UFW-PRIVATE-INVENTORY-01.zip'
with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as out:
 for p in sorted(d.rglob('*')):
  if p.is_file():
   info=zipfile.ZipInfo(p.relative_to(d.parent).as_posix(),date_time=(2026,10,27,10,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16;out.writestr(info,p.read_bytes())
with tempfile.TemporaryDirectory() as td:
 with zipfile.ZipFile(z) as out:assert out.testzip() is None;out.extractall(td)
 extracted=Path(td)/d.name
 for p in d.rglob('*'):
  if p.is_file():assert p.read_bytes()==(extracted/p.relative_to(d)).read_bytes()
 v=run(r/'Check-Package.ps1','-Root',str(extracted));assert v.returncode==0,'fresh extracted package verification failed'
(ev/'fresh-extraction-check.json').write_text(json.dumps(dict(passed=True,all_bytes_identical=True,package_verifier_passed=True,Windows_native_executed=False),indent=2)+'\n')
summary=dict(filename=z.name,sha256=sha(z),bytes=z.stat().st_size,model_assertions=model['assertions'],callback_cases=model['callback_cases'],regression_assertions=1617,package_PS_files_parsed=6,manifest_and_fresh_ZIP_verified=True,Windows_native_executed=False,explicit_storage_consent=True,firewall_audit_mutation=False,legacy_journal_access=False,target_execution=False,private_store_root='CommonApplicationData/UnifiedFW-PrivateInventory-01',raw_diagnostic_identity_exported=False,native_restore_qualified=False,ready_for_apply=False)
(r/'PACKAGE-SUMMARY.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
