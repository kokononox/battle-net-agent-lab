"""One internal integration harness; no user-side test bundle or native policy writes."""
from pathlib import Path
import argparse,subprocess,tempfile,json
p=argparse.ArgumentParser();p.add_argument('--pwsh',required=True);a=p.parse_args();r=Path(__file__).resolve().parent;runtime=r.parent/'runtime-capture-v01';ev=r/'evidence'
s=(runtime/'Test-Runtime.ps1').read_text();s=s[:s.index('\ntry{\n $modes=')]
bridge=str(r/'source/RuntimeBridge.ps1').replace("'","''")
s=s.replace('  Invoke-UfwRuntimeCallbacks $ops', "  . '"+bridge+"'\n  Invoke-UfwUnifiedRuntimeBridge $ops ('a'*64) {param($binding)return $script:S.policyRestricted}")
with tempfile.TemporaryDirectory(prefix='ufw-integrated-') as td:
 script=Path(td)/'RuntimeFixture.ps1';script.write_text(s)
 v=subprocess.run([a.pwsh,'-NoLogo','-NoProfile','-File',str(r/'tests/Test-Unified.ps1'),'-RuntimeHarness',str(script),'-RuntimeRoot',str(runtime/'package/UFW-RUNTIME-CAPTURE-01'),'-SourceRoot',str(r/'source')],capture_output=True,text=True,timeout=240)
 (ev/'integration-tests.log').write_text(v.stdout+'\n'+v.stderr)
 if v.returncode:raise RuntimeError('integration failed; inspect evidence/integration-tests.log')
report=json.loads((ev/'integration-tests.json').read_text('utf-8-sig'));assert report['passed'];print(json.dumps(report))

v=subprocess.run([a.pwsh,'-NoLogo','-NoProfile','-File',str(r/'tests/Test-LocalPolicyBackend.ps1'),'-SourceRoot',str(r/'source'),'-JournalModule',str(runtime/'package/UFW-RUNTIME-CAPTURE-01/Ufw.SessionJournal.psm1'),'-InventoryCore',str(r.parent/'private-inventory-v01/package/UFW-PRIVATE-INVENTORY-01/InventoryCore.ps1')],capture_output=True,text=True,timeout=240)
(ev/'local-policy-backend-tests.log').write_text(v.stdout+'\n'+v.stderr)
if v.returncode:raise RuntimeError('local backend failed; inspect evidence/local-policy-backend-tests.log')
backend=json.loads((ev/'local-policy-backend-tests.json').read_text('utf-8-sig'));assert backend['passed'] and not backend['native_Windows_cmdlets_executed']

local_source=(r/'tests/Test-LocalPolicyBackend.ps1').read_text()
local_source=local_source.split(' $report=& $m {\n',1)[1].split('  # Entire unchanged session coordinator',1)[0]
with tempfile.TemporaryDirectory(prefix='ufw-mixed-') as td:
 local_fixture=Path(td)/'LocalFixture.ps1';local_fixture.write_text(local_source)
 runtime_fixture=Path(td)/'RuntimeFixture.ps1';runtime_fixture.write_text(s)
 v=subprocess.run([a.pwsh,'-NoLogo','-NoProfile','-File',str(r/'tests/Test-MixedPolicyBackend.ps1'),'-SourceRoot',str(r/'source'),'-InventoryCore',str(r.parent/'private-inventory-v01/package/UFW-PRIVATE-INVENTORY-01/InventoryCore.ps1'),'-TransportPlan',str(r.parent/'exact-transport-plan-v01/Sstp.TransportPlan.ps1'),'-LocalFixture',str(local_fixture),'-RuntimeHarness',str(runtime_fixture),'-RuntimeRoot',str(runtime/'package/UFW-RUNTIME-CAPTURE-01')],capture_output=True,text=True,timeout=300)
 (ev/'mixed-policy-backend-tests.log').write_text(v.stdout+'\n'+v.stderr)
 if v.returncode:raise RuntimeError('mixed backend failed; inspect evidence/mixed-policy-backend-tests.log')
mixed=json.loads((ev/'mixed-policy-backend-tests.json').read_text('utf-8-sig'));assert mixed['passed'] and not mixed['native_Windows_effects_executed']


# Live review/global registry adapters: same backend/coordinator, no Windows effects.
mixed_source=(r/'tests/Test-MixedPolicyBackend.ps1').read_text().split(' $report=& $m {\n',1)[1].split("  $modes=@('normal'",1)[0]
with tempfile.TemporaryDirectory(prefix='ufw-live-') as td:
 local_fixture=Path(td)/'LocalFixture.ps1';local_fixture.write_text(local_source)
 mixed_fixture=Path(td)/'MixedFixture.ps1';mixed_fixture.write_text(mixed_source)
 v=subprocess.run([a.pwsh,'-NoLogo','-NoProfile','-File',str(r/'tests/Test-LiveSessionAdapters.ps1'),'-SourceRoot',str(r/'source'),'-JournalModule',str(runtime/'package/UFW-RUNTIME-CAPTURE-01/Ufw.SessionJournal.psm1'),'-InventoryCore',str(r.parent/'private-inventory-v01/package/UFW-PRIVATE-INVENTORY-01/InventoryCore.ps1'),'-LocalFixture',str(local_fixture),'-TransportPlan',str(r.parent/'exact-transport-plan-v01/Sstp.TransportPlan.ps1'),'-RuntimeRoot',str(runtime/'package/UFW-RUNTIME-CAPTURE-01'),'-MixedFixture',str(mixed_fixture)],capture_output=True,text=True,timeout=300)
 (ev/'live-session-adapter-tests.log').write_text(v.stdout+'\n'+v.stderr)
 if v.returncode:raise RuntimeError('live adapters failed; inspect evidence/live-session-adapter-tests.log')
live=json.loads((ev/'live-session-adapter-tests.json').read_text('utf-8-sig'));assert live['passed'] and not live['native_Windows_effects_executed']

regressions=[]
for name,folder,test,count in [('runtime','runtime-capture-v01','Test-Runtime.ps1',718),('private-inventory','private-inventory-v01','Test-Inventory.ps1',172)]:
 v=subprocess.run([a.pwsh,'-NoLogo','-NoProfile','-File',str(r.parent/folder/test)],capture_output=True,text=True,timeout=240)
 (ev/(name+'-regression.log')).write_text(v.stdout+'\n'+v.stderr)
 assert v.returncode==0,name+' regression failed'
 data=json.loads((r.parent/folder/'evidence/model-tests.json').read_text('utf-8-sig'));assert data['passed'] and data['assertions']==count
 (ev/(name+'-regression.json')).write_text(json.dumps(data,indent=2)+'\n');regressions.append(dict(suite=name,assertions=count))
summary=dict(passed=True,integration=report,local_policy_backend=backend,mixed_policy_backend=mixed,live_session_adapters=live,regressions=regressions,private_native_local_setter_implemented=True,private_owned_transport_writer_implemented=True,native_firewall_setter_bound=False,Windows_user_test_requested=False)
(ev/'QA-SUMMARY.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
