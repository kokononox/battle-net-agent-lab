"""Offline development tests only; test evidence IO, never Windows changes."""
from pathlib import Path
import argparse, subprocess, tempfile, json, sys
p=argparse.ArgumentParser();p.add_argument('--pwsh',required=True);a=p.parse_args();r=Path(__file__).resolve().parent;ev=r/'evidence';base=r.parent
v=subprocess.run([sys.executable,'-m','unittest','discover','-s',str(r/'tests'),'-v'],capture_output=True,text=True)
(ev/'model-tests.log').write_text(v.stdout+'\n'+v.stderr);assert v.returncode==0, 'model suite failed'
assert 'Ran 11 tests' in v.stderr
with tempfile.TemporaryDirectory(prefix='ufw-offline-') as td:
 temp=Path(td)
 old=base/'exact-transport-plan-v01'
 for n in ['Test-TransportPlan.ps1','Sstp.TransportPlan.ps1']:(temp/n).write_bytes((old/n).read_bytes())
 v=subprocess.run([a.pwsh,'-NoLogo','-NoProfile','-File',str(temp/'Test-TransportPlan.ps1')],capture_output=True,text=True)
 (ev/'transport-regression.log').write_text(v.stdout+'\n'+v.stderr);assert v.returncode==0,'transport regression failed'
 transport=json.loads((temp/'MODEL-RESULTS.json').read_text('utf-8-sig'));assert transport['passed'] and transport['assertions']==86
 (ev/'transport-regression.json').write_text(json.dumps(transport,indent=2)+'\n')
 old=base/'app-profile-plan-v01'
 source=(old/'tests/test_app_profile_plan.py').read_text().replace("Path('/data/ufw-app-profile-plan-v01')",'Path('+repr(str(old))+')')
 source=source.replace("(ROOT/'evidence/model-tests.json')", 'Path('+repr(str(temp/'profile-regression.json'))+')')
 script=temp/'test_profiles.py';script.write_text(source)
 v=subprocess.run([sys.executable,str(script),'-v'],capture_output=True,text=True)
 (ev/'profile-regression.log').write_text(v.stdout+'\n'+v.stderr);assert v.returncode==0,'profile regression failed'
 assert 'Ran 25 tests' in v.stderr
 profile=json.loads((temp/'profile-regression.json').read_text());assert profile['passed']
 (ev/'profile-regression.json').write_text(json.dumps(profile,indent=2)+'\n')
report=dict(schema='ufw-isolation-transaction-model-qa-01',passed=True,model_test_methods=11,
 forward_write_ambiguity_cases=60,recovery_crash_resume_steps=10,
 synthetic_allow_toggle_fixture_count=106,actual_user_rule_inventory_imported=False,
 prior_transport_regression_assertions=86,prior_profile_regression_methods=25,
 native_Windows_executed=False,firewall_mutation=False,native_executor_implemented=False,
 private_baseline_written=False,plan_executable=False,ready_for_apply=False,no_leak_certified=False)
(ev/'model-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
