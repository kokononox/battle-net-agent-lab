from pathlib import Path
import json,sys,unittest
root=Path(__file__).resolve().parents[1]
suite=unittest.defaultTestLoader.discover(str(root/'tests'),pattern='test_*.py')
r=unittest.TextTestRunner(verbosity=1).run(suite)
summary=dict(suite='unified-policy-and-state',test_methods=r.testsRun,failures=len(r.failures),errors=len(r.errors),skipped=len(r.skipped),passed=r.wasSuccessful(),runtime=sys.version.split()[0],platform=sys.platform,windows_firewall_tested=False,windows_gui_tested=False)
(root/'evidence/python-tests.json').write_text(json.dumps(summary,indent=2))
print(json.dumps(summary));raise SystemExit(not r.wasSuccessful())
