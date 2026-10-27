import unittest,sys,pathlib,json,platform
r=pathlib.Path('/data/ufd-normal-exit-hf124');c=r/'candidate'
suite=unittest.defaultTestLoader.discover(str(c/'tests'),pattern='test_*.py')
with (r/'python-tests.log').open('w') as stream:result=unittest.TextTestRunner(stream=stream,verbosity=1).run(suite)
d=dict(suite='offline-HF124-normal-exit-python-regression',test_methods=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),skipped_tests=[dict(test=str(t),reason=s) for t,s in result.skipped],passed=result.wasSuccessful(),runtime=platform.python_version(),platform=sys.platform,windows_firewall_tested=False,windows_gui_tested=False)
(r/'python-tests.json').write_text(json.dumps(d,indent=2));print(json.dumps(d,indent=2))
sys.exit(0 if result.wasSuccessful() else 1)
