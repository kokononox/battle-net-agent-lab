"""Offline synthetic parser/selection CI. No staging backend/installer claims."""
import argparse,json,os,platform,re,sys,unittest
from pathlib import Path
MODULES=['test_stream_blte','test_required_set','test_selection_policy.Pure','windows_stage_cases','windows_admission_cases','test_transfer_controller','test_transfer_reconcile','test_transfer_scope','test_policy_ambiguity']
EXPECTED_TESTS=260
def run(output):
 commit=os.environ.get('UPDATER_SOURCE_COMMIT','local-uncommitted');assert commit=='local-uncommitted'or re.fullmatch('[0-9a-f]{40}',commit)
 suite=unittest.defaultTestLoader.loadTestsFromNames(MODULES);result=unittest.TextTestRunner(verbosity=1).run(suite)
 diagnostics=[]
 for test,tb in (result.failures+result.errors)[:16]:
  name=tb.strip().splitlines()[-1].split(':',1)[0].split('.')[-1];name=name if name in('AssertionError','OSError','PermissionError','FileNotFoundError','FileExistsError','InvalidRelease','ValueError','RuntimeError','CalledProcessError','TimeoutExpired','AttributeError','TypeError')else'unclassified';codes=re.findall(r'WinError ([0-9]{1,6})',tb);diagnostics.append({'test_id':str(test),'error_class':name,'winerror_codes':sorted(set(map(int,codes)))})
 passed=result.wasSuccessful()and not result.skipped and result.testsRun==EXPECTED_TESTS
 report={'format':'updater-windows-transfer-ci-3','source_commit':commit,'platform':platform.system(),'python_version':platform.python_version(),'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),'passed':passed,'expected_tests':EXPECTED_TESTS,'failed_cases':diagnostics,'native_windows_stage_synthetic_tests_passed':passed,'bounded_transfer_synthetic_tests_passed':passed,'test_modules':MODULES,'scope':'synthetic_windows_transfer_staging_and_portable_parser','game_access':False,'network_in_test_suite':False,'native_windows_staging_backend_qualified':False,'windows_installer_qualified':False,'installation_ready':False,'apply_authorized':False}
 output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
 with output.open('x')as f:json.dump(report,f,indent=2);f.write('\n')
 return report
if __name__=='__main__':
 a=argparse.ArgumentParser(description=__doc__);a.add_argument('--output',required=True);x=a.parse_args();sys.exit(0 if run(x.output)['passed']else 1)
