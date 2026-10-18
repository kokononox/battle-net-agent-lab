"""Offline synthetic parser/selection CI. No staging backend/installer claims."""
import argparse,json,os,platform,re,sys,unittest
from pathlib import Path
MODULES=['test_stream_blte','test_required_set','test_selection_policy.Pure']
def run(output):
 commit=os.environ.get('UPDATER_SOURCE_COMMIT','local-uncommitted');assert commit=='local-uncommitted'or re.fullmatch('[0-9a-f]{40}',commit)
 suite=unittest.defaultTestLoader.loadTestsFromNames(MODULES);result=unittest.TextTestRunner(verbosity=1).run(suite)
 report={'format':'updater-portable-offline-ci-1','source_commit':commit,'platform':platform.system(),'python_version':platform.python_version(),'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),'passed':result.wasSuccessful()and not result.skipped,'test_modules':MODULES,'scope':'synthetic_stream_parser_and_selection_only','game_access':False,'network_in_test_suite':False,'native_windows_staging_backend_qualified':False,'windows_installer_qualified':False,'installation_ready':False,'apply_authorized':False}
 output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
 with output.open('x')as f:json.dump(report,f,indent=2);f.write('\n')
 return report
if __name__=='__main__':
 a=argparse.ArgumentParser(description=__doc__);a.add_argument('--output',required=True);x=a.parse_args();sys.exit(0 if run(x.output)['passed']else 1)
