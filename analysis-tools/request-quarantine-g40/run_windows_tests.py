import argparse,base64,hashlib,io,json,os,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
p=argparse.ArgumentParser();p.add_argument('--report',type=Path,required=True);args=p.parse_args()
if os.name!='nt':raise SystemExit('windows_required')
import test_windows
stream=io.StringIO();suite=unittest.defaultTestLoader.loadTestsFromModule(test_windows)
r=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
# Tests use synthetic data only. Publish result ids, not arbitrary private records.
failed=[test.id().split('.')[-1] for test,detail in r.failures+r.errors]
e={'schema':'windows_quarantine_g40_v1','run_id':os.environ.get('GITHUB_RUN_ID'),'source_commit':os.environ.get('GITHUB_SHA'),'platform':os.name,'tests_run':r.testsRun,'passed':r.wasSuccessful(),'failure_count':len(r.failures),'error_count':len(r.errors),'failed_test_ids':failed,'private_records_published':False,'fixtures_only':True,'loopback_only_application_connections':True,'firewall_changed':False,'windows_tasks_changed':False,'installer_executed':False,'new_network_destinations_authorized':False,'live_original_proxy_replaced':False,'source_sha256':{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(ROOT.iterdir()) if f.is_file()}}
args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(e,indent=2)+'\n')
print('G40_EVIDENCE_B64='+base64.b64encode(json.dumps(e,separators=(',',':')).encode()).decode())
if not r.wasSuccessful():
 # Synthetic fixture debugging, never real client capture data.
 print(stream.getvalue())
sys.exit(not r.wasSuccessful())
