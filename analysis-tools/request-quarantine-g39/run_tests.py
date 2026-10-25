import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
p=argparse.ArgumentParser();p.add_argument('--report',type=Path);args=p.parse_args()
suite=unittest.defaultTestLoader.discover(str(ROOT),pattern='test_*.py')
r=unittest.TextTestRunner(verbosity=2).run(suite)
evidence={'schema':'request_quarantine_g39_test_evidence_v1','platform_tested':os.name,'tests_run':r.testsRun,'tests_passed':r.wasSuccessful(),'failures':len(r.failures),'errors':len(r.errors),'fixture_data_only':True,'private_capture_data_published':False,'socket_creation_guarded_in_each_test':True,'upstream_transport_implemented':False,'windows_storage_implemented':False,'windows_storage_behavior':'fail_closed','live_proxy_integrated':False,'real_installer_executed':False,'tls_decrypted':False,'windows_policy_changed':False,'new_runtime_resources_approved':0,'files_sha256':{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(ROOT.iterdir()) if f.is_file()}}
if args.report:args.report.write_text(json.dumps(evidence,indent=2)+'\n')
sys.exit(not r.wasSuccessful())
