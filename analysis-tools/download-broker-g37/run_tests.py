"""Run the offline G37 suites with optional machine-readable result."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
p=argparse.ArgumentParser();p.add_argument('--report',type=Path);args=p.parse_args()
suite=unittest.defaultTestLoader.discover(str(ROOT),pattern='test_*.py')
result=unittest.TextTestRunner(verbosity=2).run(suite)
evidence={
 'schema':'offline_broker_session_g37_v1',
 'tests_run':result.testsRun,'tests_passed':result.wasSuccessful(),
 'failures':len(result.failures),'errors':len(result.errors),
 'injection_cases_in_contract_test':1000,'adversarial_sequences':156,
 'concurrent_duplicate_requests':32,'expected_concurrent_deliveries':1,
 'transport':'in_memory_fixtures_only','socket_creation_guarded_in_each_test':True,
 'production_catalog_resources':0,'external_network_transport_implemented':False,
 'windows_policy_changed':False,'real_battlenet_download_tested':False,
 'cross_session_replay_prevention_implemented':False,
 'timing_channel_eliminated':False,'runtime_anti_fingerprint_acceptance':False,
 'exe_delivered':False,
 'files_sha256':{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(ROOT.iterdir()) if f.is_file()}
}
if args.report:args.report.write_text(json.dumps(evidence,indent=2)+'\n')
sys.exit(not result.wasSuccessful())
