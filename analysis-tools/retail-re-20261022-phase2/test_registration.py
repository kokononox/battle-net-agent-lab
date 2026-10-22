"""Offline report-integrity checks. Never executes the input PE."""
import unittest,json,os,tempfile
from pathlib import Path
from verify_registration import verify
ROOT=Path(os.environ.get('RE_OUTPUT_DIR','/data/analysis/wow-retail-20261022-phase2'))
BINARY=Path(os.environ.get('RE_INPUT_DIR','/data/raw/wow-retail-20261022'))/'Wow.exe'
PRIOR=Path(os.environ.get('RE_PRIOR_DIR','/data/analysis/wow-retail-20261022'))/'descriptor-trace.json'
class ReportChecks(unittest.TestCase):
 def check_mutation_rejected(self,change):
  report=json.loads((ROOT/'registration-path.json').read_text());change(report)
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'modified-report.json';p.write_text(json.dumps(report))
   with self.assertRaises(AssertionError):verify(BINARY,p,PRIOR)
 def test_positive_report(self):self.assertEqual(verify(BINARY,ROOT/'registration-path.json',PRIOR)['status'],'pass')
 def test_wrong_registration_table_rejected(self):
  self.check_mutation_rejected(lambda x:x['messages'][0]['registration_table_candidate'].update(rva='0x47c7dc8'))
 def test_changed_literal_location_rejected(self):
  self.check_mutation_rejected(lambda x:x['transport_literal_evidence'][0]['occurrences'][0].update(file_offset='0x42a3179'))
 def test_unsupported_runtime_claim_rejected(self):
  self.check_mutation_rejected(lambda x:x.update(selected_message_to_realm_3724_proven=True))
if __name__=='__main__':unittest.main(verbosity=2)
