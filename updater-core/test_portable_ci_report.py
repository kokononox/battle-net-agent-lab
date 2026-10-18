import copy,json,unittest
from publish_portable_ci import validate
from run_portable_ci import MODULES
class Tests(unittest.TestCase):
 def fixture(self):return {'format':'updater-portable-offline-ci-1','source_commit':'a'*40,'platform':'Windows','python_version':'3.13.1','tests_run':73,'failures':0,'errors':0,'skipped':0,'passed':True,'test_modules':MODULES,'scope':'synthetic_stream_parser_and_selection_only','game_access':False,'network_in_test_suite':False,'native_windows_staging_backend_qualified':False,'windows_installer_qualified':False,'installation_ready':False,'apply_authorized':False}
 def verify(self,r):return validate(json.dumps(r).encode(),'a'*40)
 def bad(self,key,value):
  r=self.fixture();r[key]=value
  with self.assertRaises(AssertionError):self.verify(r)
 def test_valid_minimal(self):self.assertTrue(self.verify(self.fixture())['passed'])
 def test_linux_not_windows_proof(self):self.bad('platform','Linux')
 def test_wrong_source_commit(self):self.bad('source_commit','b'*40)
 def test_skipped_not_qualified(self):self.bad('skipped',1)
 def test_smaller_suite_not_qualified(self):self.bad('tests_run',1)
 def test_extra_private_field_refused(self):self.bad('private','not allowed')
 def test_installation_claim_refused(self):self.bad('installation_ready',True)
 def test_native_staging_claim_refused(self):self.bad('native_windows_staging_backend_qualified',True)
 def test_boolean_test_count_refused(self):self.bad('tests_run',True)
 def test_duplicate_field_refused(self):
  raw=json.dumps(self.fixture()).encode();raw=raw[:-1]+b',"platform":"Windows"}'
  with self.assertRaises(AssertionError):validate(raw,'a'*40)
if __name__=='__main__':unittest.main()
