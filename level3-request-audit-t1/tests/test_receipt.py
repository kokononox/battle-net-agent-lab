import copy,json
from pathlib import Path
import sys,tempfile,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from build_receipt import make_receipt,validate,FIELDS

class ReceiptTests(unittest.TestCase):
    def env(self,**kw):
        return dict(GITHUB_SHA='a'*40,GITHUB_RUN_ID='123',UNIT_OUTCOME='success',DEPS_OUTCOME='success',PACKAGE_OUTCOME='success',NATIVE_OUTCOME='failure',CERTIFICATE_OUTCOME='failure',**kw)
    def test_actual_builder_matches_own_schema_on_failure(self):
        with tempfile.TemporaryDirectory() as x:
            r=make_receipt(x,self.env());self.assertEqual(set(r),FIELDS);self.assertTrue(r['standard_runner_only']);self.assertIsNone(r['certificate_gate'])
    def test_old_combined_key_bug_rejected(self):
        with tempfile.TemporaryDirectory() as x:
            r=make_receipt(x,self.env());r['standard_runner_only certificate_gate']=r.pop('standard_runner_only')
            with self.assertRaises(ValueError):validate(r)
    def test_native_success_certificate_failure_still_recorded(self):
        with tempfile.TemporaryDirectory() as x:
            e=self.env();e['NATIVE_OUTCOME']='success';r=make_receipt(x,e);self.assertEqual(r['native_outcome'],'success');self.assertEqual(r['certificate_outcome'],'failure')
    def test_unpassed_artifact_refused(self):
        with tempfile.TemporaryDirectory() as x:
            e=self.env(ARTIFACT_URL='https://github.com/kokononox/battle-net-agent-lab/actions/runs/123/artifacts/456',ARTIFACT_DIGEST='a'*64)
            with self.assertRaises(ValueError):make_receipt(x,e)
    def test_positive_full_build_receipt(self):
        with tempfile.TemporaryDirectory() as x:
            root=Path(x);package=root/'release'/'Level3-Request-Audit-T1';package.mkdir(parents=True)
            (package/'BUILD-INFO.json').write_text(json.dumps({'python_version':'3.12.10'}));(package/'MANIFEST-SHA256.json').write_text('{}')
            s=dict(passed=True,loopback_only=True,send_observed=True,wsasend_observed=True,sspi_negative_input_observed=True,fixture_excluded_from_real_report=True,worker_exited=True,script_errors=0,error_code=None)
            (package/'selftest-to-share-123.json').write_text(json.dumps(s))
            c=dict(passed=True,runtime_valid=False,runtime_not_blizzard=True,runtime_status='NotSigned',bootstrap_valid=True,bootstrap_blizzard=True,bootstrap_status='Valid',bootstrap_sha256='b'*64,downloaded_only_never_executed=True,phase='complete',error_code=None)
            (root/'certificate-gate.json').write_text(json.dumps(c))
            e=self.env(ARTIFACT_URL='https://github.com/kokononox/battle-net-agent-lab/actions/runs/123/artifacts/456',ARTIFACT_DIGEST='a'*64);e.update(NATIVE_OUTCOME='success',CERTIFICATE_OUTCOME='success')
            r=make_receipt(root,e);self.assertTrue(r['selftest']['passed']);self.assertTrue(r['certificate_gate']['bootstrap_valid'])
    def test_missing_scope_bool_not_defaulted(self):
        with tempfile.TemporaryDirectory() as x:
            r=make_receipt(x,self.env());r.pop('standard_runner_only')
            with self.assertRaises(ValueError):validate(r)
    def test_unknown_fields_not_exported(self):
        with tempfile.TemporaryDirectory() as x:
            r=make_receipt(x,self.env());r['raw_log']='DO_NOT_EXPORT'
            with self.assertRaises(ValueError):validate(r)
if __name__=='__main__':unittest.main()
