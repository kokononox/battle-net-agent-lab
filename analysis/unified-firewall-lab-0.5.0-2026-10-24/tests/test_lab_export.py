from pathlib import Path
import contextlib,hashlib,importlib.util,io,json,tempfile,unittest,zipfile
from unittest.mock import patch
APP=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('lab_export',APP/'lab/export.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.patch=patch.object(module,'ROOT',self.root);self.patch.start()
        self.job=self.root/'private-state/lab-jobs/example';self.job.mkdir(parents=True)
    def tearDown(self):self.patch.stop();self.temp.cleanup()
    def run_export(self,answer='EXPORT'):
        with patch('builtins.input',return_value=answer),contextlib.redirect_stdout(io.StringIO()):module.export()
    def test_cancel_has_no_zip(self):
        self.run_export('NO');self.assertEqual(list(self.root.glob('*.zip')),[])
    def test_no_results_refused(self):
        with self.assertRaisesRegex(ValueError,'no_lab_results'):self.run_export()
    def test_export_redacts_raw_session_and_verifies_hashes(self):
        raw=dict(ok=True,session=dict(id='a',phase='restored',owner='b',entries=[dict(raw_private_image='not_exported')],plan=dict(config_digest='hidden')))
        (self.job/'result.json').write_text(json.dumps(raw));(self.job/'request.json').write_text('NEVER INCLUDED')
        (self.root/'QA.json').write_text('{}');self.run_export()
        with zipfile.ZipFile(next(self.root.glob('*.zip'))) as z:
            self.assertIsNone(z.testzip());out=json.loads(z.read('lab-results/example.json'))
            self.assertNotIn('session',out);self.assertEqual(out['session_summary']['entry_count'],1)
            self.assertFalse(any('request' in n or 'baseline' in n for n in z.namelist()))
            for name,sha in json.loads(z.read('report-sha256.json')).items():self.assertEqual(hashlib.sha256(z.read(name)).hexdigest(),sha)
    def test_symlink_report_refused(self):
        outside=self.root/'outside.json';outside.write_text('{}');(self.job/'result.json').symlink_to(outside)
        with self.assertRaisesRegex(ValueError,'reparse'):self.run_export()
    def test_invalid_json_does_not_create_archive(self):
        (self.job/'result.json').write_text('broken')
        with self.assertRaises(ValueError):self.run_export()
        self.assertEqual(list(self.root.glob('*.zip')),[])
if __name__=='__main__':unittest.main()
