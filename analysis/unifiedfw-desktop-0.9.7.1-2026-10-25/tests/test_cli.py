"""Subprocess request/response tests with an isolated COPY, not package state."""
from pathlib import Path
import json,shutil,subprocess,sys,tempfile,unittest
APP=Path(__file__).resolve().parents[1]/'app'
class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        shutil.copytree(APP,self.root/'app',ignore=shutil.ignore_patterns('__pycache__'))
    def tearDown(self):self.temp.cleanup()
    def call(self,name,action,payload):
        job=self.root/'private-state/jobs'/name;job.mkdir(parents=True)
        req=job/'request.json';res=job/'response.json';req.write_text(json.dumps(dict(action=action,payload=payload)))
        p=subprocess.run([sys.executable,'-I',str(self.root/'app/cli.py'),'--request',str(req),'--response',str(res)],capture_output=True,text=True)
        self.assertTrue(res.is_file(),p.stderr);return p,json.loads(res.read_text())
    def test_load_configure_preview_subprocess(self):
        p,loaded=self.call('load','load',{});self.assertEqual(p.returncode,0)
        owner=loaded['state']['owner'];self.assertEqual(loaded['state']['config']['generation'],0)
        p,saved=self.call('save','configure',dict(generation=0,mode='vpn_allowlist',whitelist=['8.8.8.0/24']))
        self.assertTrue(saved['ok']);self.assertEqual(saved['state']['owner'],owner)
        p,preview=self.call('preview','preview',{});self.assertTrue(preview['ok']);self.assertFalse(preview['plan']['activation_allowed']);self.assertEqual(len(preview['plan']['rules']),2)
    def test_apply_and_restore_never_escape_gate(self):
        for action in ('apply','restore','hosts_apply'):
            p,r=self.call(action,action,{})
            self.assertEqual(p.returncode,1);self.assertFalse(r['ok']);self.assertFalse(r['firewall_changed']);self.assertIn('disabled',r['error'])
    def test_stale_generation_returns_error_and_no_change(self):
        self.call('load','load',{})
        self.call('save','configure',dict(generation=0,mode='blacklist_only',whitelist=[]))
        settings=self.root/'private-state/settings.json';before=settings.read_bytes()
        p,r=self.call('stale','configure',dict(generation=0,mode='full_isolation',whitelist=['8.8.8.8']))
        self.assertFalse(r['ok']);self.assertEqual(settings.read_bytes(),before)
    def test_job_path_escape_refused(self):
        req=self.root/'request.json';req.write_text('{}');res=self.root/'should-not-exist.json'
        p=subprocess.run([sys.executable,'-I',str(self.root/'app/cli.py'),'--request',str(req),'--response',str(res)],capture_output=True)
        self.assertNotEqual(p.returncode,0);self.assertFalse(res.exists())
if __name__=='__main__':unittest.main()
