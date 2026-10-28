import copy,json,os,tempfile,unittest
from pathlib import Path
import receipt as r
import run_fixture as f

def valid():
 d=dict(schema='bnet-tcp-fixture-1',source_commit='a'*40,run_id='1',status='calibrated',**r.FIXED)
 d.update({k:True for k in r.FLAGS});d.update({k:0 for k in r.NUMS})
 for k in ('application_received_bytes','data_bytes_in_delta','thru_bytes_received_delta'):d[k]=1048576
 for k in ('application_sent_bytes','data_bytes_out_delta','thru_bytes_acked_delta'):d[k]=65536
 return d
class Receipt(unittest.TestCase):
 def test_valid(self):r.validate(valid())
 def test_no_gate_can_be_omitted(self):
  for k in r.FLAGS:
   d=valid();d[k]=False
   with self.assertRaises(ValueError):r.validate(d)
 def test_no_raw_exports_or_target_allowed(self):
  for k in r.FIXED:
   d=valid();d[k]=not d[k]
   with self.assertRaises(ValueError):r.validate(d)
 def test_exact_counter_matching(self):
  for k in r.NUMS-{'hostwide_adapter_delta_bytes'}:
   d=valid();d[k]+=1
   with self.assertRaises(ValueError):r.validate(d)
 def test_host_counter_not_identity_proof(self):
  for n in (0,202297567,2**40):
   d=valid();d['hostwide_adapter_delta_bytes']=n;r.validate(d)
 def test_no_bool_as_number(self):
  for k in r.NUMS:
   d=valid();d[k]=True
   with self.assertRaises(ValueError):r.validate(d)
 def test_unknown_secret_field_rejected(self):
  d=valid();d['endpoint']='private'
  with self.assertRaises(ValueError):r.validate(d)
 def test_failed_enable_cannot_calibrate(self):
  d=valid();d['win32_error']=5;d['status']='enable_failed';d['collection_enabled']=False;r.validate(d)
  d['status']='calibrated'
  with self.assertRaises(ValueError):r.validate(d)
 def test_duplicate_json_rejected(self):
  with tempfile.TemporaryDirectory()as t:
   p=Path(t)/'r.json';p.write_text(json.dumps(valid())[:-1]+',"status":"calibrated"}')
   with self.assertRaises(ValueError):r.read(p)
class Scope(unittest.TestCase):
 def env(self):return dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1',GITHUB_REF=f.BRANCH,TCP_CALIBRATION='approved-owned-tcp-t1')
 def test_workflow_approval_uses_block_scalar(self):
  text=(Path(f.__file__).resolve().parents[2]/'.github/workflows/prelogin-tcp-attribution.yml').read_text()
  self.assertEqual(text.count('    if: >-'),2)
  self.assertNotIn("if: github.run_attempt",text)
 def test_fresh_hosted_only(self):
  e=self.env();self.assertTrue(f.allowed(e,'win32'));self.assertFalse(f.allowed(e,'linux'))
  for k in e:
   d=e.copy();d[k]='wrong';self.assertFalse(f.allowed(d,'win32'))
 def test_target_approval_forbidden(self):
  for k in ('RETAIL_PREPARE','RETAIL_SUPERVISED'):
   d=self.env();d[k]='yes';self.assertFalse(f.allowed(d,'win32'))
 def test_native_does_not_connect_external_or_launch_target(self):
  s=Path(f.__file__).with_name('tcp_fixture.cpp').read_text()
  self.assertIn('htonl(INADDR_LOOPBACK)',s);self.assertNotIn('CreateProcess',s)
  self.assertNotIn('getaddrinfo',s);self.assertIn('rw.EnableCollection!=TRUE',s)
  self.assertIn('r.dwOwningPid==GetCurrentProcessId()',s)
  self.assertIn('r.control_clean',s)
if __name__=='__main__':unittest.main()
