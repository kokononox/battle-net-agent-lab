import gzip
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'privacy-network'))
# Local files have sibling sandbox names in development.
if not (Path(__file__).resolve().parents[1]/'privacy-network').exists():sys.path.insert(0,'/data/privacy-network')
from body_meta import analyze_body
from monitor import module_category, Monitor
from types import SimpleNamespace
import importlib.util
spec=importlib.util.spec_from_file_location('tls_validator',Path(__file__).with_name('validate.py'));v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v);validate=v.validate
class Tests(unittest.TestCase):
 def test_json_hints_no_values(self):
  b=b'{"deviceId":"SECRET_VALUE","nested":{"cpu_model":"SECRET_CPU"}}';r=analyze_body(b,len(b));self.assertEqual(r['field_name_hints'],['cpu_model','device_id']);self.assertNotIn('SECRET',json.dumps(r))
 def test_gzip(self):
  b=gzip.compress(b'{"hardwareId":"SECRET_VALUE"}');r=analyze_body(b,len(b));self.assertEqual(r['field_name_hints'],['hardware_id']);self.assertEqual(r['compression'],'gzip')
 def test_gzip_cap(self):
  b=gzip.compress(b'x'*1000000);r=analyze_body(b,len(b));self.assertEqual(r['format'],'gzip_incomplete');self.assertTrue(r['decoded_truncated'])
 def test_form(self):
  b=b'device_id=SECRET&locale=SECRET';r=analyze_body(b,len(b));self.assertEqual(r['field_name_hints'],['device_id','locale']);self.assertNotIn('SECRET',json.dumps(r))
 def test_http(self):
  b=b'POST /?token=SECRET HTTP/1.1\r\nHost: telemetry-in.battle.net\r\nAuthorization: SECRET\r\n\r\n{"cpu":"SECRET"}'
  r=analyze_body(b,len(b));self.assertEqual(r['http_host'],'telemetry-in.battle.net');self.assertEqual(r['http_method'],'POST');self.assertNotIn('SECRET',json.dumps(r))
 def test_empty(self):self.assertEqual(analyze_body(b'',0)['format'],'empty')
 def test_unreadable(self):self.assertEqual(analyze_body(b'',1,False)['format'],'unreadable')
 def test_binary(self):self.assertEqual(analyze_body(b'\x00\xff\x01',3)['format'],'other_or_binary')
 def test_unknown_key_no_value(self):
  b=b'{"unknown":"SECRET"}';r=analyze_body(b,len(b));self.assertEqual(r['keys_examined'],1);self.assertEqual(r['field_name_hints'],[])
 def test_module_classification(self):
  self.assertEqual(module_category('winhttp.dll'),'winhttp.dll');self.assertEqual(module_category('libssl-3-x64.dll'),'openssl_ssl_module');self.assertIsNone(module_category('private-name.dll'))
 def minimal(self):
  return dict(schema='bnet-live-tls-buffer-observation-2',source_commit='a'*40,run_id='123',scope='fresh_vm_startup_no_login_game_or_install_action',tool_version='17.24.2',selftest=dict(passed=False,stage='attach',loopback_only=True,synthetic_events_excluded_from_real_evidence=True),bootstrap_pin_match=None,processes=[],events=[],monitor_stats=dict(snapshots=0,errors=0,process_limit_hit=False,dropped_events=0),status='stopped',error_code='owned_loopback_selftest_failed',limits={k:False for k in 'paths_exported tls_verification_changed api_results_or_buffers_modified full_update_or_transfer_test'.split()}|{k:True for k in 'raw_values_headers_bodies_exported plaintext_is_api_input_not_proof_of_delivery field_names_are_hints_not_hardware_value_proof only_known_exported_apis_observed late_attach_and_event_caps_can_miss_data loaded_module_not_proof_of_use instrumentation_can_change_timing_or_behavior'.split()})
 def test_no_reserved_invocation_context_assignment(self):
  s=Path(__file__).with_name('hook.js').read_text();self.assertNotIn('this.context=',s);self.assertIn('this.labContext=contextTag',s)
 def test_no_reserved_invocation_context_assignment(self):
  s=Path(__file__).with_name('hook.js').read_text();self.assertNotIn('this.context=',s);self.assertIn('this.labContext=contextTag',s)
 def test_cancellation_context(self):
  class Cancel:
   def __init__(self):self.active=False
   def __enter__(self):self.active=True;return self
   def __exit__(self,*args):self.active=False
   def cancel(self):pass
  m=Monitor.__new__(Monitor);m.frida=SimpleNamespace(Cancellable=Cancel)
  self.assertTrue(m.bounded(lambda c:c.active))
 def test_minimal_valid(self):validate(self.minimal())
 def test_raw_export_rejected(self):
  r=self.minimal();r['body']='SECRET'
  with self.assertRaises(ValueError):validate(r)
 def test_privacy_claim_rejected(self):
  r=self.minimal();r['limits']['field_names_are_hints_not_hardware_value_proof']=False
  with self.assertRaises(ValueError):validate(r)
if __name__=='__main__':unittest.main()
