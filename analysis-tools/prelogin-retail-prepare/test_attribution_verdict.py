import unittest,copy,json,tempfile,shutil
from pathlib import Path
import attribution_verdict as v
DATA=Path(__file__).parent/'testdata/attribution'
class Verdict(unittest.TestCase):
 def evidence(self):return v.load(DATA)[0]
 def test_real_receipts_and_no_overclaim(self):
  r=v.assess(self.evidence());self.assertTrue(r['t6_inbound_before_finalization_and_update_observed'])
  self.assertEqual(r['t6_observed_tcp_in_octets'],144641739)
  for k in ('game_download_without_login_proven','hardware_upload_during_game_download_proven','copied_game_downloader_provenance_proven','server_storage_proven','all_process_traffic_covered','counters_identify_payload_content','guard_limits_changed','cross_run_counter_subtraction_used'):
   self.assertIs(r[k],False)
 def test_stale_receipt_rejected(self):
  e=self.evidence();e['t7_meter']['run_id']='40613265559'
  with self.assertRaises(ValueError):v.assess(e)
 def test_zero_counter_is_not_positive_proof(self):
  e=self.evidence();e['t7_meter']['data_bytes_in_delta']=0
  self.assertFalse(v.assess(e)['t7_inbound_with_zero_harness_product_api_requests_observed'])
 def test_pending_is_not_completed(self):
  e=self.evidence();e['t7_control']['status']='observing';e['t7_control']['identity_verified_after']=False
  self.assertFalse(v.assess(e)['t7_control_completed'])
 def test_claimed_product_request_rejected(self):
  e=self.evidence();e['t7_control']['product_api_requests']=1
  with self.assertRaises(ValueError):v.assess(e)
 def test_t8_stops_before_update(self):
  r=v.assess(self.evidence());self.assertTrue(r['t8_finalization_http_observed']);self.assertFalse(r['t8_start_attempted']);self.assertEqual(r['t8_supervisor_status'],'phase_network_limit');self.assertFalse(r['t8_after_start_progress_proven'])
 def test_t5_cannot_be_used_as_t8(self):
  e=self.evidence();e['t8_transfer']=e['t5_transfer']
  with self.assertRaises(ValueError):v.assess(e)
 def test_failed_fresh_calibration_rejected(self):
  e=self.evidence();e['t7_calibration']['status']='counter_mismatch'
  with self.assertRaises(ValueError):v.assess(e)
 def test_runtime_product_activity_rejected(self):
  e=self.evidence();e['t7_runtime']['initialization_attempted']=True
  with self.assertRaises(ValueError):v.assess(e)
 def test_input_tamper_rejected(self):
  with tempfile.TemporaryDirectory()as t:
   p=Path(t)/'data';shutil.copytree(DATA,p);(p/'t6_meter.json').write_text('{}')
   with self.assertRaises(ValueError):v.load(p)
 def test_missing_run_rejected(self):
  e=self.evidence();e.pop('t7_meter')
  with self.assertRaises(ValueError):v.assess(e)
 def test_counter_error_is_not_accepted(self):
  e=self.evidence();e['t7_meter']['failed_reads']=1
  with self.assertRaises(ValueError):v.assess(e)
if __name__=='__main__':unittest.main()
