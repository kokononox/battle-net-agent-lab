import copy
import json
from pathlib import Path
import unittest
import negative_control as n

ROOT=Path(__file__).parent/'testdata'/'d20'
def fixture():
 return [json.loads((ROOT/p).read_text())for p in ('supervision.json','transfer.json')]
class NegativeControl(unittest.TestCase):
 def test_actual_d20_has_no_phase_http_but_limit(self):
  g,t=fixture();r=n.summarize(g,t)
  self.assertTrue(r['phase_limit_without_phase_http_observed'])
  self.assertTrue(r['destination_empty_at_last_snapshot'])
  self.assertEqual(r['phase_network_delta_bytes'],202297567)
 def test_no_claims_of_origin_bug_download_or_hardware(self):
  r=n.summarize(*fixture())
  for k in ('traffic_process_attributed','counter_bug_proven','automatic_agent_activity_excluded','all_game_download_excluded','complete_installation_proven','hardware_upload_in_download_phase_proven'):
   self.assertIs(r[k],False)
 def test_mismatched_run_refused(self):
  g,t=fixture();t['run_id']='1'
  with self.assertRaises(ValueError):n.summarize(g,t)
 def test_no_control_status_refused(self):
  g,t=fixture();t['status']='pending'
  with self.assertRaises(ValueError):n.summarize(g,t)
 def test_no_ack_refused(self):
  g,t=fixture();g['observation']['phase_arming_acknowledged']=False
  with self.assertRaises(ValueError):n.summarize(g,t)
 def test_no_limit_event_refused(self):
  g,t=fixture();g['observation']['status']='worker_failed'
  with self.assertRaises(ValueError):n.summarize(g,t)
 def test_incomplete_cleanup_refused(self):
  g,t=fixture();g['observation']['job_drained']=False;g['observation']['final_active_processes']=1
  with self.assertRaises(ValueError):n.summarize(g,t)
if __name__=='__main__':unittest.main()
