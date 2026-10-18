import copy
import unittest
from validate import validate
from collect import SCHEMA
class ValidationTests(unittest.TestCase):
 def report(self):
  return dict(schema=SCHEMA,source_commit='a'*40,run_id='123',started_utc='2026-10-18T00:00:00+00:00',scope='signed_bootstrap_startup_and_language_page_only_not_game_update',sampler=dict(interval_seconds=.25,samples=10,errors=0,endpoint_limit_hit=False,dns_snapshot_errors=0,new_dns_address_pairs=0),endpoints=[dict(pid=1,process_name='agent.exe',address='8.8.8.8',port=443,first_seconds=1,last_seconds=2,observations=3,states=['Established'],new_dns_cache_candidates=['test.example.com'])],tls_keylog_capability=dict(file_created=False,bytes=0,recognized_line_counts={},truncated=False,keys_exported=False,decryption_attempted=False,request_content_observed=False),bootstrap_status='agent_process_observed',bootstrap_error_code=None,limits={k:True for k in 'tcp_only udp_quic_not_observed short_connections_may_be_missed process_attribution_by_basename_and_pid_not_signature dns_candidates_not_process_attribution dns_shared_ip_not_host_proof no_packet_capture no_payload_inspection no_zero_telemetry_claim no_account_or_game_actions'.split()}|{'child_network_hard_byte_cap':False},collection_status='completed')
 def test_good(self):validate(self.report())
 def test_reject_extra(self):
  r=self.report();r['raw_log']='secret'
  with self.assertRaises(ValueError):validate(r)
 def test_reject_secret_field(self):
  r=self.report();r['tls_keylog_capability']['key']='secret'
  with self.assertRaises(ValueError):validate(r)
 def test_reject_url(self):
  r=self.report();r['endpoints'][0]['new_dns_cache_candidates']=['https://example.com/?token=secret']
  with self.assertRaises(ValueError):validate(r)
 def test_reject_private_ip(self):
  r=self.report();r['endpoints'][0]['address']='127.0.0.1'
  with self.assertRaises(ValueError):validate(r)
 def test_reject_content_claim(self):
  r=self.report();r['tls_keylog_capability']['request_content_observed']=True
  with self.assertRaises(ValueError):validate(r)
if __name__=='__main__':unittest.main()
