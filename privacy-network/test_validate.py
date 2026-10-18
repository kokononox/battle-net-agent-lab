import unittest
from validate import validate
class ValidatorTests(unittest.TestCase):
 def report(self):
  return dict(schema='bnet-network-metadata-1',source_commit='a'*40,run_id='123',scope='startup_language_only_no_account_game_or_install_action',capture=dict(start_code=0,stop_code=0,convert_code=0,etl_bytes=2000,pcapng_bytes=1000,parse_status='parsed',raw_files_exported=False,requested_etl_megabytes=32,requested_packet_bytes=1536,logging_mode='circular'),dns_probe_before=dict(status='ok',category='none',hresult=0,row_count=0,old_json_shape='empty'),dns_probe_after=dict(status='ok',category='none',hresult=0,row_count=1,old_json_shape='object'),sampler=dict(samples=1,errors=0,flow_limit_hit=False),packet_stats={'packets':1},flows=[dict(process_name='agent.exe',pid=1,address='8.8.8.8',port=443,matched_outbound_packet_observations=1,prefix_gap=False,prefix_limit_hit=False,dns_candidates=['example.com'],tls_sni='example.com',http_host=None,http_method=None,cache_candidates=[])],binary_hints=[],bootstrap_status='agent_process_observed',bootstrap_error_code=None,limits={k:True for k in 'no_hardware_privacy_guarantee no_game_update_test sampling_can_miss_connections tuple_correlation_not_cryptographic_pid_proof dns_candidates_not_hostname_proof nic_duplicates_retransmissions_offload_possible packet_counts_not_requests_or_wire_byte_totals initial_contiguous_prefix_only fragments_ipv6_extensions_quic_doh_not_decoded circular_capture_may_lose_early_packets sni_may_be_outer_name_under_ech'.split()}|{k:False for k in 'decryption_performed keylog_experiment_repeated raw_headers_urls_bodies_exported bootstrap_child_network_hard_byte_cap'.split()})
 def test_good(self):validate(self.report())
 def test_raw_secret_reject(self):
  r=self.report();r['raw_payload']='secret'
  with self.assertRaises(ValueError):validate(r)
 def test_header_secret_reject(self):
  r=self.report();r['flows'][0]['Authorization']='secret'
  with self.assertRaises(ValueError):validate(r)
 def test_host_url_reject(self):
  r=self.report();r['flows'][0]['tls_sni']='https://test.com/?token=secret'
  with self.assertRaises(ValueError):validate(r)
 def test_id_label_reject(self):
  r=self.report();r['flows'][0]['tls_sni']='abcdef0123456789.test.com'
  with self.assertRaises(ValueError):validate(r)
 def test_private_address_reject(self):
  r=self.report();r['flows'][0]['address']='192.168.0.1'
  with self.assertRaises(ValueError):validate(r)
 def test_payload_claim_reject(self):
  r=self.report();r['limits']['decryption_performed']=True
  with self.assertRaises(ValueError):validate(r)
if __name__=='__main__':unittest.main()
