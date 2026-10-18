import unittest
from run import classify,contains_target,PATCH,PIN,TARGET
from validate import validate
class Tests(unittest.TestCase):
 def receipt(self):
  return dict(schema='bnet-hosts-ab-1',runner_image_version='20261018.1.0',windows_build=26100,source_commit='a'*40,run_id='123',mode='baseline',target_domain=TARGET,expected_bootstrap_sha256=PIN,bootstrap_pin_enforced=True,pin_match=True,hosts_changed=False,hosts_restored=False,flush_before_succeeded=True,flush_after_succeeded=False,resolution_before='public_only',resolution_at_launch='public_only',target_public_addresses_before=['8.8.8.8'],launch_precondition_passed=True,capture_invoked=True,outcome='collector_returned',error_code=None,scope='startup_only_not_update_or_payload_privacy_proof')
 def test_public(self):self.assertEqual(classify(['8.8.8.8'])[0],'public_only')
 def test_ipv4_ipv6_loopback(self):self.assertEqual(classify(['127.0.0.1','::1']),('loopback_only',[]))
 def test_mixed(self):self.assertEqual(classify(['127.0.0.1','8.8.8.8'])[0],'mixed_or_other')
 def test_empty(self):self.assertEqual(classify([])[0],'failed')
 def test_comment_not_mapping(self):self.assertFalse(contains_target(b'# telemetry-in.battle.net\r\n127.0.0.1 localhost\r\n'))
 def test_mapping(self):self.assertTrue(contains_target(PATCH))
 def test_alias_mapping(self):self.assertTrue(contains_target(b'127.0.0.1 alias telemetry-in.battle.net # note'))
 def test_good_baseline(self):validate(self.receipt())
 def test_good_block(self):
  r=self.receipt();r.update(mode='block_telemetry',hosts_changed=True,hosts_restored=True,flush_after_succeeded=True,resolution_at_launch='loopback_only');validate(r)
 def test_block_requires_verification(self):
  r=self.receipt();r.update(mode='block_telemetry',hosts_changed=True)
  with self.assertRaises(ValueError):validate(r)
 def test_reject_raw_hosts(self):
  r=self.receipt();r['raw_hosts']='secret'
  with self.assertRaises(ValueError):validate(r)
 def test_no_baseline_mutation(self):
  r=self.receipt();r['hosts_changed']=True
  with self.assertRaises(ValueError):validate(r)
 def test_pin_required(self):
  r=self.receipt();r['bootstrap_pin_enforced']=False
  with self.assertRaises(ValueError):validate(r)
 def test_private_addresses_rejected(self):
  r=self.receipt();r['target_public_addresses_before']=['127.0.0.1']
  with self.assertRaises(ValueError):validate(r)
if __name__=='__main__':unittest.main()
