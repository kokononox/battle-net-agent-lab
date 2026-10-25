import copy,datetime,json,unittest
from reboot_probe import prepare,compare,public,validate_public,state_valid
VALUE='abcdefab-abcd-4abc-abcd-abcdefabcdef';OTHER='00000000-0000-4000-8000-000000000001';SHA='a'*64
BEFORE='2026-10-24T01:00:00+00:00';CREATED='2026-10-24T02:00:00+00:00';AFTER='2026-10-24T03:00:00+00:00';OBSERVED='2026-10-24T04:00:00+00:00'
def context(boot=BEFORE):return dict(boot_utc=boot,machine_guid='SYNTHETIC-MACHINE-ONLY',user_sid='S-1-5-21-111-222-333-1001',profile='SYNTHETIC-PROFILE',volume_serial=42,target_running=False)
def state():return prepare(context(),VALUE,CREATED,SHA)[1]
class Tests(unittest.TestCase):
 def test_prepare_valid(self):
  r,s=prepare(context(),VALUE,CREATED,SHA);validate_public(r);self.assertEqual(r['status'],'prepared_waiting_for_manual_reboot');state_valid(s)
 def test_same_boot_is_not_reboot(self):
  r=compare(state(),context(),VALUE,OBSERVED,SHA);validate_public(r);self.assertEqual(r['status'],'same_boot_not_a_reboot_test');self.assertFalse(r['boot_change_verified']);self.assertIsNone(r['value_equal'])
 def test_same_value_after_later_boot_synthetic_only(self):
  r=compare(state(),context(AFTER),VALUE,OBSERVED,SHA);validate_public(r);self.assertTrue(r['value_equal'])
 def test_changed_value(self):
  r=compare(state(),context(AFTER),OTHER,OBSERVED,SHA);validate_public(r);self.assertIs(r['value_equal'],False)
 def test_missing_after_boot(self):
  r=compare(state(),context(AFTER),None,OBSERVED,SHA);validate_public(r);self.assertEqual(r['status'],'value_absent_after_boot');self.assertIsNone(r['value_equal'])
 def test_invalid_after_boot(self):
  r=compare(state(),context(AFTER),'invalid',OBSERVED,SHA);validate_public(r);self.assertEqual(r['status'],'value_invalid_after_boot')
 def test_wrong_environment_rejected(self):
  for k,v in [('machine_guid','other'),('user_sid','other'),('profile','other'),('volume_serial',43)]:
   c=context(AFTER);c[k]=v;r=compare(state(),c,VALUE,OBSERVED,SHA);validate_public(r);self.assertEqual(r['status'],'environment_changed');self.assertFalse(r['boot_change_verified'])
 def test_changed_script_refused(self):self.assertEqual(compare(state(),context(AFTER),VALUE,OBSERVED,'b'*64)['status'],'environment_changed')
 def test_running_before_blocked(self):
  c=context();c['target_running']=True;r,s=prepare(c,VALUE,CREATED,SHA);self.assertIsNone(s);self.assertEqual(r['status'],'blocked_target_running')
 def test_running_after_blocked(self):
  c=context(AFTER);c['target_running']=True;self.assertEqual(compare(state(),c,VALUE,OBSERVED,SHA)['status'],'blocked_target_running')
 def test_missing_before(self):self.assertIsNone(prepare(context(),None,CREATED,SHA)[1])
 def test_invalid_before(self):self.assertIsNone(prepare(context(),'invalid',CREATED,SHA)[1])
 def test_earlier_boot_rejected(self):self.assertEqual(compare(state(),context('2026-10-23T00:00:00Z'),VALUE,OBSERVED,SHA)['status'],'boot_time_check_failed')
 def test_boot_before_state_capture_rejected(self):self.assertEqual(compare(state(),context('2026-10-24T01:30:00Z'),VALUE,OBSERVED,SHA)['status'],'boot_time_check_failed')
 def test_future_boot_rejected(self):self.assertEqual(compare(state(),context('2026-10-25T00:00:00Z'),VALUE,OBSERVED,SHA)['status'],'boot_time_check_failed')
 def test_case_sensitive_comparison(self):self.assertFalse(compare(state(),context(AFTER),VALUE.upper(),OBSERVED,SHA)['value_equal'])
 def test_private_value_not_public(self):
  r=compare(state(),context(AFTER),VALUE,OBSERVED,SHA);s=json.dumps(r);self.assertNotIn(VALUE,s);self.assertNotIn('SYNTHETIC',s);self.assertNotIn(SHA,s)
 def test_no_extra_fields(self):
  r=public('probe_failed');r['uuid']=VALUE;self.assertRaises(ValueError,validate_public,r)
 def test_no_false_network_claim(self):
  r=public('probe_failed');r['outgoing_host_id_after_reboot_verified']=True;self.assertRaises(ValueError,validate_public,r)
 def test_no_false_boot_claim(self):
  r=public('same_boot_not_a_reboot_test');r['boot_change_verified']=True;self.assertRaises(ValueError,validate_public,r)
 def test_no_false_value_claim(self):
  r=public('probe_failed');r['value_equal']=True;self.assertRaises(ValueError,validate_public,r)
 def test_no_unproved_no_intervening_activity(self):
  r=public('probe_failed');r['intervening_target_activity_excluded']=True;self.assertRaises(ValueError,validate_public,r)
 def test_zero_boolean_refused(self):
  r=public('probe_failed');r['same_environment']=0;self.assertRaises(ValueError,validate_public,r)
 def test_private_unknown_fields_refused(self):
  s=state();s['raw']='anything';self.assertRaises(ValueError,state_valid,s)
 def test_private_bad_uuid_refused(self):
  s=state();s['value']='anything';self.assertRaises(ValueError,state_valid,s)
 def test_private_bad_time_refused(self):
  s=state();s['created_utc']='not-a-date';self.assertRaises(ValueError,state_valid,s)
if __name__=='__main__':unittest.main()
