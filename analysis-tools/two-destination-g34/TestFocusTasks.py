import copy,unittest
from FocusSummary import IDS,summarize
ID=next(iter(IDS))
def snap(xml,phase='poll',elapsed=10,action='a',principal='p',permissions='s'):
 return {'system_identity':True,'phase':phase,'elapsed_seconds':elapsed,'lookup_complete':True,'tasks':{ID:{'capture_complete':True,'xml':xml,'xml_sha256':xml,'actions_sha256':action,'principals_sha256':principal,'permissions_sha256':permissions}}}
A='<Task><Settings><Enabled>true</Enabled></Settings><Triggers><TimeTrigger><StartBoundary>2026-10-25T11:00:00</StartBoundary></TimeTrigger></Triggers></Task>'
B=A.replace('11:00:00','12:00:00')
class Tests(unittest.TestCase):
 def test_no_change(self):self.assertEqual(summarize(snap(A),[snap(A)],snap(A))['tasks'][0]['observed_change_count'],0)
 def test_boundary_change(self):r=summarize(snap(A),[snap(B)],snap(B));self.assertTrue(r['tasks'][0]['changed_without_setup']);self.assertIn('Task/Triggers[1]/TimeTrigger[1]/StartBoundary[1]',r['tasks'][0]['observed_changes'][0]['changed_xml_fields'])
 def test_enabled_not_exempted(self):r=summarize(snap(A),[snap(A.replace('true','false'))],{});self.assertFalse(r['tasks'][0]['automatic_exemption_granted'])
 def test_actor_never_inferred(self):self.assertFalse(summarize(snap(A),[snap(B)],{})['mutation_actor_proven'])
 def test_missing_final_unknown(self):self.assertIsNone(summarize(snap(A),[],{})['tasks'][0]['baseline_final_actions_equal'])
 def test_principal_drift(self):r=summarize(snap(A),[],snap(A,principal='new'));self.assertFalse(r['tasks'][0]['baseline_final_principals_equal'])
 def test_permissions_drift(self):r=summarize(snap(A),[snap(A,permissions='new')],snap(A,permissions='new'));self.assertTrue(r['tasks'][0]['observed_changes'][0]['permissions_changed'])
 def test_missing_binding_unknown(self):self.assertIsNone(summarize(snap(A),[],snap(A))['tasks'][0]['baseline_final_binding_equal'])
 def test_binding_change(self):
  a=snap(A);b=snap(A);a['tasks'][ID]['binding']={'capture_complete':True,'file_sha256':'a'*64,'binding_hash':'b'*64};b['tasks'][ID]['binding']={'capture_complete':True,'file_sha256':'c'*64,'binding_hash':'b'*64};self.assertFalse(summarize(a,[],b)['tasks'][0]['baseline_final_binding_equal'])
 def test_no_signature_claim(self):self.assertFalse(summarize(snap(A),[],{})['image_signatures_newly_verified'])
 def test_missing_permissions_not_equal(self):
  a=snap(A);b=snap(B);del a['tasks'][ID]['permissions_sha256'];del b['tasks'][ID]['permissions_sha256'];r=summarize(a,[b],b)['tasks'][0];self.assertIsNone(r['observed_changes'][0]['permissions_changed']);self.assertIsNone(r['baseline_final_permissions_equal'])
 def test_one_missing_permissions_unknown(self):
  a=snap(A);b=snap(B);del b['tasks'][ID]['permissions_sha256'];self.assertIsNone(summarize(a,[b],b)['tasks'][0]['observed_changes'][0]['permissions_changed'])
 def test_final_nominal_time_not_event_time(self):
  r=summarize(snap(A),[],snap(B,phase='final',elapsed=270))['tasks'][0]['observed_changes'][0];self.assertIsNone(r['elapsed_seconds']);self.assertEqual(r['timing_basis'],'phase_only_nominal_final')
 def test_poll_time_is_watch_relative(self):
  r=summarize(snap(A),[snap(B)],snap(B))['tasks'][0]['observed_changes'][0];self.assertEqual(r['timing_basis'],'snapshot_watch_relative')
 def test_failure_shape_allowlisted(self):
  a=snap(A);a['tasks'][ID].update(failure_stage='task_permissions',failure_hresult='8007007b');r=summarize(a,[],a)['tasks'][0];self.assertEqual(r['baseline_failure_hresult'],'8007007b');self.assertEqual(r['baseline_failure_stage'],'task_permissions')
 def test_enabled_direction(self):
  a=snap(A);b=snap(A.replace('<Enabled>true</Enabled>','<Enabled>false</Enabled>'));r=summarize(a,[b],b)['tasks'][0];self.assertTrue(r['baseline_enabled']);self.assertFalse(r['final_enabled']);self.assertTrue(r['observed_changes'][0]['enabled_before']);self.assertFalse(r['observed_changes'][0]['enabled_after'])
 def test_scheduler_api_handles_absent_xml_default_without_guess(self):
  a=snap('<Task/>');a['tasks'][ID]['scheduler_enabled']=True;self.assertTrue(summarize(a,[],a)['tasks'][0]['baseline_enabled'])
 def test_missing_enabled_unknown(self):
  a=snap('<Task/>');self.assertIsNone(summarize(a,[],a)['tasks'][0]['baseline_enabled'])
 def test_fresh_signature_rollup_not_stale_false(self):
  a=snap(A);a['tasks'][ID]['baseline_signature']={'checked_before_gate':True,'valid_microsoft':True,'hash_stable':True};r=summarize(a,[],a);self.assertTrue(r['image_signatures_newly_verified']);self.assertEqual(r['baseline_signatures_verified_count'],1);self.assertEqual(r['image_signature_scope'],'baseline_pre_gate_only')
 def test_failed_signature_not_verified_rollup(self):
  a=snap(A);a['tasks'][ID]['baseline_signature']={'checked_before_gate':True,'valid_microsoft':False,'hash_stable':True};r=summarize(a,[],a);self.assertFalse(r['image_signatures_newly_verified']);self.assertEqual(r['baseline_signatures_verified_count'],0)
if __name__=='__main__':unittest.main()
