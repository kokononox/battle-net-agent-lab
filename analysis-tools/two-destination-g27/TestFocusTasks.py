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
if __name__=='__main__':unittest.main()
