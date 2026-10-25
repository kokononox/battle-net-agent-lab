import unittest,copy
from ShadowSchedule import PINS,Q,candidate,review
ID=next(iter(PINS));PIN=PINS[ID]
A=f'<Task xmlns="{Q[1:-1]}"><Triggers><TimeTrigger><StartBoundary>2026-10-25T12:00:00Z</StartBoundary></TimeTrigger></Triggers><Settings><Enabled>true</Enabled></Settings></Task>'
B=A.replace('12:00:00','13:00:00')
def row(xml):return {'capture_complete':True,'actions_sha256':PIN[1],'principals_sha256':PIN[2],'permissions_sha256':PIN[4],'baseline_signature':dict(checked_before_gate=True,hash_stable=True,valid_microsoft=True),'binding':dict(capture_complete=True,file_sha256=PIN[3],binding_hash='binding'),'xml':xml}
class Tests(unittest.TestCase):
 def test_candidate(self):self.assertTrue(candidate(ID,row(A),row(B))[0])
 def test_enabled_not_schedule(self):self.assertFalse(candidate(ID,row(A),row(B.replace('true','false')))[0])
 def test_xml_attribute(self):self.assertFalse(candidate(ID,row(A),row(B.replace('<Settings>','<Settings x="1">')))[0])
 def test_action_pin(self):
  b=row(B);b['actions_sha256']='other';self.assertFalse(candidate(ID,row(A),b)[0])
 def test_principal_pin(self):
  b=row(B);b['principals_sha256']='other';self.assertFalse(candidate(ID,row(A),b)[0])
 def test_acl_pin(self):
  b=row(B);b['permissions_sha256']='other';self.assertFalse(candidate(ID,row(A),b)[0])
 def test_no_signature(self):
  a=row(A);a['baseline_signature']={};self.assertFalse(candidate(ID,a,row(B))[0])
 def test_signature_hash_unstable(self):
  a=row(A);a['baseline_signature']['hash_stable']=False;self.assertFalse(candidate(ID,a,row(B))[0])
 def test_image_change(self):
  b=row(B);b['binding']['file_sha256']='f'*64;self.assertFalse(candidate(ID,row(A),b)[0])
 def test_binding_change(self):
  b=row(B);b['binding']['binding_hash']='changed';self.assertFalse(candidate(ID,row(A),b)[0])
 def test_missing_capture(self):self.assertFalse(candidate(ID,{},row(B))[0])
 def test_unknown_identity(self):self.assertFalse(candidate('unknown',row(A),row(B))[0])
 def test_invalid_date(self):self.assertFalse(candidate(ID,row(A),row(B.replace('2026-10-25','2026-99-99')))[0])
 def test_no_change(self):self.assertFalse(candidate(ID,row(A),row(A))[0])
 def test_duplicate_boundary(self):self.assertFalse(candidate(ID,row(A),row(B.replace('</TimeTrigger>','<StartBoundary>2026-10-25T14:00:00Z</StartBoundary></TimeTrigger>')))[0])
 def test_entity(self):self.assertFalse(candidate(ID,row(A),row('<!DOCTYPE Task>'+B))[0])
 def test_shadow_never_grants(self):
  r=review({'system_identity':True,'tasks':{ID:row(A)}},{'system_identity':True,'tasks':{ID:row(B)}});self.assertFalse(r['ready_for_enforcement']);self.assertFalse(r['automatic_exemptions_added']);self.assertFalse(r['tasks'][0]['automatic_exemption_granted'])
if __name__=='__main__':unittest.main()
