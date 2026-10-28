import copy,json,unittest
import operation_state as o
class Operation(unittest.TestCase):
 def describe(self,**kw):return o.describe(dict(progress=0.0,download_complete=False,playable=False,**kw),'install')
 def test_real_typed_operation_can_authorize_attempt_not_success(self):
  s=self.describe();self.assertTrue(o.eligible(s));self.assertIsNone(s['error_code']);self.assertFalse(s['error_present'])
  r=o.receipt('a'*40,'1',[s]);self.assertFalse(r['game_payload_proven']);self.assertFalse(r['complete_installation_proven'])
 def test_explicit_auth_legal_and_error_are_not_bypassed(self):
  for kw in ({'error':4},{'error':True},{'requires_login':True},{'requires_login':1},{'requires_eula':True},{'authentication':{}},{'eula':False},{'error_code':42},{'message':'account login required'},{'errors':['PRIVATE']}):
   self.assertFalse(o.eligible(self.describe(**kw)))
 def test_unknown_private_values_are_not_exported(self):
  r=self.describe(PRIVATE_UUID='SECRET',response_uri='http://PRIVATE')
  self.assertNotIn('PRIVATE',json.dumps(r));self.assertNotIn('SECRET',json.dumps(r))
 def test_form_and_non_install_not_eligible(self):
  self.assertFalse(o.eligible(self.describe(form={})))
  s=self.describe();s['resource']='game';self.assertFalse(o.eligible(s))
 def test_fraction_must_be_finite_real_typed_and_in_range(self):
  for v in (True,-1,1.1,float('nan'),float('inf'),'0'):
   s=o.describe({'progress':v,'download_complete':False},'install');self.assertFalse(o.eligible(s))
 def test_no_success_flags_allowed(self):
  r=o.receipt('a'*40,'1',[self.describe()]);r['game_payload_proven']=True
  with self.assertRaises(ValueError):o.validate(r)
 def test_malformed_counter_or_raw_field_rejected(self):
  s=self.describe();s['raw']='PRIVATE'
  with self.assertRaises(ValueError):o.validate_state(s)
if __name__=='__main__':unittest.main()
