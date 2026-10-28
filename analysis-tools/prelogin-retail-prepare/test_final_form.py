import json,unittest
from pathlib import Path
from unittest.mock import patch
import final_form as f
import finalization_shape as s
import test_transfer_probe as fixtures
class FinalForm(unittest.TestCase):
 def state(self,data=None):
  with patch.object(f.path_guard,'inspect',return_value=fixtures.guard()),patch.object(f.path_relation,'classify',return_value=dict(relation='normalized_equal',child_depth=0,returned_absolute=True,returned_dot_segments=False,filesystem_containment_proven=False)):
   return f.describe(fixtures.final()if data is None else data,Path('D:/PRIVATE'),'a'*40,'1')
 def test_sanitized_form(self):
  r=self.state();self.assertTrue(r['finalized']);self.assertNotIn('PRIVATE',json.dumps(r));self.assertFalse(r['download_proven'])
 def test_missing_error_is_not_observed_zero(self):
  d=fixtures.final();d.pop('error');self.assertIsNone(self.state(d)['error_codes']['agent'])
 def test_explicit_auth_or_legal_not_bypassed(self):
  d=fixtures.final();d['form']['authentication']['error']=4;r=self.state(d)
  self.assertEqual(r['error_codes']['authentication'],4);self.assertIn('authentication_error',r['blockers']);self.assertTrue(r['eula_present']);self.assertFalse(r['legal_acceptance_parameter_sent'])
 def test_exact_install_link_only(self):
  r=s.classify({'response_uri':'/install/wow','PRIVATE':'SECRET'},1234)
  self.assertTrue(r['owned_install_link']);self.assertEqual(r['kind'],'unknown');self.assertNotIn('PRIVATE',json.dumps(r))
  for uri in ('/install/other','http://evil/install/wow','/install/wow?x=1'):
   self.assertFalse(s.classify({'response_uri':uri},1234)['owned_install_link'])
 def test_old_shape_still_readable(self):
  r=s.blank();r.pop('owned_install_link');s.validate(r)
if __name__=='__main__':unittest.main()
