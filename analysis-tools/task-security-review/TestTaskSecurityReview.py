import unittest
from ReviewTaskSecurity import review_permissions

def p(cat='authenticated_users',mask=0x1f01ff):return {'complete':True,'descriptor_parsed':True,'aces':[{'ace_type':'AccessAllowed','ace_flags':'None','identity_category':cat,'access_mask':mask}]}
class Tests(unittest.TestCase):
 def test_authenticated_full_block(self):self.assertEqual(review_permissions(p())['status'],'blocked_for_automatic_exception')
 def test_standard_write_dac_block(self):self.assertTrue(review_permissions(p(mask=0x40000))['control_aces'][0]['write_dac'])
 def test_standard_write_owner_block(self):self.assertTrue(review_permissions(p(mask=0x80000))['control_aces'][0]['write_owner'])
 def test_generic_all_block(self):self.assertTrue(review_permissions(p(mask=0x10000000))['control_aces'][0]['generic_all'])
 def test_generic_write_block(self):self.assertTrue(review_permissions(p(mask=0x40000000))['control_aces'][0]['generic_write'])
 def test_read_not_automatic_permission(self):self.assertFalse(review_permissions(p(mask=0x1200a9))['authorizes_exception'])
 def test_admin_full_not_auto_permission(self):self.assertFalse(review_permissions(p(cat='administrators'))['authorizes_exception'])
 def test_unknown_control_identity_blocked(self):self.assertEqual(review_permissions(p(cat='other_identity'))['status'],'blocked_for_automatic_exception')
 def test_missing_unknown(self):self.assertEqual(review_permissions(None)['status'],'unknown')
 def test_missing_aces_unknown(self):self.assertEqual(review_permissions({'complete':True,'descriptor_parsed':True})['status'],'unknown')
 def test_negative_mask_unknown(self):self.assertEqual(review_permissions(p(mask=-1))['status'],'unknown')
 def test_bool_not_mask(self):self.assertEqual(review_permissions(p(mask=True))['status'],'unknown')
 def test_conditional_deny_unknown(self):
  x=p();x['aces'][0]['ace_type']='AccessDenied';self.assertEqual(review_permissions(x)['status'],'unknown')
 def test_inherited_unknown(self):
  x=p();x['aces'][0]['ace_flags']='Inherited';self.assertEqual(review_permissions(x)['status'],'unknown')
 def test_specific_write_unknown(self):self.assertEqual(review_permissions(p(mask=2))['status'],'unknown')
if __name__=='__main__':unittest.main()
