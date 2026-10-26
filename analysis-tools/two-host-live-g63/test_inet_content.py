import unittest
from inet_content import classify
class T(unittest.TestCase):
 def test_target(self):
  p={'server':'us.version.battle.net','method':'GET','path':'/agent/versions','headers':'','body_observed_complete':True};r=classify(p);self.assertEqual(r['layer'],'WinINet_API_input_not_wire_receipt');self.assertFalse(r['automatic_request_headers_observed'])
 def test_unknown(self):self.assertIsNone(classify({'server':'other.test'}))
 def test_sensitive(self):
  r=classify({'server':'level3.blizzard.com','method':'POST','path':'/x?device=private','headers':'Cookie: private\r\n','body_observed_complete':True},b'cpu=private');self.assertTrue(r['hardware_field_name_hint']);self.assertTrue(r['explicit_credential_header_present']);self.assertNotIn('private',str(r))
 def test_false_return_not_receipt(self):self.assertFalse(classify({'server':'level3.blizzard.com','api_returned_true':False,'error':12007})['api_returned_true'])
if __name__=='__main__':unittest.main()
