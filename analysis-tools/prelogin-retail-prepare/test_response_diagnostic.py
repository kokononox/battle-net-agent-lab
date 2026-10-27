import json
import unittest
import response_diagnostic as d

class Diagnostic(unittest.TestCase):
 def test_safe_code_and_no_raw_message(self):
  r=d.describe({'code':42,'message':'PRIVATE_TOKEN auth refused /private/path'})
  self.assertEqual(r['nodes'][0]['numeric_code'],42)
  self.assertIn('authentication',r['message_markers'])
  self.assertNotIn('PRIVATE',json.dumps(r));self.assertNotIn('/private/path',json.dumps(r))
 def test_unknown_keys_not_exported(self):
  r=d.describe({'PRIVATE_IDENTIFIER':'SECRET'})
  self.assertEqual(r['unknown_top_fields'],1);self.assertNotIn('PRIVATE',json.dumps(r))
 def test_boolean_not_numeric_code(self):
  self.assertIsNone(d.describe({'code':True})['nodes'][0]['numeric_code'])
 def test_nested_and_string_values_not_exported(self):
  r=d.describe({'result':{'token':'SECRET'},'url':'http://PRIVATE','id':'PRIVATE_UUID'})
  self.assertNotIn('SECRET',json.dumps(r));self.assertNotIn('PRIVATE',json.dumps(r))
 def test_extra_fields_refused(self):
  r=d.blank();r['token']='PRIVATE'
  with self.assertRaises(ValueError):d.validate(r)
 def test_no_claim_without_observation(self):d.validate(d.blank())

if __name__=='__main__':unittest.main()
