import unittest
from inet_content import classify
from response_content import summarize
class T(unittest.TestCase):
 def test_http_layer(self):
  p={'server':'us.version.battle.net','api_family':'WinHTTP','api':'WinHttpSendRequest','method':'POST','path':'/agent/versions?device=x','body_observed_complete':True,'additional_total_bytes':20}
  r=classify(p,b'device=x');self.assertEqual(r['layer'],'WinHTTP_API_input_not_wire_receipt');self.assertTrue(r['hardware_field_name_hint']);self.assertEqual(r['send_additional_total_bytes'],20);self.assertNotIn('x',r.values())
 def test_http_response(self):
  r=summarize({'server':'level3.blizzard.com','api_family':'WinHTTP','api':'WinHttpReadData'},b'secret-body');self.assertEqual(r['layer'],'WinHTTP_completed_read_API_output');self.assertFalse(r['raw_body_exported']);self.assertNotIn('secret-body',str(r))
