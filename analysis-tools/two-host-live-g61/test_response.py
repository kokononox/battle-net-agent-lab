import unittest
from response_content import summarize
class T(unittest.TestCase):
 def test_tact(self):self.assertEqual(summarize({'server':'us.version.battle.net'},b'Region!STRING:0|Build')['body_format'],'TACT_table_header_observed')
 def test_partial(self):self.assertFalse(summarize({'server':'level3.blizzard.com'},b'\x00\xff')['complete_response_proven'])
 def test_unknown(self):self.assertIsNone(summarize({'server':'other.test'},b'private'))
 def test_no_values(self):self.assertNotIn('secret-value',str(summarize({'server':'level3.blizzard.com'},b'{"cpu":"secret-value"}')))
if __name__=='__main__':unittest.main()
