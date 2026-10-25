import json,unittest
from LogErrors import extract_codes
class Tests(unittest.TestCase):
 def test_recognized_codes(self):
  r=extract_codes(b'error 12175 ssl certificate 0x800B0109 BLZBNTBTS0000005C');self.assertEqual({x['category'] for x in r['codes']},{'winhttp_secure_failure','certificate_untrusted_root','blizzard_error_code'})
 def test_raw_details_not_exported(self):
  r=extract_codes(b'https://private.example/?token=SECRET user@example.org C:\\Users\\Private error 12002');s=json.dumps(r);self.assertNotIn('SECRET',s);self.assertNotIn('example',s);self.assertNotIn('Private',s)
 def test_port_not_error(self):self.assertEqual(extract_codes(b'connecting on port 12045')['codes'],[])
 def test_bounded_code_count(self):
  r=extract_codes(' '.join('0x8%07x'%n for n in range(64)).encode());self.assertEqual(len(r['codes']),32);self.assertTrue(r['codes_truncated'])
 def test_utf16(self):self.assertEqual(extract_codes('error 12007'.encode('utf-16'))['codes'][0]['category'],'name_not_resolved')
 def test_error_keywords_not_verdict(self):
  r=extract_codes(b'certificate accepted; no error; no failed attempt');self.assertEqual(r['keyword_counts']['certificate'],1);self.assertEqual(r['codes'],[])
if __name__=='__main__':unittest.main()
