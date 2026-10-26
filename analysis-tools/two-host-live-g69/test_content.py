import unittest
from content import Inspector
class T(unittest.TestCase):
 def test_split(self):
  a=Inspector();a.feed('s',b'GE');a.feed('s',b'T /tpr/test HTTP/1.1\r\nHost: level3.blizzard.com\r\n\r\n');self.assertEqual(len(a.rows),1)
 def test_two_requests(self):
  a=Inspector();a.feed('s',b'GET /agent/versions HTTP/1.1\r\nHost: us.version.battle.net\r\n\r\n'*2);self.assertEqual(len(a.rows),2)
 def test_sensitive(self):
  a=Inspector();a.feed('s',b'POST /x?device=secret HTTP/1.1\r\nHost: level3.blizzard.com\r\nCookie: secret\r\nContent-Length: 3\r\n\r\nabc');self.assertTrue(a.rows[0]['hardware_field_name_hint']);self.assertTrue(a.rows[0]['credential_header_present']);self.assertNotIn('secret',str(a.report()))
 def test_tls_unknown(self):
  a=Inspector();a.feed('s',b'\x17\x03\x03\x00\x09encrypted');self.assertEqual(len(a.rows),0);self.assertFalse(a.report()['fingerprinting_absence_proven'])
 def test_body_pending(self):
  a=Inspector();a.feed('s',b'POST / HTTP/1.1\r\nHost: level3.blizzard.com\r\nContent-Length: 3\r\n\r\na');self.assertEqual(len(a.rows),0)
 def test_chunked_unknown(self):
  a=Inspector();a.feed('s',b'POST / HTTP/1.1\r\nHost: level3.blizzard.com\r\nTransfer-Encoding: chunked\r\n\r\n');self.assertEqual(len(a.rows),0)
if __name__=='__main__':unittest.main()
