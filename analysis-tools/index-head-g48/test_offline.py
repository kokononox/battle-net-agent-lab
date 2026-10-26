import copy,json,socket,unittest
from email.message import Message
from unittest.mock import patch
import head_indices as h
P=h.plan((h.HERE/'plan.review-only.json').read_bytes());E=P['entries'][0]
class Response:
 code=200
 def __init__(self,headers=None):
  self.headers=Message()
  for k,v in (headers or {'Content-Length':str(E['original_expected_bytes'])}).items():self.headers[k]=v
 def read(self,*a):raise AssertionError('HEAD must never read body')
class Tests(unittest.TestCase):
 def setUp(self):self.p=patch.object(socket.socket,'connect',side_effect=AssertionError('no network in tests'));self.p.start()
 def tearDown(self):self.p.stop()
 def test_plan(self):self.assertEqual(len(P['entries']),16)
 def test_pin(self):
  with self.assertRaises(ValueError):h.plan((h.HERE/'plan.review-only.json').read_bytes()+b' ')
 def test_request(self):
  for e in P['entries']:
   r=h.request(e);self.assertEqual(r.method,'HEAD');self.assertIsNone(r.data);self.assertIsNone(r.get_header('Range'));self.assertIsNone(r.get_header('Cookie'));self.assertIsNone(r.get_header('Authorization'));self.assertNotIn('?',r.full_url)
 def test_200_zero_read(self):self.assertTrue(h.observe(Response(),E)['head_length_usable_for_review'])
 def test_changed_length_not_validation(self):
  d=h.observe(Response({'Content-Length':'42'}),E);self.assertFalse(d['matches_original_expected']);self.assertFalse(d['payload_or_index_validated'])
 def test_missing_length(self):self.assertFalse(h.observe(Response({'Content-Type':'text/plain'}),E)['head_length_usable_for_review'])
 def test_duplicate_length(self):
  r=Response();r.headers['Content-Length']='8';self.assertFalse(h.observe(r,E)['head_length_usable_for_review'])
 def test_invalid_length(self):self.assertFalse(h.observe(Response({'Content-Length':'-1'}),E)['head_length_usable_for_review'])
 def test_compression(self):self.assertFalse(h.observe(Response({'Content-Length':'10','Content-Encoding':'gzip'}),E)['head_length_usable_for_review'])
 def test_transfer(self):self.assertFalse(h.observe(Response({'Content-Length':'10','Transfer-Encoding':'chunked'}),E)['head_length_usable_for_review'])
 def test_range(self):self.assertFalse(h.observe(Response({'Content-Length':'10','Content-Range':'bytes 0-9/20'}),E)['head_length_usable_for_review'])
 def test_error_status_no_read(self):
  for status in [301,302,404,500]:
   r=Response();r.code=status;self.assertFalse(h.observe(r,E)['head_length_usable_for_review'])
 def test_no_redirect(self):self.assertIsNone(h.NoRedirect().redirect_request(None))
 def test_unknown_headers_omitted(self):
  r=Response();r.headers['Set-Cookie']='ignored';self.assertNotIn('set-cookie',h.observe(r,E)['observed_headers'])
 def test_record_bound(self):
  with self.assertRaises(ValueError):h.observe(Response({'Content-Length':'9'*257}),E)
if __name__=='__main__':unittest.main()
