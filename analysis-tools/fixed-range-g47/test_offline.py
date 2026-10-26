import hashlib,json,socket,unittest
from email.message import Message
from unittest.mock import patch
import fetch_ranges as f
P=f.load_plan((f.HERE/'plan.review-only.json').read_bytes());E=P['entries'][0]
class Resp:
 code=206
 def __init__(self,body=None,changes=None):
  self.body=b'a'*E['expected_encoded_bytes'] if body is None else body;self.reads=0;self.headers=Message()
  h={'Content-Length':str(E['expected_encoded_bytes']),'Content-Range':f"bytes {E['range_start']}-{E['range_end']}/60000000"}
  h.update(changes or {})
  for k,v in h.items():
   if v is not None:self.headers[k]=v
 def read(self,n):self.reads+=1;b=self.body[:n];self.body=self.body[n:];return b
class Tests(unittest.TestCase):
 def setUp(self):self.p=patch.object(socket.socket,'connect',side_effect=AssertionError('network forbidden'));self.p.start()
 def tearDown(self):self.p.stop()
 def reject(self,r):
  with self.assertRaises(ValueError):f.read_response(r,E)
  self.assertEqual(r.reads,0)
 def test_plan(self):self.assertEqual(sum(x['expected_encoded_bytes'] for x in P['entries']),4310)
 def test_tamper_plan(self):
  with self.assertRaises(ValueError):f.load_plan((f.HERE/'plan.review-only.json').read_bytes()+b' ')
 def test_request(self):
  for e in P['entries']:
   r=f.request(e);self.assertIsNone(r.data);self.assertEqual(r.method,'GET');self.assertNotIn('?',r.full_url);self.assertEqual(r.get_header('Range'),e['range_header']);self.assertIsNone(r.get_header('Cookie'));self.assertIsNone(r.get_header('Authorization'))
 def test_no_redirect(self):self.assertIsNone(f.NoRedirect().redirect_request(None))
 def test_whole_archive(self):r=Resp();r.code=200;self.reject(r)
 def test_404(self):r=Resp();r.code=404;self.reject(r)
 def test_exact(self):self.assertEqual(len(f.read_response(Resp(),E)),27)
 def test_wrong_length(self):self.reject(Resp(changes={'Content-Length':'28'}))
 def test_missing_length(self):self.reject(Resp(changes={'Content-Length':None}))
 def test_missing_range(self):self.reject(Resp(changes={'Content-Range':None}))
 def test_wrong_range(self):self.reject(Resp(changes={'Content-Range':'bytes 0-26/60000000'}))
 def test_unknown_total(self):self.reject(Resp(changes={'Content-Range':f"bytes {E['range_start']}-{E['range_end']}/*"}))
 def test_invalid_total(self):self.reject(Resp(changes={'Content-Range':f"bytes {E['range_start']}-{E['range_end']}/{E['range_end']}"}))
 def test_duplicate(self):r=Resp();r.headers['Content-Range']=r.headers['Content-Range'];self.reject(r)
 def test_compression(self):self.reject(Resp(changes={'Content-Encoding':'gzip'}))
 def test_transfer(self):self.reject(Resp(changes={'Transfer-Encoding':'chunked'}))
 def test_overflow(self):
  with self.assertRaises(ValueError):f.read_response(Resp(body=b'a'*28),E)
 def test_short(self):
  with self.assertRaises(ValueError):f.read_response(Resp(body=b'a'),E)
 def test_synthetic_blte(self):
  d=b'local synthetic only';b=b'BLTE'+b'\0'*4+b'N'+d;e={'expected_encoded_bytes':len(b),'expected_decoded_bytes':len(d),'ekey':hashlib.md5(b).hexdigest(),'ckey':hashlib.md5(d).hexdigest()};v,out=f.verify(e,b);self.assertEqual(out,d);self.assertTrue(v['decoded_ckey_verified'])
  e['ckey']='0'*32
  with self.assertRaises(ValueError):f.verify(e,b)
 def test_bad_ekey(self):
  with self.assertRaises(ValueError):f.verify(E,b'a'*27)
if __name__=='__main__':unittest.main()
