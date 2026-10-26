import base64,hashlib,json,socket,unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch
import fetch_footers as f
from footer import verify_footer
from http_contract import read_response,NoRedirect,request
P=f.plan((f.HERE/'plan.review-only.json').read_bytes());E=P['entries'][0]
def synthetic(count=300,fields=bytes([1,0,0,4,4,4,16,8]),bad_checksum=False):
 b=b'\x11'*8+fields+count.to_bytes(4,'little');b+=hashlib.md5(b[8:]+b'\0'*8).digest()[:8]
 if bad_checksum:b=b[:-1]+bytes([b[-1]^1])
 return b,hashlib.md5(b).hexdigest()
class Resp:
 code=206
 def __init__(self,body=b'a'*28,changes=None):
  self.body=body;self.reads=0;self.headers=Message();h={'Content-Length':'28','Content-Range':f"bytes {E['range_start']}-{E['range_end']}/{E['expected_content_range_total']}"};h.update(changes or {})
  for k,v in h.items():
   if v is not None:self.headers[k]=v
 def read(self,n):self.reads+=1;b=self.body[:n];self.body=self.body[n:];return b
class Tests(unittest.TestCase):
 def setUp(self):self.p=patch.object(socket.socket,'connect',side_effect=AssertionError('network forbidden'));self.p.start()
 def tearDown(self):self.p.stop()
 def test_plan(self):self.assertEqual(sum(e['expected_response_body_bytes'] for e in P['entries']),448)
 def test_pin(self):
  with self.assertRaises(ValueError):f.plan((f.HERE/'plan.review-only.json').read_bytes()+b' ')
 def test_requests(self):
  for e in P['entries']:
   r=request(e);self.assertEqual(r.method,'GET');self.assertIsNone(r.data);self.assertNotIn('?',r.full_url);self.assertEqual(r.get_header('Range'),e['range_header']);self.assertIsNone(r.get_header('Cookie'));self.assertIsNone(r.get_header('Authorization'))
 def reject_before_read(self,r):
  with self.assertRaises(ValueError):read_response(r,E)
  self.assertEqual(r.reads,0)
 def test_full_index(self):r=Resp();r.code=200;self.reject_before_read(r)
 def test_404(self):r=Resp();r.code=404;self.reject_before_read(r)
 def test_exact_response(self):self.assertEqual(len(read_response(Resp(),E)),28)
 def test_length(self):self.reject_before_read(Resp(changes={'Content-Length':'29'}))
 def test_no_length(self):self.reject_before_read(Resp(changes={'Content-Length':None}))
 def test_wrong_total(self):self.reject_before_read(Resp(changes={'Content-Range':f"bytes {E['range_start']}-{E['range_end']}/{E['expected_content_range_total']+1}"}))
 def test_unknown_total(self):self.reject_before_read(Resp(changes={'Content-Range':f"bytes {E['range_start']}-{E['range_end']}/*"}))
 def test_duplicate(self):r=Resp();r.headers['Content-Range']=r.headers['Content-Range'];self.reject_before_read(r)
 def test_gzip(self):self.reject_before_read(Resp(changes={'Content-Encoding':'gzip'}))
 def test_transfer(self):self.reject_before_read(Resp(changes={'Transfer-Encoding':'chunked'}))
 def test_overflow(self):
  with self.assertRaises(ValueError):read_response(Resp(body=b'a'*29),E)
 def test_short(self):
  with self.assertRaises(ValueError):read_response(Resp(body=b'a'*27),E)
 def test_no_redirect(self):self.assertIsNone(NoRedirect().redirect_request(None))
 def test_synthetic_valid(self):
  b,k=synthetic();v=verify_footer(b,k,8268);self.assertEqual(v['derived_blocks'],2);self.assertFalse(v['toc_content_verified'])
 def test_wrong_key(self):
  b,k=synthetic()
  with self.assertRaises(ValueError):verify_footer(b,'0'*32,8268)
 def test_checksum(self):
  b,k=synthetic(bad_checksum=True)
  with self.assertRaises(ValueError):verify_footer(b,k,8268)
 def test_count_bounds(self):
  for n in [0,10001]:
   b,k=synthetic(count=n)
   with self.assertRaises(ValueError):verify_footer(b,k,8268)
 def test_unsupported_fields(self):
  for pos in range(8):
   a=bytearray([1,0,0,4,4,4,16,8]);a[pos]^=1;b,k=synthetic(fields=bytes(a))
   with self.assertRaises(ValueError):verify_footer(b,k,8268)
 def test_layout_mismatch(self):
  b,k=synthetic()
  with self.assertRaises(ValueError):verify_footer(b,k,24748)
 def test_prior_real_archive_footers(self):
  root=f.BASE if (f.BASE/'reports/archive-index-g46/public-index-fixtures.json').exists() else f.BASE.parent/'g46'
  fixtures=json.loads((root/'reports/archive-index-g46/public-index-fixtures.json').read_text())['objects'];count=0
  for x in fixtures.values():
   if x['kind']!='archive_index':continue
   b=base64.b64decode(x['base64']);v=verify_footer(b[-28:],x['key'],len(b));self.assertEqual(v['derived_index_bytes'],len(b));count+=1
  self.assertEqual(count,29)
if __name__=='__main__':unittest.main()
