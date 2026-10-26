import base64,hashlib,json,socket,unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch
import fetch_indices as f
from http_contract import request,read_response,NoRedirect
from index_parser import parse_index
P=f.plan((f.HERE/'plan.review-only.json').read_bytes())
class Resp:
 code=200
 def __init__(self,body=b'ab',changes=None):
  self.body=body;self.reads=0;self.headers=Message();h={'Content-Length':'2'};h.update(changes or {})
  for k,v in h.items():
   if v is not None:self.headers[k]=v
 def read(self,n):self.reads+=1;b=self.body[:n];self.body=self.body[n:];return b
class Tests(unittest.TestCase):
 def setUp(self):self.p=patch.object(socket.socket,'connect',side_effect=AssertionError('network forbidden'));self.p.start()
 def tearDown(self):self.p.stop()
 def test_plan(self):self.assertEqual(sum(e['expected_bytes'] for e in P['entries']),272368)
 def test_pin(self):
  with self.assertRaises(ValueError):f.plan((f.HERE/'plan.review-only.json').read_bytes()+b' ')
 def test_requests(self):
  for e in P['entries']:
   r=request(e);self.assertEqual(r.method,'GET');self.assertIsNone(r.data);self.assertNotIn('?',r.full_url)
   for name in ['Range','Cookie','Authorization']:self.assertIsNone(r.get_header(name))
 def reject(self,r):
  with self.assertRaises(ValueError):read_response(r,2)
  self.assertEqual(r.reads,0)
 def test_206(self):r=Resp();r.code=206;self.reject(r)
 def test_404(self):r=Resp();r.code=404;self.reject(r)
 def test_exact(self):self.assertEqual(read_response(Resp(),2),b'ab')
 def test_length(self):self.reject(Resp(changes={'Content-Length':'3'}))
 def test_no_length(self):self.reject(Resp(changes={'Content-Length':None}))
 def test_duplicate(self):r=Resp();r.headers['Content-Length']='2';self.reject(r)
 def test_compression(self):self.reject(Resp(changes={'Content-Encoding':'gzip'}))
 def test_transfer(self):self.reject(Resp(changes={'Transfer-Encoding':'chunked'}))
 def test_range(self):self.reject(Resp(changes={'Content-Range':'bytes 0-1/2'}))
 def test_oversize(self):
  with self.assertRaises(ValueError):read_response(Resp(body=b'abc'),2)
 def test_short(self):
  with self.assertRaises(ValueError):read_response(Resp(body=b'a'),2)
 def test_no_redirect(self):self.assertIsNone(NoRedirect().redirect_request(None))
 def fixtures(self):
  root=f.BASE if (f.BASE/'reports/archive-index-g46/public-index-fixtures.json').exists() else f.BASE.parent/'g46'
  return json.loads((root/'reports/archive-index-g46/public-index-fixtures.json').read_text())['objects']
 def test_30_prior_real_indexes(self):
  x=self.fixtures();self.assertEqual(len(x),30)
  for v in x.values():
   b=base64.b64decode(v['base64']);self.assertEqual(hashlib.sha256(b).hexdigest(),v['sha256']);parse_index(b,v['key'],v['kind'])
 def test_prior_footer_binding(self):
  v=next(x for x in self.fixtures().values() if x['kind']=='archive_index');b=base64.b64decode(v['base64']);e={'expected_bytes':len(b),'expected_footer_sha256':hashlib.sha256(b[-28:]).hexdigest(),'archive_or_index_key':v['key'],'kind':v['kind']};self.assertEqual(f.verify(e,b)['entry_count'],parse_index(b,v['key'],v['kind'])['entry_count']);e['expected_footer_sha256']='0'*64
  with self.assertRaises(ValueError):f.verify(e,b)
 def test_corruption(self):
  v=next(iter(self.fixtures().values()));b=base64.b64decode(v['base64'])
  for i in [0,len(b)-29,len(b)-1]:
   a=bytearray(b);a[i]^=1
   with self.assertRaises(ValueError):parse_index(bytes(a),v['key'],v['kind'])
 def test_wrong_key(self):
  v=next(iter(self.fixtures().values()));b=base64.b64decode(v['base64'])
  with self.assertRaises(ValueError):parse_index(b,'0'*32,v['kind'])
if __name__=='__main__':unittest.main()
