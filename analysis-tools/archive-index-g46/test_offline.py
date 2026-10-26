import base64,copy,hashlib,json,socket,unittest
from unittest.mock import patch
from pathlib import Path
import bindings,locate
from index_parser import parse_index,Rejected
from http_contract import read_response,NoRedirect
B=locate.BASE;O=locate.OUT
R=json.loads((O/'fetch-evidence.json').read_text())
def synthetic(rows=None,loose=False,count=None,last=None,pad=False):
 rows=rows or [(1,27,100),(2,31,200)];ob=0 if loose else 4
 block=b''.join(k.to_bytes(16,'big')+s.to_bytes(4,'big')+(off.to_bytes(4,'big') if ob else b'') for k,s,off in rows).ljust(4096,b'\0')
 if pad:block=block[:-1]+b'X'
 toc=(last if last is not None else rows[-1][0]).to_bytes(16,'big')+hashlib.md5(block).digest()[:8]
 f=hashlib.md5(toc).digest()[:8]+bytes([1,0,0,4,ob,4,16,8])+(count if count is not None else len(rows)).to_bytes(4,'little')
 f+=hashlib.md5(f[8:]+b'\0'*8).digest()[:8]
 return block+toc+f,hashlib.md5(f).hexdigest(),'loose_file_index' if loose else 'archive_index'
class Resp:
 code=200
 def __init__(self,body=b'ab',headers=None):self.body=body;self.headers=headers or {};self.reads=0
 def read(self,n):self.reads+=1;b=self.body[:n];self.body=self.body[n:];return b
class Tests(unittest.TestCase):
 def setUp(self):self.net=patch.object(socket.socket,'connect',side_effect=AssertionError('network forbidden'));self.net.start()
 def tearDown(self):self.net.stop()
 def test_bindings(self):self.assertEqual(len(bindings.validate(B,locate.ROOT,R)),3)
 def test_row_tamper(self):
  r=copy.deepcopy(R);r['results'][0]['url']+='?x=1'
  with self.assertRaises(ValueError):bindings.validate(B,locate.ROOT,r)
 def test_all_real_fixtures(self):
  fixtures=json.loads((O/'public-index-fixtures.json').read_text())['objects'];n=0
  for r in R['results']:
   if not r['received_and_sized']:continue
   b=base64.b64decode(fixtures[r['id']]['base64'],validate=True)
   self.assertEqual(hashlib.sha256(b).hexdigest(),r['sha256']);self.assertEqual(len(b),r['expected_bytes']);parse_index(b,r['archive_or_index_key'],r['kind']);n+=1
  self.assertEqual(n,30)
 def test_fixture_fallback(self):
  r=next(r for r in R['results'] if r['received_and_sized'])
  with patch.object(Path,'exists',return_value=False):self.assertEqual(len(bindings.snapshot(B,r)),r['bytes'])
 def test_partial_receipt(self):
  rejected=[r for r in R['results'] if not r['received_and_sized']];self.assertEqual(len(rejected),16)
  self.assertTrue(all(r['http_status']==200 and r['error_code']=='response_length' for r in rejected));self.assertEqual(sum(r.get('bytes',0) for r in R['results']),351040)
 def test_real_locations(self):
  d=json.loads((O/'index-verification.json').read_text());self.assertEqual(d['verified_index_count'],30);self.assertFalse(d['all_46_indices_verified'])
  self.assertEqual([len(x['locations']) for x in d['sample_locations']],[1,1,0])
  self.assertEqual([x['locations'][0]['offset'] for x in d['sample_locations'][:2]],[49635016,41437004])
 def test_unexecuted_ranges(self):
  p=json.loads((O/'next-range-plan.unexecuted.json').read_text());self.assertFalse(p['executed']);self.assertEqual(p['expected_encoded_bytes'],4310);self.assertEqual(p['max_requests'],2);self.assertTrue(p['reject_full_archive_200_before_body']);self.assertFalse(p['all_three_samples_have_archive_candidate'])
 def test_synthetic_normal(self):self.assertEqual(parse_index(*synthetic())['entry_count'],2)
 def test_synthetic_loose(self):self.assertEqual(parse_index(*synthetic(loose=True))['offset_bytes'],0)
 def reject(self,**kw):
  with self.assertRaises(Rejected):parse_index(*synthetic(**kw))
 def test_duplicate(self):self.reject(rows=[(1,1,0),(1,1,1)])
 def test_order(self):self.reject(rows=[(2,1,0),(1,1,1)])
 def test_zero_size(self):self.reject(rows=[(1,0,0)])
 def test_overflow(self):self.reject(rows=[(1,2,2**32-1)])
 def test_count(self):self.reject(count=3)
 def test_toc_last_key(self):self.reject(last=3)
 def test_padding(self):self.reject(pad=True)
 def test_corrupt_chain(self):
  b,k,t=synthetic()
  for i in [0,4096,4121,4140]:
   a=bytearray(b);a[i]^=1
   with self.assertRaises(Rejected):parse_index(bytes(a),k,t)
 def test_wrong_filename(self):
  b,k,t=synthetic()
  with self.assertRaises(Rejected):parse_index(b,'0'*32,t)
 def test_length_before_read(self):
  r=Resp(headers={'Content-Length':'99'})
  with self.assertRaises(ValueError):read_response(r,2)
  self.assertEqual(r.reads,0)
 def test_status_before_read(self):
  r=Resp();r.code=404
  with self.assertRaises(ValueError):read_response(r,2)
  self.assertEqual(r.reads,0)
 def test_overflow_response(self):
  with self.assertRaises(ValueError):read_response(Resp(body=b'abc'),2)
 def test_exact_response(self):self.assertEqual(read_response(Resp(),2),b'ab')
 def test_no_redirect(self):self.assertIsNone(NoRedirect().redirect_request(None))
 def test_range_header_rejected(self):
  with self.assertRaises(ValueError):read_response(Resp(headers={'Content-Range':'bytes 0-1/2'}),2)
if __name__=='__main__':unittest.main()
