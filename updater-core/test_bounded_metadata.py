import unittest,io
from bounded_metadata import metadata_headers,read_metadata
from release_core import InvalidRelease
class R:
 status=200
 def __init__(self,headers,body=b'abc'):self.headers=headers;self.body=io.BytesIO(body)
 def geturl(self):return 'https://cdn.example/pinned.index'
 def read(self,n):return self.body.read(n)
class Tests(unittest.TestCase):
 def test_no_length_bounded(self):
  r=R({'Transfer-Encoding':'chunked'},b'abcEXTRA');self.assertIsNone(metadata_headers(r,r.geturl(),3)['content_length']);n=[];self.assertEqual(read_metadata(r,3,n.append),b'abc');self.assertEqual(sum(n),3);self.assertEqual(r.body.tell(),3)
 def test_exact_length(self):
  r=R({'Content-Length':'3'});self.assertEqual(metadata_headers(r,r.geturl(),3)['content_length'],'3')
 def test_wrong_length_no_body(self):
  r=R({'Content-Length':'4'})
  with self.assertRaises(InvalidRelease):metadata_headers(r,r.geturl(),3)
  self.assertEqual(r.body.tell(),0)
 def test_reject_status_range_encoding_url(self):
  for headers in ({'Content-Range':'bytes 0-2/3'},{'Content-Encoding':'gzip'}):
   r=R(headers)
   with self.assertRaises(InvalidRelease):metadata_headers(r,r.geturl(),3)
   self.assertEqual(r.body.tell(),0)
  r=R({});r.status=206
  with self.assertRaises(InvalidRelease):metadata_headers(r,r.geturl(),3)
  r.status=200
  with self.assertRaises(InvalidRelease):metadata_headers(r,'https://different.example',3)
 def test_short_counted(self):
  n=[]
  with self.assertRaises(InvalidRelease):read_metadata(R({},b'ab'),3,n.append)
  self.assertEqual(sum(n),2)
if __name__=='__main__':unittest.main()
class CappedTests(unittest.TestCase):
 def test_shorter_frame_not_identity(self):
  from bounded_metadata import capped_metadata_headers
  r=R({'Content-Length':'40'},b'x'*40);obs,n=capped_metadata_headers(r,r.geturl(),100);self.assertEqual(n,40);self.assertEqual(r.body.tell(),0)
 def test_over_budget_rejected(self):
  from bounded_metadata import capped_metadata_headers
  r=R({'Content-Length':'101'})
  with self.assertRaises(InvalidRelease):capped_metadata_headers(r,r.geturl(),100)
  self.assertEqual(r.body.tell(),0)
 def test_unframed_rejected(self):
  from bounded_metadata import capped_metadata_headers
  r=R({})
  with self.assertRaises(InvalidRelease):capped_metadata_headers(r,r.geturl(),100)
class PinnedCeilingTests(unittest.TestCase):
 def test_independent_approved_ceiling(self):
  from bounded_metadata import pinned_index_headers
  r=R({'Content-Length':'120'},b'x'*120);_,n=pinned_index_headers(r,r.geturl(),150,500);self.assertEqual(n,120);self.assertEqual(r.body.tell(),0)
 def test_aggregate_remaining_enforced(self):
  from bounded_metadata import pinned_index_headers
  r=R({'Content-Length':'120'})
  with self.assertRaises(InvalidRelease):pinned_index_headers(r,r.geturl(),150,100)
  self.assertEqual(r.body.tell(),0)
 def test_no_boolean_budget(self):
  from bounded_metadata import pinned_index_headers
  r=R({'Content-Length':'120'})
  with self.assertRaises(InvalidRelease):pinned_index_headers(r,r.geturl(),150,True)
