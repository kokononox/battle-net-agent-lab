import dataclasses,hashlib,http.client,io,tempfile,unittest,urllib.error
from pathlib import Path
from unittest.mock import patch
from metadata_objects import MetadataSession
from test_metadata_objects import fixture
from test_release_core import target
from release_core import InvalidRelease
class Response:
 def __init__(self,url,body):self.url=url;self.body=body;self.status=200;self.headers={'Content-Length':str(len(body))};self.calls=0
 def geturl(self):return self.url
 def read(self,n):self.calls+=1;part=self.body[:n];self.body=self.body[n:];return part
 def __enter__(self):return self
 def __exit__(self,*a):pass
class Tests(unittest.TestCase):
 def setUp(self):
  self.raw,s=fixture();self.specs=[s,dataclasses.replace(s,name='download',ekey='2'*32),dataclasses.replace(s,name='encoding',ekey='3'*32)];self.t=MetadataSession(target(),self.specs,sum(s.encoded_size for s in self.specs));self.url=next(iter(self.t.allowed));self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.out=Path(self.tmp.name)/'metadata.blte'
 def fetch(self,r):
  with patch('metadata_objects.urllib.request.build_opener')as p:p.return_value.open.return_value=r;return self.t.fetch(self.url,self.out)
 def test_exact_no_extra_eof_read(self):
  r=Response(self.url,self.raw);self.fetch(r);self.assertEqual(r.calls,1);self.assertEqual(self.t.used,len(self.raw));self.assertEqual(self.out.read_bytes(),self.raw)
 def test_no_retry(self):
  self.fetch(Response(self.url,self.raw))
  with self.assertRaises(InvalidRelease):self.fetch(Response(self.url,self.raw))
 def test_reject_missing_length_without_body(self):
  r=Response(self.url,self.raw);r.headers={}
  with self.assertRaises(InvalidRelease):self.fetch(r)
  self.assertEqual(r.calls,0)
 def test_reject_bad_length_without_body(self):
  r=Response(self.url,self.raw);r.headers['Content-Length']=str(len(self.raw)+1)
  with self.assertRaises(InvalidRelease):self.fetch(r)
  self.assertEqual(r.calls,0)
 def test_no_redirect(self):
  r=Response('https://other.example',self.raw)
  with self.assertRaises(InvalidRelease):self.fetch(r)
  self.assertEqual(r.calls,0)
 def test_no_range_response(self):
  r=Response(self.url,self.raw);r.status=206
  with self.assertRaises(InvalidRelease):self.fetch(r)
  self.assertEqual(r.calls,0)
 def test_truncated_counts(self):
  r=Response(self.url,self.raw);r.body=b'x'
  with self.assertRaises(InvalidRelease):self.fetch(r)
  self.assertEqual(self.t.used,1);self.assertFalse(self.out.exists())
 def test_partial_exception_counted(self):
  r=Response(self.url,self.raw)
  with patch.object(r,'read',side_effect=http.client.IncompleteRead(b'ab',5)):
   with self.assertRaises(http.client.IncompleteRead):self.fetch(r)
  self.assertEqual(self.t.used,2);self.assertFalse(self.out.exists())
 def test_http_error_body_not_read(self):
  body=io.BytesIO(b'private');e=urllib.error.HTTPError(self.url,403,'Denied',{},body)
  with patch('metadata_objects.urllib.request.build_opener')as p:
   p.return_value.open.side_effect=e
   with self.assertRaises(urllib.error.HTTPError):self.t.fetch(self.url,self.out)
  self.assertTrue(body.closed);self.assertEqual(self.t.used,0)
if __name__=='__main__':unittest.main()
