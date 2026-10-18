import dataclasses,hashlib,json,unittest
from unittest.mock import patch
from release_core import RunCheckpoint,InvalidRelease
from test_release_core import fixture_baseline,target
from test_local_candidates import fixture
from range_resume import ObjectTransfer,RangeResult,ApprovedRanges,object_url,strong_etag
class Response:
 def __init__(self,url,a,b,total,body):
  self.url=url;self.status=206;self.headers={'Content-Range':f'bytes {a}-{b}/{total}','Content-Length':str(b-a+1),'ETag':'"fixed"'};self.body=body;self.reads=0
 def geturl(self):return self.url
 def __enter__(self):return self
 def __exit__(self,*a):pass
 def read(self,n):self.reads+=1;r=self.body[:n];self.body=self.body[n:];return r
class Tests(unittest.TestCase):
 def setUp(self):
  _,self.raw,self.spec,_,_=fixture();self.cp=RunCheckpoint(fixture_baseline(),target());self.s=ObjectTransfer(self.cp,self.spec);self.url=object_url(self.cp,self.spec)
 def result(self,a,b):return RangeResult(self.url,a,b,len(self.raw),'"fixed"',self.raw[a:b+1])
 def bad(self,fn,*a):
  with self.assertRaises(InvalidRelease):fn(*a)
 def partial(self):return self.s.accept(self.result(0,25),(0,25))
 def test_split_roundtrip(self):
  p=self.partial();p=ObjectTransfer.restore(p.serialize(),self.cp,self.spec,self.cp.baseline);span=p.next_range(len(self.raw));q=p.accept(self.result(*span),span);self.assertTrue(q.verified()['full_ckey_verified']);self.assertFalse(q.verified()['installation_ready'])
 def test_incomplete(self):self.bad(self.partial().verified)
 def test_wrong_baseline(self):self.bad(ObjectTransfer.restore,self.partial().serialize(),self.cp,self.spec,fixture_baseline('1.0.1.101'))
 def test_wrong_target(self):self.bad(ObjectTransfer.restore,self.partial().serialize(),RunCheckpoint(self.cp.baseline,target('1.2.0.300')),self.spec,self.cp.baseline)
 def test_wrong_object(self):self.bad(ObjectTransfer.restore,self.partial().serialize(),self.cp,dataclasses.replace(self.spec,ckey='f'*32),self.cp.baseline)
 def test_tamper(self):
  d=json.loads(self.partial().serialize());d['partial_sha256']='f'*64;self.bad(ObjectTransfer.restore,json.dumps(d).encode(),self.cp,self.spec,self.cp.baseline)
 def test_duplicate(self):self.bad(ObjectTransfer.restore,b'{"format":1,"format":2}',self.cp,self.spec,self.cp.baseline)
 def test_extra_field(self):
  d=json.loads(self.s.serialize());d['install']=True;self.bad(ObjectTransfer.restore,json.dumps(d).encode(),self.cp,self.spec,self.cp.baseline)
 def test_invalid_base64(self):
  d=json.loads(self.s.serialize());d['partial_base64']='??';self.bad(ObjectTransfer.restore,json.dumps(d).encode(),self.cp,self.spec,self.cp.baseline)
 def test_changed_etag(self):
  p=self.partial();r=dataclasses.replace(self.result(26,len(self.raw)-1),etag='"new"');self.bad(p.accept,r,(26,len(self.raw)-1))
 def test_wrong_url(self):self.bad(self.s.accept,dataclasses.replace(self.result(0,25),url='https://example.org'),(0,25))
 def test_wrong_range(self):self.bad(self.s.accept,self.result(1,25),(0,25))
 def test_wrong_length(self):self.bad(self.s.accept,dataclasses.replace(self.result(0,25),body=b'x'),(0,25))
 def test_bad_chunk(self):
  for x in (0,True,4*1024**2+1):self.bad(self.s.next_range,x)
 def test_content_corrupt(self):
  r=dataclasses.replace(self.result(0,len(self.raw)-1),body=self.raw[:-1]+bytes([self.raw[-1]^1]));self.bad(self.s.accept(r,(0,len(self.raw)-1)).verified)
 def test_etag_syntax(self):
  for t in (None,'W/"abc"','abc','"a"b"','"a\nb"'):self.assertFalse(strong_etag(t))
 def test_no_implicit_approval(self):self.bad(ApprovedRanges,self.cp,self.spec,((0,25),),False)
 def test_overlap_rejected(self):self.bad(ApprovedRanges,self.cp,self.spec,((0,25),(25,30)),True)
 def fetch(self,response,transport=None):
  t=transport or ApprovedRanges(self.cp,self.spec,((0,25),),True)
  with patch('range_resume.urllib.request.build_opener') as opener:
   opener.return_value.open.return_value=response;r=t.fetch((0,25));req=opener.return_value.open.call_args.args[0];self.assertEqual(req.get_header('Range'),'bytes=0-25');return r,t
 def test_fake_http_success_and_budget(self):
  r=Response(self.url,0,25,len(self.raw),self.raw[:26]);out,t=self.fetch(r);self.assertEqual(out.body,self.raw[:26]);self.assertEqual(t.body_bytes_read,26);self.bad(t.fetch,(0,25))
 def test_reject_before_read(self):
  for field,value in [('status',200),('url','https://example.org')]:
   r=Response(self.url,0,25,len(self.raw),self.raw[:26]);setattr(r,field,value)
   with self.assertRaises(InvalidRelease):self.fetch(r)
   self.assertEqual(r.reads,0)
 def test_bad_headers_before_read(self):
  for k,v in [('Content-Range','bytes 0-25/999'),('Content-Length','27'),('Content-Encoding','gzip'),('ETag','W/"fixed"')]:
   r=Response(self.url,0,25,len(self.raw),self.raw[:26]);r.headers[k]=v
   with self.assertRaises(InvalidRelease):self.fetch(r)
   self.assertEqual(r.reads,0)
 def test_short_body(self):
  with self.assertRaises(InvalidRelease):self.fetch(Response(self.url,0,25,len(self.raw),b'x'))
 def test_unapproved_range(self):self.bad(ApprovedRanges(self.cp,self.spec,((0,25),),True).fetch,(26,30))
 def test_etag_changed_before_read(self):
  r=Response(self.url,0,25,len(self.raw),self.raw[:26]);t=ApprovedRanges(self.cp,self.spec,((0,25),),True)
  with patch('range_resume.urllib.request.build_opener') as o:
   o.return_value.open.return_value=r;self.bad(t.fetch,(0,25),'"other"')
  self.assertEqual(r.reads,0)
if __name__=='__main__':unittest.main()
