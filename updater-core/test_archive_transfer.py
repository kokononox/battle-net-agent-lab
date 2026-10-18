import dataclasses,hashlib,json,tempfile,unittest,urllib.error,io
from pathlib import Path
from unittest.mock import patch
from release_core import RunCheckpoint,InvalidRelease
from test_release_core import fixture_baseline,target
from test_local_candidates import fixture
from test_cdn_index import make
from cdn_index import parse_cdn_index
from cdn_routes import IndexRequest
from archive_transfer import ArchiveTransfer,ArchiveResponse,ArchiveSource,ApprovedArchiveRanges,archive_url,bind_source
class R:
 def __init__(self,url,x,y,total,body):
  self.url=url;self.status=206;self.headers={'Content-Range':f'bytes {x}-{y}/{total}','Content-Length':str(y-x+1),'ETag':'"fixed"'};self.body=body;self.reads=0
 def geturl(self):return self.url
 def read(self,n):self.reads+=1;r=self.body[:n];self.body=self.body[n:];return r
 def __enter__(self):return self
 def __exit__(self,*args):pass
class Tests(unittest.TestCase):
 def setUp(self):
  _,self.raw,self.spec,_,_=fixture();self.cp=RunCheckpoint(fixture_baseline(),target());b,k=make(rows=[(bytes.fromhex(self.spec.ekey),len(self.raw),1000)],off=4);self.index=parse_cdn_index(b,k);self.req=IndexRequest(k,self.cp.target.origins[0]+'/tpr/wow/data/'+k[:2]+'/'+k[2:4]+'/'+k+'.index',len(b));self.src=bind_source(self.cp,self.spec,self.index,self.req);self.s=ArchiveTransfer(self.cp,self.spec,self.src);self.url=archive_url(self.cp,self.src);self.total=999999
 def result(self,a,b):return ArchiveResponse(self.url,1000+a,1000+b,self.total,'"fixed"',self.raw[a:b+1])
 def partial(self):return self.s.accept(self.result(0,25),(0,25))
 def bad(self,fn,*args):
  with self.assertRaises(InvalidRelease):fn(*args)
 def test_real_file_roundtrip_synthetic_data(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)/'partial.json';p.write_bytes(self.partial().serialize());s=ArchiveTransfer.restore(p.read_bytes(),self.cp,self.spec,self.src,self.cp.baseline);span=(26,len(self.raw)-1);s=s.accept(self.result(*span),span);self.assertTrue(s.verified()['full_ckey_verified']);self.assertFalse(s.verified()['installation_ready'])
 def test_incomplete(self):self.bad(self.partial().verified)
 def test_changed_source(self):self.bad(ArchiveTransfer.restore,self.partial().serialize(),self.cp,self.spec,dataclasses.replace(self.src,offset=1001),self.cp.baseline)
 def test_changed_archive_key(self):self.bad(ArchiveTransfer.restore,self.partial().serialize(),self.cp,self.spec,dataclasses.replace(self.src,archive_key='f'*32),self.cp.baseline)
 def test_changed_index_digest(self):self.bad(ArchiveTransfer.restore,self.partial().serialize(),self.cp,self.spec,dataclasses.replace(self.src,index_sha256='f'*64),self.cp.baseline)
 def test_changed_baseline(self):self.bad(ArchiveTransfer.restore,self.partial().serialize(),self.cp,self.spec,self.src,fixture_baseline('1.0.1.101'))
 def test_changed_target(self):self.bad(ArchiveTransfer.restore,self.partial().serialize(),RunCheckpoint(self.cp.baseline,target('1.2.0.300')),self.spec,self.src,self.cp.baseline)
 def test_changed_object(self):self.bad(ArchiveTransfer.restore,self.partial().serialize(),self.cp,dataclasses.replace(self.spec,ckey='f'*32),self.src,self.cp.baseline)
 def test_partial_tamper(self):
  d=json.loads(self.partial().serialize());d['partial_sha256']='f'*64;self.bad(ArchiveTransfer.restore,json.dumps(d).encode(),self.cp,self.spec,self.src,self.cp.baseline)
 def test_duplicate_json(self):self.bad(ArchiveTransfer.restore,b'{"format":1,"format":2}',self.cp,self.spec,self.src,self.cp.baseline)
 def test_changed_etag(self):
  s=self.partial();self.bad(s.accept,dataclasses.replace(self.result(26,len(self.raw)-1),etag='"other"'),(26,len(self.raw)-1))
 def test_changed_total(self):
  s=self.partial();self.bad(s.accept,dataclasses.replace(self.result(26,len(self.raw)-1),total=self.total+1),(26,len(self.raw)-1))
 def test_wrong_physical_offset(self):self.bad(self.s.accept,dataclasses.replace(self.result(0,25),start=0,end=25),(0,25))
 def test_wrong_url(self):self.bad(self.s.accept,dataclasses.replace(self.result(0,25),url='https://other.example'),(0,25))
 def test_bool_response_geometry(self):self.bad(self.s.accept,dataclasses.replace(self.result(0,25),start=True),(0,25))
 def test_bad_body(self):
  r=self.result(0,len(self.raw)-1);r=dataclasses.replace(r,body=r.body[:-1]+bytes([r.body[-1]^1]));self.bad(self.s.accept(r,(0,len(self.raw)-1)).verified)
 def test_source_overflow(self):self.bad(ArchiveSource,self.src.archive_key,self.src.index_sha256,2**32)
 def test_binding_wrong_origin(self):self.bad(bind_source,self.cp,self.spec,self.index,dataclasses.replace(self.req,url='https://other.example/pinned.index'))
 def test_no_permission(self):self.bad(ApprovedArchiveRanges,self.cp,self.spec,self.src,((0,25),),False)
 def transport(self):return ApprovedArchiveRanges(self.cp,self.spec,self.src,((0,25),(26,len(self.raw)-1)),True)
 def response(self):return R(self.url,1000,1025,self.total,self.raw[:26])
 def fetch(self,r,t=None,etag=None,total=None):
  t=t or self.transport()
  with patch('archive_transfer.urllib.request.build_opener')as o:
   o.return_value.open.return_value=r;v=t.fetch((0,25),etag,total);req=o.return_value.open.call_args.args[0];self.assertEqual(req.get_header('Range'),'bytes=1000-1025')
  return v,t
 def test_http_success_budget(self):
  r=self.response();v,t=self.fetch(r);self.assertEqual(v.body,self.raw[:26]);self.assertEqual(t.body_bytes_read,26);self.bad(t.fetch,(0,25))
 def test_headers_rejected_without_body(self):
  for k,v in [('Content-Length','999'),('Content-Range','bytes 0-25/999999'),('Content-Encoding','gzip'),('ETag','W/"fixed"')]:
   r=self.response();r.headers[k]=v
   with self.assertRaises(InvalidRelease):self.fetch(r)
   self.assertEqual(r.reads,0)
 def test_ignored_range_200(self):
  r=self.response();r.status=200
  with self.assertRaises(InvalidRelease):self.fetch(r)
  self.assertEqual(r.reads,0)
 def test_changed_etag_before_body(self):
  r=self.response()
  with self.assertRaises(InvalidRelease):self.fetch(r,etag='"changed"')
  self.assertEqual(r.reads,0)
 def test_changed_total_before_body(self):
  r=self.response()
  with self.assertRaises(InvalidRelease):self.fetch(r,total=self.total+1)
  self.assertEqual(r.reads,0)
 def test_403_closed_not_read(self):
  t=self.transport();body=io.BytesIO(b'not read');e=urllib.error.HTTPError(self.url,403,'Forbidden',{},body)
  with patch('archive_transfer.urllib.request.build_opener')as o:
   o.return_value.open.side_effect=e
   with self.assertRaises(urllib.error.HTTPError):t.fetch((0,25))
  self.assertTrue(body.closed);self.assertEqual(t.body_bytes_read,0);self.assertEqual(t.observations[0]['status'],403)
 def test_short_read_counted(self):
  r=self.response();r.body=b'x';t=self.transport()
  with self.assertRaises(InvalidRelease):self.fetch(r,t)
  self.assertEqual(t.body_bytes_read,1)
 def test_unapproved_range(self):self.bad(self.transport().fetch,(1,25))
if __name__=='__main__':unittest.main()
