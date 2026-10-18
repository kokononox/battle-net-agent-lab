import dataclasses,hashlib,http.client,io,json,os,tempfile,unittest
from email.message import Message
from pathlib import Path
from release_core import RunCheckpoint,InvalidRelease
from test_release_core import fixture_baseline,target
from test_stream_blte import fixture
from stream_stage import StreamStage,SEGMENT
from windows_stream_stage import WindowsStreamStage
from archive_transfer import ArchiveSource,ArchiveResponse,archive_url
from transfer_controller import TransferGrant,TransferController,RangeRequest
from stream_http import ApprovedStreamHTTP

class ControllerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.stages=[];self.addCleanup(self.close_all);self.cp=RunCheckpoint(fixture_baseline(),target());self.payloads={};self.calls=[]
  for i in range(2):self.add_stage(i)
  self.stages=tuple(self.stages);self.grant=self.approve();self.controller=TransferController.create(self.stages,self.grant,self.fetch)
 def add_stage(self,i,large=False,shared=False):
  raw,spec=fixture((bytes([97+i])*(SEGMENT+111))if large else bytes([97+i])*80);src=ArchiveSource(('1'if shared else format(i+1,'x'))*32,'2'*64,100+i*10000 if shared else 100);cls=WindowsStreamStage if os.name=='nt'else StreamStage;s=cls.create(self.root/str(i),self.cp,spec,src);self.stages.append(s);self.payloads[s.identity]=raw;return s
 def close_all(self):
  for s in reversed(self.stages):s.close()
 def approve(self,**kw):return TransferGrant.approve(tuple(self.stages),max_requests=kw.get('requests',8),max_body_bytes=kw.get('bytes',4*SEGMENT),approved=kw.get('approved',True))
 def fetch(self,req):
  self.calls.append(req);raw=self.payloads[req.stage_identity];a,b=req.relative;return ArchiveResponse(req.url,req.start,req.end,999999999,'"entity"',raw[a:b+1])
 def bad(self,fn,*args,**kw):
  with self.assertRaises((InvalidRelease,OSError)):fn(*args,**kw)
 def step(self,**kw):return self.controller.step(self.cp.baseline,**kw)
 def restore(self):return TransferController.restore(self.stages,TransferGrant.restore(self.grant.serialize(),self.stages,approved=True),self.fetch)
 def test_multiobject_fresh_completion(self):
  self.step();self.step();r=self.controller.finish();self.assertTrue(r['all_objects_freshly_verified']);self.assertEqual(len(r['proofs']),2);self.assertFalse(r['apply_authorized']);self.assertIsNone(r['required_network_download_bytes']);self.assertEqual(len(self.calls),2)
 def test_resume_between_objects(self):self.step();self.controller=self.restore();self.step();self.assertTrue(self.controller.finish()['all_objects_freshly_verified']);self.assertEqual(len(self.calls),2)
 def test_finished_step_does_not_refetch(self):
  self.step();self.step();self.step();self.assertEqual(len(self.calls),2)
 def test_incomplete_not_verified(self):self.bad(self.controller.finish)
 def test_cancel_before_request_no_reservation(self):
  r=self.step(cancelled=lambda:True);self.assertEqual(r['reserved_requests'],0);self.assertFalse(self.calls)
 def test_cancel_after_request_pending_no_retry(self):
  values=iter([False,True]);self.bad(self.step,cancelled=lambda:next(values));self.bad(self.restore);self.assertEqual(len(self.calls),1)
 def test_changed_baseline_before_network(self):self.bad(self.controller.step,fixture_baseline('1.0.1.101'));self.assertFalse(self.calls)
 def test_changed_source_before_network(self):
  self.stages[0].source=dataclasses.replace(self.stages[0].source,offset=101);self.bad(self.step);self.assertFalse(self.calls)
 def test_new_target_before_network(self):
  self.stages[0].cp=RunCheckpoint(self.cp.baseline,target('20.0.0.100001'));self.bad(self.step);self.assertFalse(self.calls)
 def test_approval_required(self):self.bad(self.approve,approved=False)
 def test_restore_requires_approval(self):self.bad(TransferGrant.restore,self.grant.serialize(),self.stages,approved=False)
 def test_boolean_budget_refused(self):self.bad(self.approve,requests=True)
 def test_too_small_request_budget(self):self.bad(self.approve,requests=1)
 def test_too_small_byte_budget(self):self.bad(self.approve,bytes=1)
 def test_unknown_stage_type_refused(self):self.bad(TransferGrant.approve,(object(),),max_requests=1,max_body_bytes=1,approved=True)
 def test_duplicate_stage_refused(self):self.bad(TransferGrant.approve,(self.stages[0],self.stages[0]),max_requests=3,max_body_bytes=1000,approved=True)
 def test_existing_ledger_not_overwritten(self):
  before=(self.stages[0].path/'transfer.json').read_bytes();self.bad(TransferController.create,self.stages,self.grant,self.fetch);self.assertEqual((self.stages[0].path/'transfer.json').read_bytes(),before)
 def test_reserved_crash_no_automatic_retry(self):
  def fault(at):raise RuntimeError('synthetic interruption')
  with self.assertRaises(RuntimeError):self.step(_fault=fault)
  self.assertFalse(self.calls);self.bad(self.restore)
 def test_after_stage_commit_crash_not_adopted(self):
  def fault(at):
   if at=='stage_committed':raise RuntimeError('synthetic interruption')
  with self.assertRaises(RuntimeError):self.step(_fault=fault)
  self.assertEqual(self.stages[0].doc['committed_bytes'],self.stages[0].spec.encoded_size);self.bad(self.restore)
 def test_fetch_failure_not_retried(self):
  def fail(req):raise OSError('synthetic transport stop')
  self.controller.fetch=fail;self.bad(self.step);self.bad(self.step);self.bad(self.restore)
 def test_corrupt_completed_payload_stops(self):
  def corrupt(req):return dataclasses.replace(self.fetch(req),body=b'x'*len(self.fetch(req).body))
  self.controller.fetch=corrupt;self.bad(self.step);self.bad(self.restore)
 def test_ledger_duplicate_keys_refused(self):
  p=self.stages[0].path/'transfer.json';raw=p.read_bytes();p.write_bytes(raw[:-1]+b',"cursor":0}');self.bad(self.restore)
 def test_ledger_budget_tamper_refused(self):
  p=self.stages[0].path/'transfer.json';d=json.loads(p.read_bytes());d['reserved_requests']=True;p.write_text(json.dumps(d));self.bad(self.restore)
 def test_external_stage_append_refused(self):
  s=self.stages[0];req=RangeRequest(s.identity,(0,s.spec.encoded_size-1),archive_url(s.cp,s.source),100,100+s.spec.encoded_size-1,None,None);s.append(self.fetch(req),req.relative);self.bad(self.step)
 def test_mutated_grant_refused(self):self.grant.max_body_bytes+=1;self.bad(self.step)
 def test_resume_prefix_corruption_refused(self):
  self.step();s=self.stages[0];(s.path/s.doc['segments'][0]['name']).write_bytes(b'x'*s.spec.encoded_size);self.bad(self.restore)
 def test_grant_duplicate_json_refused(self):
  raw=self.grant.serialize();self.bad(TransferGrant.restore,raw[:-1]+b',"max_requests":8}',self.stages,approved=True)
 def test_large_object_multiple_ranges(self):
  self.close_all();self.stages=[];s=self.add_stage(9,True);self.stages=tuple(self.stages);self.grant=self.approve();self.controller=TransferController.create(self.stages,self.grant,self.fetch);self.step();self.controller=self.restore();self.step();r=self.controller.finish();self.assertGreater(s.spec.encoded_size,SEGMENT);self.assertEqual(r['completed_ranges'],2);self.assertEqual(self.calls[-1].expected_etag,'"entity"')

 def shared_stages(self):
  self.close_all();self.stages=[];self.add_stage(8,shared=True);self.add_stage(9,shared=True);self.stages=tuple(self.stages);self.grant=self.approve();self.controller=TransferController.create(self.stages,self.grant,self.fetch)
 def test_shared_archive_entity_pinned_across_objects(self):
  self.shared_stages();self.step();self.step();self.assertEqual(self.calls[-1].expected_etag,'"entity"');self.assertEqual(self.calls[-1].expected_total,999999999);self.assertTrue(self.controller.finish()['all_objects_freshly_verified'])
 def test_shared_archive_changed_etag_stops(self):
  self.shared_stages();self.step();self.controller.fetch=lambda req:dataclasses.replace(self.fetch(req),etag='"changed"');self.bad(self.step);self.bad(self.restore)
 def test_shared_archive_changed_total_stops(self):
  self.shared_stages();self.step();self.controller.fetch=lambda req:dataclasses.replace(self.fetch(req),total=999999998);self.bad(self.step);self.bad(self.restore)
 def test_resume_in_fresh_process(self):
  import subprocess,sys
  self.step();self.close_all();capsule=self.root/'resume.json';capsule.write_text(json.dumps({'grant':self.grant.serialize().decode(),'cp':self.cp.serialize().decode(),'paths':[str(s.path)for s in self.stages],'specs':[s.spec.public()for s in self.stages],'sources':[s.source.public()for s in self.stages]}))
  code="""import json,sys,os
from pathlib import Path
from release_core import RunCheckpoint
from stream_blte import StreamObjectSpec
from stream_stage import StreamStage
from windows_stream_stage import WindowsStreamStage
from archive_transfer import ArchiveSource,ArchiveResponse
from transfer_controller import TransferGrant,TransferController
from test_stream_blte import fixture
x=json.loads(Path(sys.argv[1]).read_bytes());cp=RunCheckpoint.restore(x['cp'].encode());cls=WindowsStreamStage if os.name=='nt'else StreamStage;stages=tuple(cls.restore(p,cp,StreamObjectSpec(**s),ArchiveSource(**a),cp.baseline)for p,s,a in zip(x['paths'],x['specs'],x['sources']))
def fetch(req):
 raw,_=fixture(b'b'*80);a,b=req.relative;return ArchiveResponse(req.url,req.start,req.end,999999999,'"entity"',raw[a:b+1])
try:
 g=TransferGrant.restore(x['grant'].encode(),stages,approved=True);c=TransferController.restore(stages,g,fetch);c.step(cp.baseline);r=c.finish();assert r['all_objects_freshly_verified'];print('fresh_process_two_objects_verified_no_game')
finally:
 for s in stages:s.close()
"""
  result=subprocess.run([sys.executable,'-c',code,str(capsule)],cwd=Path(__file__).parent,env={k:v for k,v in os.environ.items()if k in('SystemRoot','PATH','TEMP','TMP')},capture_output=True,timeout=30);self.assertEqual(result.returncode,0,'synthetic_fresh_process_resume_failed');self.assertEqual(result.stdout.strip(),b'fresh_process_two_objects_verified_no_game')

class Response:
 def __init__(self,req,body):
  self.status=206;self.url=req.url;self.headers=Message();self.headers['Content-Length']=str(req.end-req.start+1);self.headers['Content-Range']=f'bytes {req.start}-{req.end}/{100+len(body)}';self.headers['ETag']='"entity"';self.body=body;self.reads=0;self.closed=False
 def geturl(self):return self.url
 def read(self,n):self.reads+=1;raw=self.body[:n];self.body=self.body[n:];return raw
 def __enter__(self):return self
 def __exit__(self,*args):self.closed=True

class HTTPTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);raw,spec=fixture(b'abcde');cp=RunCheckpoint(fixture_baseline(),target());src=ArchiveSource('1'*32,'2'*64,100);cls=WindowsStreamStage if os.name=='nt'else StreamStage;self.stage=cls.create(Path(self.tmp.name)/'stage',cp,spec,src);self.addCleanup(self.stage.close);self.stages=(self.stage,);self.grant=TransferGrant.approve(self.stages,max_requests=1,max_body_bytes=len(raw),approved=True);self.req=RangeRequest(self.stage.identity,(0,len(raw)-1),archive_url(cp,src),100,100+len(raw)-1,None,None);self.response=Response(self.req,raw);self.raw=raw;self.open_calls=[];self.t=ApprovedStreamHTTP(self.stages,self.grant,approved_network=True,opener=self.open)
 def open(self,req,**kw):self.open_calls.append(req);return self.response
 def bad(self,fn,*a,**kw):
  with self.assertRaises((InvalidRelease,OSError,http.client.IncompleteRead)):fn(*a,**kw)
 def reject_header(self,k,v):
  if k in self.response.headers:del self.response.headers[k]
  self.response.headers[k]=v;self.bad(self.t.fetch,self.req);self.assertEqual(self.response.reads,0)
 def test_exact_fetch(self):r=self.t.fetch(self.req);self.assertEqual(r.body,self.raw);self.assertTrue(self.response.closed);self.assertEqual(self.open_calls[0].get_header('Range'),f'bytes=100-{self.req.end}')
 def test_controller_http_integration(self):
  c=TransferController.create(self.stages,self.grant,self.t.fetch);c.step(self.stage.cp.baseline);self.assertTrue(c.finish()['all_objects_freshly_verified'])
 def test_no_network_approval(self):self.bad(ApprovedStreamHTTP,self.stages,self.grant,approved_network=False,opener=self.open);self.assertFalse(self.open_calls)
 def test_ungranted_request(self):self.bad(self.t.fetch,dataclasses.replace(self.req,url='https://invalid.example'));self.assertFalse(self.open_calls)
 def test_repeated_range_refused(self):self.t.fetch(self.req);self.bad(self.t.fetch,self.req);self.assertEqual(len(self.open_calls),1)
 def test_range_ignored_no_body(self):self.response.status=200;self.bad(self.t.fetch,self.req);self.assertEqual(self.response.reads,0)
 def test_redirect_no_body(self):self.response.url+='x';self.bad(self.t.fetch,self.req);self.assertEqual(self.response.reads,0)
 def test_wrong_length(self):self.reject_header('Content-Length','1')
 def test_compressed_body(self):self.reject_header('Content-Encoding','gzip')
 def test_weak_etag(self):self.reject_header('ETag','W/"weak"')
 def test_changed_etag(self):self.bad(self.t.fetch,dataclasses.replace(self.req,expected_etag='"different"'));self.assertEqual(self.response.reads,0)
 def test_changed_total(self):self.bad(self.t.fetch,dataclasses.replace(self.req,expected_total=999999));self.assertEqual(self.response.reads,0)
 def test_wrong_range(self):self.reject_header('Content-Range','bytes 0-9/999')
 def test_duplicate_header(self):self.response.headers['ETag']='"other"';self.bad(self.t.fetch,self.req);self.assertEqual(self.response.reads,0)
 def test_short_body_no_retry(self):self.response.body=b'';self.bad(self.t.fetch,self.req);self.bad(self.t.fetch,self.req);self.assertEqual(len(self.open_calls),1)
 def test_incomplete_read_charged(self):
  def read(n):raise http.client.IncompleteRead(b'abc',n-3)
  self.response.read=read;self.bad(self.t.fetch,self.req);self.assertEqual(self.t.body_bytes_read,3)
 def test_if_range_sent(self):self.t.fetch(dataclasses.replace(self.req,expected_etag='"entity"'));self.assertEqual(self.open_calls[0].get_header('If-range'),'"entity"')
 def test_chunked_framing_refused(self):self.reject_header('Transfer-Encoding','chunked')
 def test_duplicate_content_length_refused(self):self.response.headers['Content-Length']=str(len(self.raw));self.bad(self.t.fetch,self.req);self.assertEqual(self.response.reads,0)
 def test_missing_etag_refused(self):del self.response.headers['ETag'];self.bad(self.t.fetch,self.req);self.assertEqual(self.response.reads,0)
 def test_no_eof_probe(self):self.t.fetch(self.req);self.assertEqual(self.response.reads,1)

