import dataclasses,hashlib,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from release_core import RunCheckpoint,InvalidRelease
from test_release_core import fixture_baseline,target
from test_stream_blte import fixture
from stream_stage import StreamStage,SEGMENT
from archive_transfer import ArchiveSource,ArchiveResponse,archive_url
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.path=Path(self.tmp.name)/'stage';self.raw,self.spec=fixture();self.cp=RunCheckpoint(fixture_baseline(),target());self.source=ArchiveSource('1'*32,'2'*64,100);self.s=StreamStage.create(self.path,self.cp,self.spec,self.source)
 def restore(self,cp=None,baseline=None,source=None):return StreamStage.restore(self.path,cp or self.cp,self.spec,source or self.source,baseline or self.cp.baseline)
 def response(self,a,b,**kw):return dataclasses.replace(ArchiveResponse(archive_url(self.cp,self.source),100+a,100+b,100+len(self.raw),'"fixed"',self.raw[a:b+1]),**kw)
 def append(self,s=None):
  s=s or self.s;a,b=s.next_range();return s.append(self.response(a,b),(a,b))
 def bad(self,fn,*args,**kw):
  with self.assertRaises((InvalidRelease,OSError)):fn(*args,**kw)
 def doc(self):return json.loads((self.path/'journal.json').read_bytes())
 def change(self,d):(self.path/'journal.json').write_text(json.dumps(d))
 def test_complete_stream_verify(self):
  self.append();p=self.s.verify();self.assertTrue(p['all_segment_sha256_reverified']);self.assertLessEqual(p['maximum_source_block_bytes'],65536);self.assertFalse(p['apply_authorized'])
 def test_incomplete_no_proof(self):self.bad(self.s.verify)
 def test_restore_not_payload_proof(self):
  self.append();self.assertFalse(self.restore().summary()['payload_reverified'])
 def test_corrupt_payload_restore_does_not_claim_health(self):
  self.append();p=self.path/self.doc()['segments'][0]['name'];p.write_bytes(b'x'*len(self.raw));s=self.restore();self.assertFalse(s.summary()['payload_reverified']);self.bad(s.verify)
 def test_missing_payload_rejected_on_verify(self):
  self.append();(self.path/self.doc()['segments'][0]['name']).unlink();self.bad(self.restore().verify)
 def test_symlink_payload(self):
  self.append();p=self.path/self.doc()['segments'][0]['name'];raw=p.read_bytes();p.unlink();q=Path(self.tmp.name)/'external';q.write_bytes(raw);p.symlink_to(q);self.bad(self.s.verify)
 def test_hardlink_payload(self):
  self.append();p=self.path/self.doc()['segments'][0]['name'];(Path(self.tmp.name)/'external').hardlink_to(p);self.bad(self.s.verify)
 def test_changed_target(self):self.bad(self.restore,cp=RunCheckpoint(self.cp.baseline,target('20.0.0.100001')))
 def test_changed_baseline(self):self.bad(self.restore,baseline=fixture_baseline('1.0.1.101'))
 def test_changed_source(self):self.bad(self.restore,source=dataclasses.replace(self.source,offset=101))
 def test_wrong_etag(self):
  self.s.append(self.response(0,10),(0,10));self.bad(self.s.append,self.response(11,len(self.raw)-1,etag='"other"'),(11,len(self.raw)-1))
 def test_changed_total(self):
  self.s.append(self.response(0,10),(0,10));self.bad(self.s.append,self.response(11,len(self.raw)-1,total=1000),(11,len(self.raw)-1))
 def test_wrong_url(self):self.bad(self.s.append,self.response(0,len(self.raw)-1,url='https://example.org'),(0,len(self.raw)-1))
 def test_boolean_geometry(self):self.bad(self.s.append,self.response(0,10,start=True),(0,10))
 def test_lock_not_broken(self):
  (self.path/'writer.lock').write_text('keep');self.bad(self.s.verify);self.assertTrue((self.path/'writer.lock').exists())
 def test_stale_writer(self):
  other=self.restore();self.s.append(self.response(0,10),(0,10));self.bad(other.append,self.response(11,len(self.raw)-1),(11,len(self.raw)-1))
 def test_duplicate_json(self):
  (self.path/'journal.json').write_text('{"a":1,"a":2}');self.bad(self.restore)
 def test_traversal(self):
  self.append();d=self.doc();d['segments'][0]['name']='../x';self.change(d);self.bad(self.restore)
 def test_gap_in_journal(self):
  self.append();d=self.doc();d['segments'][0]['start']=1;self.change(d);self.bad(self.restore)
 def test_payload_digest_and_full_ckey_both_required(self):
  self.append();d=self.doc();p=self.path/d['segments'][0]['name'];raw=p.read_bytes()[:-1]+b'x';p.write_bytes(raw);d['segments'][0]['sha256']=hashlib.sha256(raw).hexdigest();self.change(d);self.bad(self.s.verify)
 def test_orphan_never_adopted(self):
  (self.path/('a'*32+'.seg')).write_bytes(b'orphan');self.assertEqual(self.restore().summary()['committed_bytes'],0)
 def crash(self,point):
  def fault(x):
   if x==point:raise RuntimeError('simulated')
  with self.assertRaises(RuntimeError):self.s.append(self.response(0,len(self.raw)-1),(0,len(self.raw)-1),_fault=fault)
 def test_crash_before_journal(self):self.crash('segment_synced');self.assertEqual(self.restore().summary()['committed_bytes'],0)
 def test_crash_before_replace(self):self.crash('journal_synced');self.assertEqual(self.restore().summary()['committed_bytes'],0)
 def test_crash_after_replace(self):self.crash('journal_replaced');self.assertTrue(self.restore().verify()['full_ckey_verified'])
 def test_large_n_across_segments_and_process(self):
  raw,spec=fixture(b'abcdef'*(1024**2));path=Path(self.tmp.name)/'large';s=StreamStage.create(path,self.cp,spec,self.source)
  for a in range(0,len(raw),SEGMENT):
   b=min(a+SEGMENT,len(raw))-1;r=ArchiveResponse(archive_url(self.cp,self.source),100+a,100+b,100+len(raw),'"large"',raw[a:b+1]);s.append(r,(a,b))
  # A fresh Python process restores metadata; no raw payload encoded in JSON.
  args=Path(self.tmp.name)/'args.json';args.write_text(json.dumps({'cp':json.loads(self.cp.serialize()),'spec':spec.public(),'source':self.source.public(),'path':str(path)}))
  code='''import json,sys
from release_core import RunCheckpoint
from stream_blte import StreamObjectSpec
from stream_stage import StreamStage
from archive_transfer import ArchiveSource
r=json.load(open(sys.argv[1]));cp=RunCheckpoint.restore(json.dumps(r['cp']).encode());s=StreamStage.restore(r['path'],cp,StreamObjectSpec(**r['spec']),ArchiveSource(**r['source']),cp.baseline);print(json.dumps(s.verify()))
'''
  p=subprocess.run([sys.executable,'-c',code,str(args)],cwd=Path(__file__).parent,check=True,capture_output=True,text=True);proof=json.loads(p.stdout);self.assertTrue(proof['full_ckey_verified']);self.assertEqual(proof['encoded_bytes'],len(raw));self.assertLess((path/'journal.json').stat().st_size,4096)
if __name__=='__main__':unittest.main()
