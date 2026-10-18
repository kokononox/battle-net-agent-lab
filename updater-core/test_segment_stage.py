import dataclasses,hashlib,json,tempfile,unittest
from pathlib import Path
from release_core import RunCheckpoint,InvalidRelease
from test_release_core import fixture_baseline,target
from test_local_candidates import fixture
from archive_transfer import ArchiveSource,ArchiveResponse,archive_url
from segment_stage import SegmentStage
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.path=Path(self.tmp.name)/'stage';_,self.raw,self.spec,_,_=fixture();self.cp=RunCheckpoint(fixture_baseline(),target());self.src=ArchiveSource('1'*32,'2'*64,1000);self.s=SegmentStage.create(self.path,self.cp,self.spec,self.src)
 def restore(self,**kw):return SegmentStage.restore(self.path,kw.get('cp',self.cp),self.spec,kw.get('source',self.src),kw.get('baseline',self.cp.baseline))
 def r(self,a,b):return ArchiveResponse(archive_url(self.cp,self.src),1000+a,1000+b,999999,'"fixed"',self.raw[a:b+1])
 def first(self):return self.s.append(self.r(0,25),(0,25))
 def doc(self):return json.loads((self.path/'journal.json').read_bytes())
 def write(self,d):(self.path/'journal.json').write_text(json.dumps(d))
 def bad(self,fn,*args,**kw):
  with self.assertRaises((InvalidRelease,OSError)):fn(*args,**kw)
 def test_separate_restore_full_identity(self):
  self.first();s=self.restore();s.append(self.r(26,len(self.raw)-1),(26,len(self.raw)-1));self.assertTrue(s.verified()['full_ckey_verified']);self.assertFalse(s.verified()['installation_ready'])
 def test_journal_no_payload(self):
  self.first();d=self.doc();self.assertNotIn('partial_base64',d);self.assertEqual(d['committed_bytes'],26);self.assertEqual(len(d['segments']),1)
 def test_incomplete(self):self.bad(self.s.verified)
 def test_existing_directory_not_reused(self):self.bad(SegmentStage.create,self.path,self.cp,self.spec,self.src)
 def test_changed_baseline(self):self.bad(self.restore,baseline=fixture_baseline('1.0.1.101'))
 def test_changed_target(self):self.bad(self.restore,cp=RunCheckpoint(self.cp.baseline,target('1.2.0.300')))
 def test_changed_source(self):self.bad(self.restore,source=dataclasses.replace(self.src,offset=1001))
 def test_changed_segment(self):
  self.first();p=self.path/self.doc()['segments'][0]['name'];p.write_bytes(b'x'*26);self.bad(self.restore)
 def test_missing_segment(self):
  self.first();(self.path/self.doc()['segments'][0]['name']).unlink();self.bad(self.restore)
 def test_symlink_segment(self):
  self.first();p=self.path/self.doc()['segments'][0]['name'];data=p.read_bytes();p.unlink();q=Path(self.tmp.name)/'external';q.write_bytes(data);p.symlink_to(q);self.bad(self.restore)
 def test_hardlink_segment(self):
  self.first();p=self.path/self.doc()['segments'][0]['name'];(Path(self.tmp.name)/'hard').hardlink_to(p);self.bad(self.restore)
 def test_path_traversal(self):
  self.first();d=self.doc();d['segments'][0]['name']='../external';self.write(d);self.bad(self.restore)
 def test_duplicate_json(self):
  (self.path/'journal.json').write_bytes(b'{"format":1,"format":2}');self.bad(self.restore)
 def test_boolean_commit(self):
  d=self.doc();d['committed_bytes']=False;self.write(d);self.bad(self.restore)
 def test_gap(self):self.bad(self.s.append,self.r(1,25),(1,25))
 def test_repeated_span(self):self.first();self.bad(self.s.append,self.r(0,25),(0,25))
 def test_entity_change(self):
  self.first();self.bad(self.s.append,dataclasses.replace(self.r(26,len(self.raw)-1),etag='"changed"'),(26,len(self.raw)-1))
 def test_total_change(self):
  self.first();self.bad(self.s.append,dataclasses.replace(self.r(26,len(self.raw)-1),total=999998),(26,len(self.raw)-1))
 def test_wrong_url(self):self.bad(self.s.append,dataclasses.replace(self.r(0,25),url='https://other.example'),(0,25))
 def test_short_body(self):self.bad(self.s.append,dataclasses.replace(self.r(0,25),body=b'x'),(0,25))
 def test_lock_never_broken(self):
  (self.path/'writer.lock').write_text('abandoned');self.bad(self.s.append,self.r(0,25),(0,25));self.assertTrue((self.path/'writer.lock').exists())
 def test_stale_writer(self):
  s=self.restore();self.first();self.bad(s.append,self.r(26,len(self.raw)-1),(26,len(self.raw)-1));self.assertEqual(self.restore().summary()['committed_bytes'],26)
 def crash_at(self,point):
  def fault(x):
   if x==point:raise RuntimeError('simulated interruption')
  with self.assertRaises(RuntimeError):self.s.append(self.r(0,25),(0,25),_fault=fault)
 def test_crash_after_segment(self):
  self.crash_at('segment_synced');s=self.restore();self.assertEqual(s.summary()['committed_bytes'],0);s.append(self.r(0,25),(0,25));self.assertEqual(len(list(self.path.glob('*.seg'))),2)
 def test_crash_before_replace(self):self.crash_at('journal_synced');self.assertEqual(self.restore().summary()['committed_bytes'],0)
 def test_crash_after_replace(self):self.crash_at('journal_replaced');self.assertEqual(self.restore().summary()['committed_bytes'],26)
 def test_orphan_not_adopted(self):
  (self.path/('a'*32+'.seg')).write_bytes(b'unknown');self.assertEqual(self.restore().summary()['committed_bytes'],0)
 def test_bad_payload_with_valid_segment_digest(self):
  raw=self.raw[:-1]+bytes([self.raw[-1]^1]);r=dataclasses.replace(self.r(0,len(raw)-1),body=raw);self.s.append(r,(0,len(raw)-1));self.bad(self.s.verified)
if __name__=='__main__':unittest.main()
