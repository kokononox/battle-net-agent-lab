"""Explicit Windows-only synthetic I/O suite. Not collected by Linux discovery.
All fixture paths live in one new tempfile tree, never a game or user path.
"""
import dataclasses,hashlib,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from release_core import RunCheckpoint,InvalidRelease
from test_release_core import fixture_baseline,target
from test_stream_blte import fixture
from archive_transfer import ArchiveSource,ArchiveResponse,archive_url
from windows_store import WindowsStore
from windows_stream_stage import WindowsStreamStage
from stream_stage import SEGMENT
class WindowsStageTests(unittest.TestCase):
 def setUp(self):
  self.assertEqual(os.name,'nt');self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.path=self.root/'stage';self.raw,self.spec=fixture();self.cp=RunCheckpoint(fixture_baseline(),target());self.source=ArchiveSource('1'*32,'2'*64,100);self.stages=[];self.addCleanup(self.close_all);self.s=self.create(self.path)
 def close_all(self):
  for s in reversed(self.stages):s.close()
 def create(self,path,spec=None):
  s=WindowsStreamStage.create(path,self.cp,spec or self.spec,self.source);self.stages.append(s);return s
 def restore(self,**kw):
  s=WindowsStreamStage.restore(self.path,kw.get('cp',self.cp),self.spec,kw.get('source',self.source),kw.get('baseline',self.cp.baseline));self.stages.append(s);return s
 def response(self,a,b,**kw):return dataclasses.replace(ArchiveResponse(archive_url(self.cp,self.source),100+a,100+b,100+len(self.raw),'"fixture"',self.raw[a:b+1]),**kw)
 def append(self):
  a,b=self.s.next_range();return self.s.append(self.response(a,b),(a,b))
 def bad(self,fn,*args,**kw):
  with self.assertRaises((InvalidRelease,OSError)):fn(*args,**kw)
 def doc(self):return json.loads((self.path/'journal.json').read_bytes())
 def change(self,d):(self.path/'journal.json').write_text(json.dumps(d))
 def test_native_complete(self):
  self.append();r=self.s.verify();self.assertTrue(r['all_segment_sha256_reverified']);self.assertEqual(r['backend'],'native_windows_owned_scratch');self.assertFalse(r['native_casc_writer_qualified']);self.assertFalse(r['power_loss_qualified'])
 def test_restore_not_health(self):
  self.append();self.assertFalse(self.restore().summary()['payload_reverified'])
 def test_incomplete(self):self.bad(self.s.verify)
 def test_existing_directory_never_overwritten(self):self.bad(WindowsStreamStage.create,self.path,self.cp,self.spec,self.source)
 def test_changed_baseline(self):self.bad(self.restore,baseline=fixture_baseline('1.0.1.101'))
 def test_changed_target(self):self.bad(self.restore,cp=RunCheckpoint(self.cp.baseline,target('20.0.0.100001')))
 def test_changed_source(self):self.bad(self.restore,source=dataclasses.replace(self.source,offset=101))
 def test_changed_payload(self):
  self.append();p=self.path/self.doc()['segments'][0]['name'];p.write_bytes(b'x'*len(self.raw));self.bad(self.restore().verify)
 def test_missing_payload(self):
  self.append();(self.path/self.doc()['segments'][0]['name']).unlink();self.bad(self.restore().verify)
 def test_hardlink_payload(self):
  self.append();p=self.path/self.doc()['segments'][0]['name'];(self.root/'hard.bin').hardlink_to(p);self.bad(self.s.verify)
 def test_hardlink_journal(self):
  (self.root/'journal-alias.bin').hardlink_to(self.path/'journal.json');self.bad(self.restore)
 def test_full_content_check_after_segment_digest(self):
  self.append();d=self.doc();p=self.path/d['segments'][0]['name'];raw=p.read_bytes()[:-1]+b'x';p.write_bytes(raw);d['segments'][0]['sha256']=hashlib.sha256(raw).hexdigest();self.change(d);self.bad(self.s.verify)
 def test_read_handle_denies_write(self):
  self.append();row=self.doc()['segments'][0];f,n=self.s.store.open_read(row['name'],size=row['size'])
  with f:self.bad((self.path/row['name']).write_bytes,b'x')
 def test_read_handle_denies_delete(self):
  self.append();row=self.doc()['segments'][0];f,n=self.s.store.open_read(row['name'],size=row['size'])
  with f:self.bad((self.path/row['name']).unlink)
 def test_held_root_denies_rename(self):self.bad(self.path.rename,self.root/'moved')
 def test_held_ancestor_denies_rename(self):self.bad(self.root.rename,self.root.with_name(self.root.name+'-moved'))
 def test_exclusive_lock_not_broken(self):
  (self.path/'writer.lock').write_bytes(b'keep');self.bad(self.s.verify);self.assertEqual((self.path/'writer.lock').read_bytes(),b'keep')
 def test_concurrent_lock_handle(self):
  fd=self.s.store.create_handle('writer.lock')
  try:self.bad(self.s.append,self.response(0,10),(0,10))
  finally:os.close(fd);(self.path/'writer.lock').unlink()
 def test_stale_writer(self):
  other=self.restore();self.s.append(self.response(0,10),(0,10));self.bad(other.append,self.response(11,len(self.raw)-1),(11,len(self.raw)-1))
 def test_wrong_etag(self):
  self.s.append(self.response(0,10),(0,10));self.bad(self.s.append,self.response(11,len(self.raw)-1,etag='"changed"'),(11,len(self.raw)-1))
 def test_wrong_total(self):
  self.s.append(self.response(0,10),(0,10));self.bad(self.s.append,self.response(11,len(self.raw)-1,total=1000),(11,len(self.raw)-1))
 def test_wrong_url(self):self.bad(self.s.append,self.response(0,10,url='https://example.invalid'),(0,10))
 def test_short_body(self):self.bad(self.s.append,self.response(0,10,body=b'x'),(0,10))
 def test_duplicate_json(self):
  (self.path/'journal.json').write_text('{"a":1,"a":2}');self.bad(self.restore)
 def test_journal_traversal(self):
  self.append();d=self.doc();d['segments'][0]['name']='../outside';self.change(d);self.bad(self.restore)
 def test_boolean_commit(self):
  d=self.doc();d['committed_bytes']=False;self.change(d);self.bad(self.restore)
 def test_orphan_not_adopted(self):
  (self.path/('a'*32+'.seg')).write_bytes(b'orphan');self.assertEqual(self.restore().summary()['committed_bytes'],0)
 def crash(self,point):
  def fault(x):
   if x==point:raise RuntimeError('simulated interruption')
  with self.assertRaises(RuntimeError):self.s.append(self.response(0,len(self.raw)-1),(0,len(self.raw)-1),_fault=fault)
 def test_simulated_interrupt_after_segment(self):self.crash('segment_synced');self.assertEqual(self.restore().summary()['committed_bytes'],0)
 def test_simulated_interrupt_before_replace(self):self.crash('journal_synced');self.assertEqual(self.restore().summary()['committed_bytes'],0)
 def test_simulated_interrupt_after_replace(self):self.crash('journal_replaced');self.assertTrue(self.restore().verify()['full_ckey_verified'])
 def test_closed_guard_stops_operations(self):self.s.close();self.bad(self.s.next_range)
 def test_unc_refused_without_access(self):self.bad(WindowsStore,r'\\server.invalid\share\stage')
 def test_relative_path_refused(self):self.bad(WindowsStore,'relative-stage')
 def test_ads_child_refused(self):self.bad(self.s.store.write_new,'probe.bin:ads',b'x')
 def test_reserved_child_refused(self):self.bad(self.s.store.write_new,'con.bin',b'x')
 def junction(self,name,target):
  p=self.root/name;result=subprocess.run(['cmd','/d','/c','mklink','/J',str(p),str(target)],capture_output=True,timeout=15);self.assertEqual(result.returncode,0,'synthetic_junction_fixture_creation_failed');return p
 def test_reparse_root_refused(self):
  outside=self.root/'outside';outside.mkdir();link=self.junction('link',outside);self.bad(WindowsStore,link)
 def test_reparse_ancestor_refused_before_create(self):
  outside=self.root/'outside';outside.mkdir();link=self.junction('link',outside);self.bad(WindowsStore,link/'new-stage',create=True);self.assertFalse((outside/'new-stage').exists())
 def test_large_object_separate_process(self):
  raw,spec=fixture(b'abcdef'*(1024**2));p=self.root/'large';s=self.create(p,spec)
  for a in range(0,len(raw),SEGMENT):
   b=min(a+SEGMENT,len(raw))-1;s.append(ArchiveResponse(archive_url(self.cp,self.source),100+a,100+b,100+len(raw),'"large"',raw[a:b+1]),(a,b))
  args=self.root/'input.json';args.write_text(json.dumps({'cp':json.loads(self.cp.serialize()),'spec':spec.public(),'source':self.source.public(),'path':str(p)}));s.close()
  code='''import json,sys
from release_core import RunCheckpoint
from stream_blte import StreamObjectSpec
from windows_stream_stage import WindowsStreamStage
from archive_transfer import ArchiveSource
r=json.load(open(sys.argv[1]));cp=RunCheckpoint.restore(json.dumps(r['cp']).encode())
with WindowsStreamStage.restore(r['path'],cp,StreamObjectSpec(**r['spec']),ArchiveSource(**r['source']),cp.baseline)as s:print(json.dumps(s.verify()))
'''
  env={k:os.environ[k]for k in('SystemRoot','PATH','TEMP','TMP')if k in os.environ};result=subprocess.run([sys.executable,'-c',code,str(args)],cwd=Path(__file__).parent,env=env,capture_output=True,text=True,check=True,timeout=60);proof=json.loads(result.stdout);self.assertTrue(proof['full_ckey_verified']);self.assertEqual(proof['encoded_bytes'],len(raw));self.assertLess((p/'journal.json').stat().st_size,4096)
if __name__=='__main__':unittest.main()
