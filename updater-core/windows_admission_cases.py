"""Native candidate admission against tiny synthetic SQLite catalogues only."""
import contextlib,io,json,os,sqlite3,tempfile,unittest
from pathlib import Path
from test_build_catalogue import fixture
from test_release_core import fixture_baseline
from test_metadata_objects import fixture as blte_fixture
import test_staged_reuse as fixture_helpers
from build_catalogue import build
from candidate_plan import build_candidate
from release_core import RunCheckpoint,TargetSnapshot,InvalidRelease
from stream_blte import StreamObjectSpec
from windows_stream_stage import WindowsStreamStage
from stream_staged_reuse import reverify_stream_candidate
from archive_transfer import ArchiveSource,ArchiveResponse,archive_url
from reuse_candidates import sha_file
def admission_fixture():
 raw,s=blte_fixture(b'abcde',b'N');return raw,StreamObjectSpec(s.ckey,s.ekey,s.decoded_size,s.encoded_size)
class WindowsAdmissionTests(unittest.TestCase):
 def setUp(self):
  self.assertEqual(os.name,'nt');self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.stages=[];self.addCleanup(self.close_all);self.b,self.o=fixture(self.root)
  with contextlib.redirect_stdout(io.StringIO()):build(self.b,self.o)
  self.plan=self.root/'plan';p=build_candidate(self.b,self.o,self.plan,'Windows');self.cp=RunCheckpoint(fixture_baseline(),TargetSnapshot.restore(p['target']));self.raw,self.spec=admission_fixture();self.src=ArchiveSource('1'*32,'2'*64,100)
  self.stage=WindowsStreamStage.create(self.root/'stage',self.cp,self.spec,self.src);self.stages.append(self.stage);self.stage.append(ArchiveResponse(archive_url(self.cp,self.src),100,100+len(self.raw)-1,1000,'"cache"',self.raw),(0,len(self.raw)-1));fixture_helpers.Tests.update_db(self)
 def close_all(self):
  for stage in reversed(self.stages):stage.close()
 def review(self):return reverify_stream_candidate(self.stage,self.plan,self.o)
 def bad(self):
  with self.assertRaises((InvalidRelease,OSError)):self.review()
 def test_freshly_verified_native_input(self):
  r=self.review();self.assertTrue(r['eligible_as_verified_staging_input']);self.assertTrue(r['proof']['all_segment_sha256_reverified']);self.assertEqual(r['proof']['backend'],'native_windows_owned_scratch');self.assertFalse(r['apply_authorized']);self.assertFalse(r['installed_content_reuse_authorized']);self.assertIsNone(r['required_network_download_bytes'])
 def test_restored_metadata_still_reverified(self):
  self.stage.close();self.stage=WindowsStreamStage.restore(self.root/'stage',self.cp,self.spec,self.src,self.cp.baseline);self.stages.append(self.stage);self.assertFalse(self.stage.summary()['payload_reverified']);self.assertTrue(self.review()['proof']['all_segment_sha256_reverified'])
 def test_corrupt_payload_not_admitted(self):
  p=self.stage.path/self.stage.doc['segments'][0]['name'];p.write_bytes(b'x'*len(self.raw));self.bad()
 def test_changed_target_not_admitted(self):
  p=self.plan/'CANDIDATE-PLAN-to-share.json';d=json.loads(p.read_bytes());d['target']['version']='20.0.0.100001';d['target']['build_id']=100001;p.write_text(json.dumps(d));self.bad()
 def test_changed_catalogue_not_admitted(self):
  p=self.o/'TARGET-CATALOGUE.sqlite';p.write_bytes(p.read_bytes()+b'x');self.bad()
 def test_unselected_object_not_admitted(self):
  p=self.plan/'CANDIDATE-PLAN.sqlite';d=sqlite3.connect(p);d.execute('DELETE FROM selected_download');d.commit();d.close();p2=self.plan/'CANDIDATE-PLAN-to-share.json';r=json.loads(p2.read_bytes());r['database']['sha256']=sha_file(p);p2.write_text(json.dumps(r));self.bad()
 def test_receipt_cannot_grant_apply(self):
  p=self.plan/'CANDIDATE-PLAN-to-share.json';r=json.loads(p.read_bytes());r['apply_authorized']=True;p.write_text(json.dumps(r));self.assertFalse(self.review()['apply_authorized'])
 def test_closed_guard_not_admitted(self):self.stage.close();self.bad()
 def test_unknown_subclass_refused_before_io(self):
  class Unknown(WindowsStreamStage):pass
  with self.assertRaisesRegex(InvalidRelease,'stream_owned_stage_required'):reverify_stream_candidate(Unknown(),'not-read','not-read')
 def test_native_full_ckey_mismatch_not_admitted(self):
  p=self.o/'TARGET-CATALOGUE.sqlite';d=sqlite3.connect(p);d.execute('UPDATE content_links SET ckey=?',(bytes.fromhex('f'*32),));d.commit();d.close();p2=self.o/'CATALOGUE-VERIFIED-to-share.json';r=json.loads(p2.read_bytes());r['database']['sha256']=sha_file(p);p2.write_text(json.dumps(r));p3=self.plan/'CANDIDATE-PLAN-to-share.json';r3=json.loads(p3.read_bytes());r3['source_catalogue_sha256']=r['database']['sha256'];p3.write_text(json.dumps(r3));self.bad()
