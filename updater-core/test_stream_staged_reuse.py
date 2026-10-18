import json,sqlite3,unittest
import test_staged_reuse as small_fixture
from stream_blte import StreamObjectSpec
from stream_stage import StreamStage
from stream_staged_reuse import reverify_stream_candidate
from archive_transfer import ArchiveResponse,archive_url
from release_core import InvalidRelease
from reuse_candidates import sha_file
# Borrow setup only; do NOT inherit/count the earlier suite a second time.
class Tests(unittest.TestCase):
 def setUp(self):
  small_fixture.Tests.setUp(self);self.large=StreamStage.create(self.root/'stream-stage',self.cp,StreamObjectSpec(**self.spec.public()),self.src);self.large.append(ArchiveResponse(archive_url(self.cp,self.src),100,100+len(self.raw)-1,1000,'"cache"',self.raw),(0,len(self.raw)-1))
 update_db=small_fixture.Tests.update_db
 def run_review(self):return reverify_stream_candidate(self.large,self.plan,self.o)
 def test_verified_candidate(self):
  r=self.run_review();self.assertTrue(r['eligible_as_verified_staging_input']);self.assertFalse(r['installed_content_reuse_authorized']);self.assertFalse(r['apply_authorized'])
 def test_corrupt_segment(self):
  p=self.large.path/self.large.doc['segments'][0]['name'];p.write_bytes(b'x'*len(self.raw))
  with self.assertRaises(InvalidRelease):self.run_review()
 def test_target_changed(self):
  p=self.plan/'CANDIDATE-PLAN-to-share.json';r=json.loads(p.read_bytes());r['target']['version']='20.0.0.100001';r['target']['build_id']=100001;p.write_text(json.dumps(r))
  with self.assertRaises(InvalidRelease):self.run_review()
 def test_catalogue_changed(self):
  p=self.o/'TARGET-CATALOGUE.sqlite';p.write_bytes(p.read_bytes()+b'x')
  with self.assertRaises(InvalidRelease):self.run_review()
 def test_unselected_object(self):
  p=self.plan/'CANDIDATE-PLAN.sqlite';db=sqlite3.connect(p);db.execute('DELETE FROM selected_download');db.commit();db.close();p2=self.plan/'CANDIDATE-PLAN-to-share.json';r=json.loads(p2.read_bytes());r['database']['sha256']=sha_file(p);p2.write_text(json.dumps(r))
  with self.assertRaises(InvalidRelease):self.run_review()
 def test_receipt_does_not_grant_apply(self):
  p=self.plan/'CANDIDATE-PLAN-to-share.json';r=json.loads(p.read_bytes());r['apply_authorized']=True;p.write_text(json.dumps(r));self.assertFalse(self.run_review()['apply_authorized'])
if __name__=='__main__':unittest.main()
