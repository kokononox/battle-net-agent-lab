"""Synthetic target candidate/catalogue binding; no installed-file IO."""
import io,json,sqlite3,unittest
import test_staged_reuse as fixtures
from reuse_candidates import sha_file
from stream_blte import StreamObjectSpec
from local_content_capture import LocalContentCapture
from local_capture_admission import admit_capture
from release_core import InvalidRelease
class Cases(unittest.TestCase):
 def setUp(self):
  fixtures.Tests.setUp(self);self.capture=LocalContentCapture.capture(io.BytesIO(self.raw),target=self.cp.target,spec=StreamObjectSpec(**self.spec.public()),scratch=self.root,byte_budget=len(self.raw));self.addCleanup(self.capture.close)
 update_db=fixtures.Tests.update_db
 def review(self):return admit_capture(self.capture,self.plan,self.o)
 def test_valid_copy_is_target_candidate_input(self):
  r=self.review();self.assertTrue(r['eligible_as_verified_staging_input']);self.assertEqual(r['verified_staging_input_bytes'],len(self.raw));self.assertFalse(r['generation_proof_needed_for_copied_content_identity'])
 def test_source_generation_and_installation_still_not_claimed(self):
  r=self.review()
  for k in ('source_generation_proven','source_store_binding_proven','vendor_selection_policy_qualified','required_set_selected','installed_content_reuse_authorized','installation_ready','apply_authorized'):self.assertFalse(r[k],k)
  self.assertIsNone(r['required_network_download_bytes'])
 def test_fake_capture_refused_before_path_read(self):
  with self.assertRaisesRegex(InvalidRelease,'instance_required'):admit_capture(object(),'absent','absent')
 def test_closed_capture_refused(self):
  self.capture.close()
  with self.assertRaises(InvalidRelease):self.review()
 def test_changed_target_refused(self):
  p=self.plan/'CANDIDATE-PLAN-to-share.json';r=json.loads(p.read_bytes());r['target']['version']='20.0.0.100001';r['target']['build_id']=100001;p.write_text(json.dumps(r))
  with self.assertRaises(InvalidRelease):self.review()
 def test_changed_catalogue_bytes_refused(self):
  p=self.o/'TARGET-CATALOGUE.sqlite';p.write_bytes(p.read_bytes()+b'bad')
  with self.assertRaises(InvalidRelease):self.review()
 def test_changed_plan_bytes_refused(self):
  p=self.plan/'CANDIDATE-PLAN.sqlite';p.write_bytes(p.read_bytes()+b'bad')
  with self.assertRaises(InvalidRelease):self.review()
 def test_unselected_key_refused(self):
  p=self.plan/'CANDIDATE-PLAN.sqlite';d=sqlite3.connect(p);d.execute('DELETE FROM selected_download');d.commit();d.close();rpath=self.plan/'CANDIDATE-PLAN-to-share.json';r=json.loads(rpath.read_bytes());r['database']['sha256']=sha_file(p);rpath.write_text(json.dumps(r))
  with self.assertRaises(InvalidRelease):self.review()
 def test_changed_full_content_key_refused(self):
  p=self.o/'TARGET-CATALOGUE.sqlite';d=sqlite3.connect(p);d.execute('UPDATE content_links SET ckey=?',(bytes.fromhex('f'*32),));d.commit();d.close();rpath=self.o/'CATALOGUE-VERIFIED-to-share.json';r=json.loads(rpath.read_bytes());r['database']['sha256']=sha_file(p);rpath.write_text(json.dumps(r));ppath=self.plan/'CANDIDATE-PLAN-to-share.json';q=json.loads(ppath.read_bytes());q['source_catalogue_sha256']=r['database']['sha256'];ppath.write_text(json.dumps(q))
  with self.assertRaises(InvalidRelease):self.review()
 def test_copy_corrupted_after_capture_refused(self):
  self.capture.file.seek(-1,2);self.capture.file.write(b'!')
  with self.assertRaises(InvalidRelease):self.review()
 def test_receipt_flag_does_not_grant_install(self):
  p=self.plan/'CANDIDATE-PLAN-to-share.json';r=json.loads(p.read_bytes());r['apply_authorized']=True;p.write_text(json.dumps(r));self.assertFalse(self.review()['apply_authorized'])
 def test_unknown_capture_subclass_refused(self):
  class Unknown(LocalContentCapture):pass
  with self.assertRaises(InvalidRelease):admit_capture(Unknown(),'absent','absent')
if __name__=='__main__':unittest.main()
