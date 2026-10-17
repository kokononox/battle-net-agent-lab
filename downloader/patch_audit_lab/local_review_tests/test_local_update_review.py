"""Synthetic saved DBs, real source/target payloads; never a real user install."""
import json,os,sqlite3,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import patch_audit as a
import source_binding as b
import local_update_review as r
from fixtures import Fixture,contents,TARGET
import staging_sample as s

class ReviewTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.portable=Path(os.environ['REVIEW_PORTABLE']).resolve();cls.audit=cls.portable/'pinned_metadata'
  cls.watch=b.Watch();cls.metadata=b.load_metadata(cls.audit,cls.watch)
  cls.source=Path(os.environ['REVIEW_SOURCE_ARCHIVE']).read_bytes();cls.committed=Path(os.environ['REVIEW_COMMITTED_ARCHIVE']).read_bytes()
  cls.watch.check()
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.f=Fixture(self.root,self.metadata[2],self.source)
 def tearDown(self):self.temp.cleanup();self.watch.check()
 def review(self,**kw):
  with patch.object(b,'load_metadata',return_value=self.metadata):return r.review(self.f.lab,self.audit,**kw)
 def committed_fixture(self,claims=True):
  other=self.root/'committed';other.mkdir();self.f=Fixture(other,self.metadata[2],self.committed,committed=True,claims=claims)
 def test_source_reused_but_unknown_target_conditional(self):
  q,_=self.review();self.assertEqual(q['actions'],{'full_download':1,'reuse':1});self.assertEqual(q['conditional_payload_bytes'],158);self.assertEqual(q['local_verification']['archive_payload_bytes_read'],158)
 def test_committed_two_real_objects_reused(self):
  self.committed_fixture();q,_=self.review();self.assertEqual(q['actions'],{'reuse':2});self.assertEqual(q['local_verification']['archive_payload_bytes_read'],316)
 def test_old_flags_not_required(self):
  self.committed_fixture(claims=False);q,_=self.review();self.assertEqual(q['actions'],{'reuse':2});self.assertFalse(q['local_verification']['saved_success_flags_used_as_proof'])
 def test_zero_budget_ignores_success_claims(self):
  self.committed_fixture();q,_=self.review(byte_budget=0);self.assertEqual(q['actions'],{'full_download':2});self.assertEqual(q['local_verification']['archive_payload_bytes_read'],0)
 def test_insufficient_budget_no_partial_read(self):
  q,_=self.review(byte_budget=157);self.assertEqual(q['local_verification']['archive_payload_bytes_read'],0)
 def test_exact_budget_reuse(self):
  q,_=self.review(byte_budget=158);self.assertEqual(q['actions']['reuse'],1);self.assertEqual(q['local_verification']['archive_read_calls'],1)
 def test_one_read_limit(self):
  self.committed_fixture();q,_=self.review(max_reads=1);self.assertEqual(q['local_verification']['archive_read_calls'],1);self.assertEqual(q['actions'],{'full_download':1,'reuse':1})
 def test_zero_checks(self):q,_=self.review(max_checks=0);self.assertEqual(q['local_verification']['candidate_checks'],0);self.assertEqual(q['actions'],{'full_download':2})
 def test_zero_read_calls(self):q,_=self.review(max_reads=0);self.assertEqual(q['local_verification']['archive_read_calls'],0)
 def test_negative_budget(self):
  with self.assertRaises(b.BindingError):self.review(byte_budget=-1)
 def test_boolean_budget(self):
  with self.assertRaises(b.BindingError):self.review(byte_budget=True)
 def test_too_large_budget(self):
  with self.assertRaises(b.BindingError):self.review(byte_budget=r.MAX_BYTES+1)
 def test_object_limit(self):
  q,_=self.review(object_limit=1);self.assertEqual(q['target_objects_evaluated'],1);self.assertFalse(q['scope']['evaluated_all_saved_rows'])
 def test_invalid_object_limit(self):
  with self.assertRaises(b.BindingError):self.review(object_limit=0)
 def test_cancelled_before_reads(self):
  with self.assertRaises(b.BindingError):self.review(cancel=lambda:True)
 def test_inputs_unchanged(self):
  before=contents(self.root);self.review();self.assertEqual(before,contents(self.root))
 def test_fingerprint_change_rejected(self):
  self.f.archive.write_bytes(self.source+b'x')
  with self.assertRaises(b.BindingError):self.review()
 def test_added_storage_file_rejected(self):
  (self.f.storage/'extra').write_bytes(b'x')
  with self.assertRaises(b.BindingError):self.review()
 def test_corrupt_payload_not_reused_despite_prior_claim(self):
  raw=bytearray(self.source);raw[-1]^=1;self.f.archive.write_bytes(raw);self.f.refresh_snapshot()
  q,_=self.review();self.assertNotIn('reuse',q['actions']);self.assertFalse(q['not_found_means_missing_or_corrupt']);self.assertGreater(q['local_verification']['candidate_diagnostics_not_corruption_verdicts'].get('candidate_payload_not_verified_or_unsupported',0),0)
 def test_source_captured_once_for_target_and_patch_base(self):
  q,_=self.review();self.assertEqual(q['local_verification']['archive_read_calls'],1)
 def test_source_fresh_not_generic_patch_permission(self):
  q,_=self.review();row=next(x for x in q['rows'] if x['target_ekey']==TARGET);self.assertEqual(row['action'],'full_download');self.assertGreater(row['patch_diagnostics'].get('patch_order_and_target_encoding_capability_unproven',0),0)
 def test_wrong_binding_rejected(self):
  wrong=dict(self.metadata[2],download_ckey='1'*32)
  self.f.edit(self.f.plan,'UPDATE metadata SET value=? WHERE name=?',(json.dumps(wrong),'target_binding'))
  with self.assertRaises(b.BindingError):self.review()
 def test_mixed_plan_id_rejected(self):
  self.f.edit(self.f.ev,'UPDATE metadata SET value=? WHERE name=?',(json.dumps('other'),'source_plan_id'))
  with self.assertRaises(b.BindingError):self.review()
 def test_unprocessed_evidence_rejected(self):
  self.f.edit(self.f.ev,'UPDATE metadata SET value=? WHERE name=?',(json.dumps({'candidate_rows_pending':1,'all_discovered_candidates_processed':False}),'local_verification_summary'))
  with self.assertRaises(b.BindingError):self.review()
 def test_sidecar_rejected(self):
  Path(str(self.f.inv)+'-journal').write_bytes(b'x')
  with self.assertRaises(b.BindingError):self.review()
 def test_missing_ekey_index_rejected(self):
  self.f.edit(self.f.inv,'DROP INDEX candidate_key')
  with self.assertRaises(b.BindingError):self.review()
 def test_source_out_of_bounds_not_read(self):
  self.f.edit(self.f.inv,'UPDATE candidates SET payload_offset=100000')
  # Existing prior full-proof coordinates are invalid: pre-read binder must stop.
  with self.assertRaises(b.BindingError):self.review()
 def test_invalid_candidate_without_success_flag_not_read(self):
  self.f.edit(self.f.ev,'UPDATE evidence SET encoded_object_verified=0')
  self.f.edit(self.f.inv,'UPDATE candidates SET payload_offset=100000')
  q,_=self.review();self.assertEqual(q['local_verification']['archive_read_calls'],0);self.assertNotIn('reuse',q['actions'])
 def test_ckey_mismatch_no_reuse(self):
  self.f.edit(self.f.ev,'UPDATE evidence SET encoded_object_verified=0')
  self.f.edit(self.f.inv,'UPDATE candidates SET ckey=?',(bytes.fromhex('2'*32),))
  q,_=self.review();self.assertNotIn('reuse',q['actions'])
 def test_public_report_omits_private_paths(self):
  q,_=self.review();text=json.dumps(q);self.assertNotIn(str(self.f.archive),text);self.assertNotIn(str(self.f.lab),text)
 def test_publish_separate_new_report(self):
  q,private=self.review();before=contents(self.f.lab);out=self.root/'reports';r.publish(self.f.lab,q,private,out)
  self.assertEqual(q,json.loads((out/'LOCAL-UPDATE-REVIEW-to-share.json').read_text()));self.assertEqual(before,contents(self.f.lab));self.assertEqual(len(list(out.iterdir())),1)
 def test_publish_inside_lab_rejected(self):
  q,private=self.review()
  with self.assertRaises(b.BindingError):r.publish(self.f.lab,q,private,self.f.lab/'reports')
 def test_publish_inside_storage_rejected(self):
  q,private=self.review()
  with self.assertRaises(b.BindingError):r.publish(self.f.lab,q,private,self.f.storage/'reports')
 def test_publish_in_other_game_tree_rejected(self):
  q,private=self.review();game=self.root/'game';game.mkdir();(game/'.build.info').write_text('fixture')
  with self.assertRaises(b.BindingError):r.publish(self.f.lab,q,private,game/'reports')
 def test_publish_existing_rejected(self):
  q,private=self.review();out=self.root/'reports';out.mkdir()
  with self.assertRaises(b.BindingError):r.publish(self.f.lab,q,private,out)
 def test_changed_inputs_prevent_publish(self):
  q,private=self.review();self.f.archive.write_bytes(self.source+b'x')
  with self.assertRaises(b.BindingError):r.publish(self.f.lab,q,private,self.root/'reports')
  self.assertFalse((self.root/'reports').exists())
 def test_sidecar_appearing_before_publish_rejected(self):
  q,private=self.review();Path(str(self.f.plan)+'-journal').write_bytes(b'x')
  with self.assertRaises(b.BindingError):r.publish(self.f.lab,q,private,self.root/'reports')
  self.assertFalse((self.root/'reports').exists())
 def test_change_during_publication_leaves_no_final_report(self):
  q,private=self.review();original=r.json.dump
  def change(*args,**kw):
   result=original(*args,**kw);self.f.archive.write_bytes(self.source+b'x');return result
  with patch.object(r.json,'dump',side_effect=change):
   with self.assertRaises(b.BindingError):r.publish(self.f.lab,q,private,self.root/'reports')
  self.assertFalse((self.root/'reports/LOCAL-UPDATE-REVIEW-to-share.json').exists())
  self.assertFalse(list((self.root/'reports').glob('*.pending')))
 def test_publication_does_not_overwrite_racing_file(self):
  q,private=self.review();original=r.os.link
  def race(src,dst):Path(dst).write_bytes(b'KEEP');return original(src,dst)
  with patch.object(r.os,'link',side_effect=race):
   with self.assertRaises(FileExistsError):r.publish(self.f.lab,q,private,self.root/'reports')
  self.assertEqual((self.root/'reports/LOCAL-UPDATE-REVIEW-to-share.json').read_bytes(),b'KEEP')
 def test_no_network_calls(self):
  import urllib.request
  with patch.object(urllib.request,'urlopen',side_effect=AssertionError('network forbidden')):q,_=self.review()
  self.assertEqual(q['network_requests'],0)
 def test_invalid_preview_rejected_before_bind(self):
  with patch.object(b,'bind',side_effect=AssertionError('must not inspect inputs')):
   with self.assertRaises(b.BindingError):r.review(self.f.lab,self.audit,preview_limit=-1)
 def test_arbitrary_selection_labels_not_in_public_report(self):
  tag={'policy':'PRIVATE_ACCOUNT_LABEL','profile':{'account':'SECRET'},'source_path':str(self.f.archive)}
  self.f.edit(self.f.plan,'UPDATE metadata SET value=? WHERE name=?',(json.dumps({'selected_unique_objects':2,'tag_selection':tag}),'plan_summary'))
  q,_=self.review();self.assertNotIn('PRIVATE_ACCOUNT_LABEL',json.dumps(q));self.assertNotIn('SECRET',json.dumps(q));self.assertNotIn(str(self.f.archive),json.dumps(q))
 def test_queue_sidecar_before_publish_rejected(self):
  q,private=self.review();Path(str(self.f.queue)+'-journal').write_bytes(b'x')
  with self.assertRaises(b.BindingError):r.publish(self.f.lab,q,private,self.root/'reports')
 def test_change_after_link_removes_final_report(self):
  q,private=self.review();original=r.os.link
  def change(src,dst):original(src,dst);self.f.archive.write_bytes(self.source+b'x')
  with patch.object(r.os,'link',side_effect=change):
   with self.assertRaises(b.BindingError):r.publish(self.f.lab,q,private,self.root/'reports')
  self.assertFalse((self.root/'reports/LOCAL-UPDATE-REVIEW-to-share.json').exists())
 def test_safe_errors_exclude_private_exception_details(self):
  self.assertNotIn('PRIVATE',json.dumps(r.public_error(OSError('PRIVATE/path'))))
  self.assertEqual(r.public_error(b.BindingError('plan_id_conflict'))['code'],'plan_id_conflict')
 def test_no_global_claims(self):
  q,_=self.review();self.assertIsNone(q['required_network_download_bytes']);self.assertFalse(q['full_game_build_plan']);self.assertFalse(q['installed_build_detected']);self.assertFalse(q['installation_ready']);self.assertFalse(q['apply_authorized'])
 def test_full_real_metadata_adapter_without_mock(self):
  q,_=r.review(self.f.lab,self.audit);self.assertEqual(q['actions'],{'full_download':1,'reuse':1})
 def test_real_portable_unlocks_only_pinned_patch(self):
  q,_=r.review(self.f.lab,self.audit,portable=self.portable);self.assertEqual(q['actions'],{'patch':1,'reuse':1});self.assertEqual(q['conditional_payload_bytes'],0);self.assertEqual(q['local_verification']['archive_read_calls'],1)
 def test_cli_invalid_path_safe(self):
  q=subprocess.run([sys.executable,'-B',r.__file__,'--lab','/does-not-exist','--audit-dir',str(self.audit)],capture_output=True,text=True)
  self.assertEqual(q.returncode,1);self.assertEqual(q.stderr,'');self.assertEqual(json.loads(q.stdout)['status'],'stopped_safely')
if __name__=='__main__':unittest.main()
