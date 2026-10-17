"""Owned synthetic DBs + real pair payloads. No real user install/profile proof."""
import contextlib,copy,io,json,os,sqlite3,sys,tempfile,types,unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
import local_update_review as r
import local_review_launcher as launch
import review_checkpoint as c
import review_report_explain as explain
import build_update_plan as planner
import source_binding as b
sys.path.insert(0,str(Path(r.__file__).parent/'local_review_tests'))
from fixtures import Fixture,contents,TARGET
import staging_sample as sample

T=planner.Target(TARGET,sample.OPTION['target_ckey'],158,33940,full_route=True)
def planned(t=T):return planner.plan([t],[],target_binding={},scope={})
class ClearSemantics(unittest.TestCase):
 def test_unknown_route_is_not_required_download(self):
  q=planned();self.assertEqual(q['actions'],{'full_download':1});self.assertEqual(q['unresolved_local_objects'],1);self.assertIsNone(q['rows'][0]['download_required']);self.assertEqual(q['transfer_option_counts'],{'conditional_full_download':1})
 def test_no_transfer_unknown_not_local_completion(self):
  q=planned(replace(T,full_route=False));self.assertEqual(q['unresolved_transfer_options'],1);self.assertEqual(q['unresolved_local_objects'],1)
 def test_zero_unresolved_route_does_not_mean_local_verified(self):
  q=planned();self.assertEqual(q['unresolved_objects'],0);self.assertEqual(q['unresolved_transfer_options'],0);self.assertEqual(q['unresolved_local_objects'],1)
 def test_fresh_status_separate_from_route(self):
  q=planned(replace(T,local='fresh_encoded'));self.assertEqual(q['local_status_counts'],{'fresh_verified':1});self.assertEqual(q['unresolved_local_objects'],0);self.assertEqual(q['rows'][0]['transfer_option'],'no_transfer')
 def test_counts_do_not_depend_on_preview(self):
  q=planner.plan([T,replace(T,ekey='1'*32,local='fresh_encoded')],[],target_binding={},scope={},preview_limit=0);self.assertEqual(q['unresolved_local_objects'],1);self.assertEqual(q['local_status_counts'],{'fresh_verified':1,'not_fresh_verified':1})
 def test_all_manifest_not_install_profile(self):
  q=c.selection_status(r.public_selection({'policy':'all_download_manifest_records'}));self.assertEqual(q['status'],'all_manifest_records_not_install_profile');self.assertFalse(q['actual_required_install_set_known'])
 def test_no_locale_guess(self):
  q=c.selection_status(r.public_selection({'policy':'matching_or_unclassified_per_dimension;OR_locales;AND_dimensions','profile':{'account':'PRIVATE'}}));self.assertEqual(q['status'],'saved_install_profile_not_established');self.assertNotIn('PRIVATE',json.dumps(q))
 def test_saved_profile_not_active_install_proof(self):
  q=c.selection_status(r.public_selection({'policy':'matching_or_unclassified_per_dimension;OR_locales;AND_dimensions','profile':{'platform':'Windows','architecture':'x86_64','region':'EU','locales':['enUS']}}));self.assertEqual(q['status'],'saved_profile_projection_not_active_install_proof');self.assertFalse(q['active_installed_profile_verified'])

class Continuation(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.portable=Path(os.environ['REVIEW_PORTABLE']).resolve();cls.audit=cls.portable/'pinned_metadata';cls.metadata=b.load_metadata(cls.audit,b.Watch())
  cls.source=Path(os.environ['REVIEW_SOURCE_ARCHIVE']).read_bytes();cls.committed=Path(os.environ['REVIEW_COMMITTED_ARCHIVE']).read_bytes()
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.f=Fixture(self.root,self.metadata[2],self.committed,committed=True)
 def tearDown(self):self.temp.cleanup()
 def review(self,**kw):
  with patch.object(b,'load_metadata',return_value=self.metadata):return r.review(self.f.lab,self.audit,**kw)
 def saved(self,q,name='previous.json'):
  p=self.root/name;p.write_text(json.dumps(q));return p
 def test_prepare_has_zero_payload_reads_and_no_input_writes(self):
  before=contents(self.f.lab)
  with patch.object(r.Reader,'verify',side_effect=AssertionError('no payload')):q,_=self.review(batch=True,metadata_only=True)
  self.assertEqual(q['local_verification']['archive_payload_bytes_read'],0);self.assertEqual(q['target_objects_evaluated'],0);self.assertIsNone(q['continuation']['next_cursor']['after_ekey']);self.assertTrue(q['continuation']['has_more_saved_targets']);self.assertEqual(contents(self.f.lab),before)
 def test_prepare_can_publish_external_report(self):
  q,private=self.review(batch=True,metadata_only=True);out=r.publish(self.f.lab,q,private,self.root/'out');self.assertEqual(json.loads((out/'LOCAL-UPDATE-REVIEW-to-share.json').read_text()),q)
 def test_prepare_rejects_portable_payload_work(self):
  with patch.object(b,'bind',side_effect=AssertionError('no input work')):
   with self.assertRaises(b.BindingError):self.review(batch=True,metadata_only=True,portable=self.portable)
 def test_two_bounded_batches_continue_without_repeating_first_target(self):
  first,_=self.review(batch=True,max_reads=1);self.assertEqual(first['actions'],{'reuse':1});self.assertEqual(first['continuation']['status'],'paused_on_limits');self.assertEqual(first['continuation']['next_cursor']['after_ekey'],sample.OPTION['source_ekey']);self.assertEqual(first['continuation']['deferred_target_ekey_not_skipped'],TARGET)
  second,_=self.review(batch=True,continue_from=self.saved(first),max_reads=1)
  self.assertEqual(second['actions'],{'reuse':1});self.assertEqual(second['rows'][0]['target_ekey'],TARGET);self.assertEqual(second['local_verification']['archive_payload_bytes_read'],158);self.assertFalse(second['continuation']['has_more_saved_targets']);self.assertFalse(second['scope']['evaluated_all_saved_rows']);self.assertFalse(second['continuation']['cumulative_verified_objects_claimed'])
 def test_first_deferred_target_never_skipped(self):
  q,_=self.review(batch=True,byte_budget=157);self.assertEqual(q['target_objects_evaluated'],0);self.assertIsNone(q['continuation']['next_cursor']['after_ekey']);self.assertEqual(q['continuation']['status'],'blocked_no_progress')
 def test_zero_read_calls_does_not_advance_position(self):
  q,_=self.review(batch=True,max_reads=0);self.assertFalse(q['continuation']['position_advanced']);self.assertEqual(q['local_verification']['archive_read_calls'],0)
 def test_zero_checks_does_not_advance_position(self):
  q,_=self.review(batch=True,max_checks=0);self.assertFalse(q['continuation']['position_advanced']);self.assertEqual(q['local_verification']['candidate_checks'],0)
 def test_exact_budget_defers_next_target(self):
  q,_=self.review(batch=True,byte_budget=158);self.assertEqual(q['actions'],{'reuse':1});self.assertEqual(q['continuation']['deferred_target_ekey_not_skipped'],TARGET)
 def test_object_limit_continues_by_key_not_offset(self):
  q,_=self.review(batch=True,object_limit=1);self.assertEqual(q['continuation']['status'],'position_batch_complete');q2,_=self.review(batch=True,continue_from=self.saved(q),object_limit=1);self.assertEqual(q2['rows'][0]['target_ekey'],TARGET)
 def test_completed_cursor_reads_no_more_payload(self):
  q,_=self.review(batch=True);p=self.saved(q)
  with patch.object(r.Reader,'verify',side_effect=AssertionError('no payload')):q2,_=self.review(batch=True,continue_from=p)
  self.assertEqual(q2['target_objects_evaluated'],0);self.assertFalse(q2['continuation']['has_more_saved_targets']);self.assertEqual(q2['local_verification']['archive_payload_bytes_read'],0)
 def test_old_proof_flags_not_imported(self):
  q,_=self.review(batch=True,metadata_only=True);q['actions']={'reuse':999999};q['rows']=[{'local_state':'fresh_encoded','target_ekey':TARGET}];q['installation_ready']=True
  fresh,_=self.review(batch=True,continue_from=self.saved(q),max_reads=0)
  self.assertEqual(fresh['actions'],{});self.assertFalse(fresh['installation_ready']);self.assertFalse(fresh['continuation']['prior_results_used_for_fresh_decisions'])
 def test_legacy_report_cannot_seed_bound_position(self):
  q,_=self.review();p=self.saved(q)
  with patch.object(r.Reader,'verify',side_effect=AssertionError('must stop before payload')):
   with self.assertRaisesRegex(b.BindingError,'legacy_report_has_no_bound_continuation'):self.review(batch=True,continue_from=p)
 def test_wrong_input_binding_stops_before_payload(self):
  q,_=self.review(batch=True,metadata_only=True);q['continuation']['next_cursor']['input_binding']='0'*64
  with patch.object(r.Reader,'verify',side_effect=AssertionError('no payload')):
   with self.assertRaises(b.BindingError):self.review(batch=True,continue_from=self.saved(q))
 def test_changed_saved_plan_rejects_cursor(self):
  q,_=self.review(batch=True,metadata_only=True);p=self.saved(q);self.f.edit(self.f.plan,'UPDATE plan SET transfer_supported=0')
  with self.assertRaisesRegex(b.BindingError,'continuation_inputs_changed'):self.review(batch=True,continue_from=p)
 def test_different_lab_rejects_cursor(self):
  q,_=self.review(batch=True,metadata_only=True);p=self.saved(q);other=self.root/'other';other.mkdir();self.f=Fixture(other,self.metadata[2],self.committed,committed=True)
  with self.assertRaises(b.BindingError):self.review(batch=True,continue_from=p)
 def test_nonexistent_cursor_key_rejected(self):
  q,_=self.review(batch=True,metadata_only=True);q['continuation']['next_cursor']['after_ekey']='0'*32
  with self.assertRaisesRegex(b.BindingError,'continuation_key_not_in_plan'):self.review(batch=True,continue_from=self.saved(q))
 def test_cursor_extra_proof_field_rejected(self):
  q,_=self.review(batch=True,metadata_only=True);q['continuation']['next_cursor']['verified']=True
  with self.assertRaises(b.BindingError):self.review(batch=True,continue_from=self.saved(q))
 def test_cursor_duplicate_keys_rejected(self):
  p=self.root/'bad.json';p.write_text('{"format":"readonly-local-update-review-1","format":"other"}')
  with self.assertRaises(b.BindingError):self.review(batch=True,continue_from=p)
 def test_cursor_oversize_rejected(self):
  p=self.root/'large.json';p.write_bytes(b' '*(4*1024**2+1))
  with self.assertRaises(b.BindingError):self.review(batch=True,continue_from=p)
 def test_cursor_file_is_watched_through_publication(self):
  q,_=self.review(batch=True,metadata_only=True);p=self.saved(q);q2,private=self.review(batch=True,continue_from=p,object_limit=1);p.write_text('changed')
  with self.assertRaises(b.BindingError):r.publish(self.f.lab,q2,private,self.root/'out')
 def test_no_private_paths_or_raw_profile_in_cursor(self):
  q,_=self.review(batch=True,metadata_only=True);text=json.dumps(q);self.assertNotIn(str(self.root),text);self.assertNotIn('snapshot_id',json.dumps(q['continuation']));self.assertFalse(q['scope']['installation_scope']['profile_guessed'])
 def test_unknown_no_candidate_is_not_missing_and_may_advance(self):
  self.f.edit(self.f.inv,'DELETE FROM candidates WHERE ekey=?',(bytes.fromhex(TARGET),));self.f.edit(self.f.ev,'DELETE FROM evidence WHERE ekey=?',(bytes.fromhex(TARGET),))
  q,_=self.review(batch=True);self.assertEqual(q['unresolved_local_objects'],1);self.assertFalse(q['continuation']['has_more_saved_targets']);self.assertFalse(q['not_found_means_missing_or_corrupt']);self.assertIsNone(q['required_network_download_bytes'])
 def test_batch_limits_not_relaxed(self):
  with self.assertRaises(b.BindingError):self.review(batch=True,byte_budget=32*1024**2+1)
 def test_no_automatic_next_batch_or_network(self):
  import urllib.request
  with patch.object(urllib.request,'urlopen',side_effect=AssertionError('no network')):q,_=self.review(batch=True,max_reads=1)
  self.assertFalse(q['continuation']['automatic_next_batch_started']);self.assertEqual(q['local_verification']['archive_read_calls'],1)
 def test_explainer_uses_only_report_no_Lab_or_payload(self):
  q,_=self.review(max_reads=0)
  with patch.object(b,'bind',side_effect=AssertionError('no Lab')),patch.object(r.Reader,'verify',side_effect=AssertionError('no payload')):e=explain.explain(q)
  self.assertEqual(e['target_objects_not_fresh_verified'],2);self.assertEqual(e['archive_payload_bytes_read_by_explainer'],0);self.assertFalse(e['bound_continuation_available']);self.assertFalse(e['installation_ready'])
 def test_explainer_rejects_bad_totals(self):
  q,_=self.review();q['target_objects_evaluated']=999
  with self.assertRaises(b.BindingError):explain.explain(q)
 def test_explainer_rejects_preview_count_conflict(self):
  q,_=self.review();q['rows_omitted']=3
  with self.assertRaises(b.BindingError):explain.explain(q)
 def test_explainer_rejects_boolean_counter(self):
  q,_=self.review();q['actions']['reuse']=True
  with self.assertRaises(b.BindingError):explain.explain(q)
 def test_explainer_rejects_budget_overrun_claim(self):
  q,_=self.review();q['local_verification']['archive_read_calls']=999
  with self.assertRaises(b.BindingError):explain.explain(q)
 def test_explainer_whitelists_scope_policy(self):
  q,_=self.review();q['scope']['tag_selection']['policy']='PRIVATE';self.assertNotIn('PRIVATE',json.dumps(explain.explain(q)))
 def test_explainer_conditional_bytes_not_required_network(self):
  q,_=self.review(max_reads=0);q['required_network_download_bytes']=316;e=explain.explain(q);self.assertIsNone(e['required_network_download_bytes']);self.assertTrue(e['input_claims_only_not_new_content_proof'])
 def test_metadata_only_launcher_does_not_start_payload_batch(self):
  tk=types.ModuleType('tkinter');tk.Tk=lambda:types.SimpleNamespace(withdraw=lambda:None,destroy=lambda:None);tk.filedialog=types.SimpleNamespace(askdirectory=lambda **kw:str(self.f.lab));tk.messagebox=types.SimpleNamespace()
  def fake_review(*args,**kw):
   self.assertTrue(kw['metadata_only']);self.assertTrue(kw['batch']);self.assertIsNone(kw['continue_from']);return {'local_status_counts':{},'transfer_option_counts':{},'local_verification':{'archive_payload_bytes_read':0},'continuation':{'status':'prepared_metadata_only'}},{}
  with patch.dict(sys.modules,{'tkinter':tk,'tkinter.filedialog':tk.filedialog,'tkinter.messagebox':tk.messagebox}),patch.object(r,'review',side_effect=fake_review),patch.object(r,'publish',return_value=self.root/'out'),contextlib.redirect_stdout(io.StringIO()):self.assertEqual(launch.main(metadata_only=True),0)
 def test_continuation_picker_cancel_does_not_start_review(self):
  tk=types.ModuleType('tkinter');tk.Tk=lambda:types.SimpleNamespace(withdraw=lambda:None,destroy=lambda:None);tk.filedialog=types.SimpleNamespace(askdirectory=lambda **kw:str(self.f.lab),askopenfilename=lambda **kw:'');tk.messagebox=types.SimpleNamespace()
  with patch.dict(sys.modules,{'tkinter':tk,'tkinter.filedialog':tk.filedialog,'tkinter.messagebox':tk.messagebox}),patch.object(r,'review',side_effect=AssertionError('no read')),contextlib.redirect_stdout(io.StringIO()):self.assertEqual(launch.main(continuation=True),0)
if __name__=='__main__':unittest.main()
