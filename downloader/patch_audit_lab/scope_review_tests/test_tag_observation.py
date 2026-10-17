"""Schema observation is NOT unknown-tag acceptance or an install selection."""
import hashlib,io,json,os
from unittest.mock import patch
import unittest
import source_binding as b
import saved_scope_review as s
from test_saved_scope_review import manifest,PROFILE,Integration

def observe(raw):return s.parse_manifest(s.ManifestReader(io.BytesIO(raw),len(raw),lambda:None),PROFILE,observe_unresolved=True)
def tags(extra=None):return [('Windows',1,255),('x86_64',2,255),('enUS',3,255),('EU',4,255)]+([] if extra is None else [extra])

class Observation(unittest.TestCase):
    def test_unknown_dimension_full_parse_but_no_selection(self):
        q=observe(manifest(tags=tags(('NovelPlatform',1,255))))
        self.assertFalse(q['selection_model_supported']);self.assertIsNone(q['diagnostic_selected_records']);self.assertIsNone(q['diagnostic_unselected_records'])
        self.assertIn('download_unknown_dimension_tag_no_guess',q['tag_schema']['blockers']);self.assertEqual(q['tag_schema']['observed_tags'][-1]['name'],'NovelPlatform')
    def test_unknown_kind_no_meaning_guessed(self):
        q=observe(manifest(tags=tags(('NovelKind',6,255))));self.assertIsNone(q['diagnostic_selected_records']);self.assertIn('download_unknown_tag_kind_no_guess',q['tag_schema']['blockers'])
    def test_kind_mismatch_not_reassigned_by_name(self):
        q=observe(manifest(tags=[('Windows',2,255)]));self.assertFalse(q['selection_model_supported']);self.assertIn('download_known_tag_kind_conflict',q['tag_schema']['blockers'])
    def test_missing_requested_tag_not_defaulted(self):
        q=observe(manifest(tags=[]));self.assertFalse(q['tag_schema']['model_supported']);self.assertIn('download_requested_tag_absent_no_fallback',q['tag_schema']['blockers'])
    def test_all_unknowns_collected_not_first_only(self):
        q=observe(manifest(tags=tags()+[('NovelA',1,255),('NovelB',2,255),('NovelC',9,255)]));self.assertEqual(len(q['tag_schema']['observed_tags']),7);self.assertEqual(len(q['tag_schema']['blockers']),2)
    def test_account_path_private_labels_redacted(self):
        for label in ('acct-Example','geoip-Example','PRIVATE_ACCOUNT','a/b','a@b','secret-token'):
            q=observe(manifest(tags=tags((label,1,255))));row=q['tag_schema']['observed_tags'][-1];self.assertIsNone(row['name']);self.assertEqual(row['name_utf8_sha256'],hashlib.sha256(label.encode()).hexdigest());self.assertNotIn(label,json.dumps(q))
    def test_padding_still_excluded_from_tag_member_counts(self):
        q=observe(manifest(n=7,tags=tags(('NovelPlatform',1,255))));self.assertEqual(q['tag_schema']['observed_tags'][-1]['member_records_excluding_padding'],7);self.assertEqual(q['nonzero_unused_padding_bits_ignored'],5)
    def test_complete_raw_hash_even_with_unknowns(self):
        raw=manifest(tags=tags(('NovelPlatform',1,255)));r=s.ManifestReader(io.BytesIO(raw),len(raw),lambda:None);s.parse_manifest(r,PROFILE,observe_unresolved=True);self.assertEqual(r.used,len(raw));self.assertEqual(r.md5.hexdigest(),hashlib.md5(raw).hexdigest())
    def test_trailing_bytes_not_accepted_by_observation(self):
        with self.assertRaisesRegex(b.BindingError,'download_manifest_trailing_bytes'):observe(manifest(tags=tags(('NovelPlatform',1,255)))+b'x')
    def test_truncation_not_accepted_by_observation(self):
        with self.assertRaises(b.BindingError):observe(manifest(tags=tags(('NovelPlatform',1,255)))[:-1])

# Reuse SETUP/HELPERS without inheriting 26 existing tests a second time.
class ObservationIntegration(unittest.TestCase):
    setUpClass=classmethod(Integration.setUpClass.__func__)
    setUp=Integration.setUp;tearDown=Integration.tearDown;review=Integration.review;rebind_test_manifest=Integration.rebind_test_manifest
    def test_verified_unknown_schema_report_publishes_without_selection(self):
        self.rebind_test_manifest(manifest(tags=tags(('NovelPlatform',1,255))));self.path.write_bytes(self.raw)
        q,private=self.review();self.assertTrue(q['download_metadata']['content_identity_revalidated']);self.assertEqual(q['status'],'bound_download_identity_verified_tag_schema_unresolved');self.assertIsNone(q['diagnostic_projection']);self.assertFalse(q['target_Download_tag_projection_computed']);self.assertFalse(q['installation_ready']);self.assertIsNone(private['absent_download_path'])
        final=s.publish(q,private,self.root/'new');self.assertEqual(json.loads(final.read_text()),q);self.assertEqual(q['scope']['archive_payload_bytes_read'],0)
    def test_unknown_schema_hash_mismatch_no_report_and_no_label_leak(self):
        self.rebind_test_manifest(manifest(tags=tags(('NovelPlatform',1,255))));self.path.write_bytes(self.raw[:-1]+b'\x7f')
        try:self.review()
        except b.BindingError as ex:
            self.assertEqual(str(ex),'saved_download_ckey_mismatch');self.assertNotIn('NovelPlatform',json.dumps(s.public_error(ex,'project_download_tags')))
        else:self.fail('unverified schema was accepted')
    def test_unknown_schema_rechecks_metadata_before_publication(self):
        self.rebind_test_manifest(manifest(tags=tags(('NovelPlatform',1,255))));self.path.write_bytes(self.raw);q,private=self.review();self.path.write_bytes(self.raw+b'changed')
        with self.assertRaises(b.BindingError):s.publish(q,private,self.root/'new')
    def test_unknown_schema_never_reads_archive_or_network(self):
        self.rebind_test_manifest(manifest(tags=tags(('NovelPlatform',1,255))));self.path.write_bytes(self.raw)
        from pathlib import Path
        original=Path.open
        def check(path,*args,**kw):
            if path==self.f.archive:raise AssertionError('archive payload forbidden')
            return original(path,*args,**kw)
        with patch.object(Path,'open',check),patch.object(s.a.Fetcher,'get',side_effect=AssertionError('network forbidden')):q,_=self.review()
        self.assertFalse(q['target_Download_tag_projection_computed']);self.assertEqual(q['network_requests'],0)

# unittest discovery must not discover the imported reference TestCase itself.
del Integration
