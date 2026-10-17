"""Pinned-model tests use SYNTHETIC manifests/identity bindings, not user bytes."""
from dataclasses import replace,FrozenInstanceError
from pathlib import Path
from unittest.mock import patch
import hashlib,io,json,random,unittest
import saved_scope_review as s
import pinned_download_model as m
import source_binding as b
from test_saved_scope_review import manifest,PROFILE,Integration

CATALOGUE=m.PINNED_MODEL.tags

def fixture_tags(overrides=None,padding_noise=False):
    masks={'Windows':0xf0,'OSX':0x0c,'x86_64':0xf0,'x86_32':0x0c,'enUS':0xc0,'frFR':0x30,'EU':0xc0,'US':0x30,'Alternate':0x01,'HighRes':0x04,'Talebound':0x02,'speech':0x01,'text':0x04}
    masks.update(overrides or {})
    return [(name,kind,masks.get(name,0)|int(padding_noise)) for name,kind in CATALOGUE]

def model_for(raw,identity='synthetic-observed-schema-NOT-real-target'):
    return m.Model(identity,hashlib.md5(raw).hexdigest(),hashlib.sha256(raw).hexdigest(),len(raw),raw[2],int.from_bytes(raw[5:9],'big'),CATALOGUE)

def run(raw,model=None,profile=PROFILE):
    r=s.ManifestReader(io.BytesIO(raw),len(raw),lambda:None)
    return s.parse_manifest(r,profile,observe_unresolved=True,pinned_model=model)

def oracle(tags,profile=PROFILE,n=8):
    # Independent per-record set membership, not integer complement formula.
    required={1:{profile['platform']},2:{profile['architecture']},3:set(profile['locales']),4:{profile['region']}}
    selected=0
    for ordinal in range(n):
        bit=1<<(((n+7)//8)*8-1-ordinal);ok=True
        for kind,values in required.items():
            members={name for name,raw,mask in tags if raw&~0x4000==kind and mask&bit}
            ok &= not members or bool(members&values)
        if ok:selected|=bit
    return selected

class PinnedModel(unittest.TestCase):
    def setUp(self):self.tags=fixture_tags();self.raw=manifest(tags=self.tags);self.model=model_for(self.raw)
    def test_production_identity_exact_and_catalogue31(self):
        p=m.PINNED_MODEL;self.assertEqual(p.ckey,'5beff4cf8122da27a6788d9062c8d3c2');self.assertEqual(p.sha256,'02f0ccb262e1a202e8beaf89ee9011a800b37f29cb34edbc36fe600204686ce1');self.assertEqual(len(p.tags),31);self.assertEqual(p.format_version,1);self.assertEqual(p.manifest_records,2881619);self.assertEqual(p.decoded_bytes,74562151)
    def test_lookup_only_exact_ckey(self):
        self.assertIs(m.for_ckey(m.PINNED_MODEL.ckey),m.PINNED_MODEL);self.assertIsNone(m.for_ckey('0'*32));self.assertIsNone(m.for_ckey(m.PINNED_MODEL.ckey.upper()))
    def test_frozen_model(self):
        with self.assertRaises(FrozenInstanceError):self.model.ckey='0'*32
    def test_synthetic_exact_catalogue_projects_four_records(self):
        q=run(self.raw,self.model);self.assertEqual(q['diagnostic_selected_records'],4);self.assertEqual(q['diagnostic_unselected_records'],4);self.assertEqual(q['selected_record_bitmap_sha256'],hashlib.sha256(b'\xc3').hexdigest());self.assertTrue(q['pinned_tag_model']['raw_identity_header_and_ordered_catalogue_revalidated']);self.assertEqual(q['non_dimension_tags_not_excluded'],5)
    def test_random_masks_match_independent_per_record_oracle(self):
        rng=random.Random(70391)
        for _ in range(64):
            tags=fixture_tags({name:rng.randrange(256) for name,_ in CATALOGUE});raw=manifest(tags=tags);q=run(raw,model_for(raw));expected=oracle(tags)
            self.assertEqual(q['diagnostic_selected_records'],expected.bit_count());self.assertEqual(q['selected_record_bitmap_sha256'],hashlib.sha256(bytes([expected])).hexdigest())
    def test_kind5_and_optional_categories_never_exclude(self):
        results=[]
        for mask in (0,255):
            tags=fixture_tags({name:mask for name in ('speech','text','Alternate','HighRes','Talebound')});raw=manifest(tags=tags);results.append(run(raw,model_for(raw))['selected_record_bitmap_sha256'])
        self.assertEqual(*results)
    def test_generic_whitelists_not_expanded(self):
        q=run(self.raw);self.assertFalse(q['selection_model_supported']);self.assertIsNone(q['diagnostic_selected_records']);self.assertNotIn('Android',s.DIMENSIONS[0]);self.assertNotIn('arm64',s.DIMENSIONS[1])
    def test_no_ARM64_alias_inference(self):
        q=run(self.raw,self.model,dict(PROFILE,architecture='ARM64'));self.assertIsNone(q['diagnostic_selected_records']);self.assertIn('download_requested_tag_absent_no_fallback',q['tag_schema']['blockers'])
    def test_missing_catalogue_tag_rejected(self):
        raw=manifest(tags=self.tags[:-1])
        with self.assertRaises(b.BindingError):run(raw,self.model)
    def test_extra_catalogue_tag_rejected(self):
        raw=manifest(tags=self.tags+[('Unknown',1,255)])
        with self.assertRaises(b.BindingError):run(raw,self.model)
    def test_reordered_catalogue_rejected(self):
        raw=manifest(tags=list(reversed(self.tags)))
        with self.assertRaisesRegex(b.BindingError,'pinned_model_tag_catalogue_mismatch'):run(raw,self.model)
    def test_raw_kind_changed_rejected(self):
        tags=list(self.tags);name,kind,mask=tags[0];tags[0]=(name,2,mask);raw=manifest(tags=tags)
        with self.assertRaisesRegex(b.BindingError,'pinned_model_tag_catalogue_mismatch'):run(raw,self.model)
    def test_ckey_mismatch_rejected(self):
        with self.assertRaisesRegex(b.BindingError,'pinned_model_ckey_mismatch'):run(self.raw,replace(self.model,ckey='0'*32))
    def test_sha256_mismatch_rejected(self):
        with self.assertRaisesRegex(b.BindingError,'pinned_model_sha256_mismatch'):run(self.raw,replace(self.model,sha256='0'*64))
    def test_size_mismatch_rejected(self):
        with self.assertRaisesRegex(b.BindingError,'pinned_model_size_mismatch'):run(self.raw,replace(self.model,decoded_bytes=len(self.raw)+1))
    def test_record_count_mismatch_rejected(self):
        with self.assertRaisesRegex(b.BindingError,'pinned_model_header_mismatch'):run(self.raw,replace(self.model,manifest_records=9))
    def test_binary_version_mismatch_rejected(self):
        with self.assertRaisesRegex(b.BindingError,'pinned_model_header_mismatch'):run(self.raw,replace(self.model,format_version=1))
    def test_production_pin_cannot_accept_synthetic_file(self):
        with self.assertRaises(b.BindingError):run(self.raw,m.PINNED_MODEL)
    def test_padding_excluded_but_raw_hashes_include_noise(self):
        tags=fixture_tags(padding_noise=True);raw=manifest(n=7,tags=tags);q=run(raw,model_for(raw));expected=oracle(tags,n=7);self.assertEqual(q['diagnostic_selected_records'],expected.bit_count());self.assertEqual(q['nonzero_unused_padding_bits_ignored'],31);self.assertEqual(q['selected_record_bitmap_sha256'],hashlib.sha256(bytes([expected])).hexdigest())
    def test_no_install_or_unique_object_or_network_claim(self):
        q=run(self.raw,self.model);self.assertFalse(q['vendor_install_policy_proven']);self.assertFalse(q['unique_objects_or_duplicate_size_consistency_computed']);self.assertFalse(q['selected_encoded_bytes_computed']);self.assertTrue(q['pinned_tag_model']['policy_is_conservative_record_projection_NOT_vendor_install_selection'])

class PinnedIntegration(unittest.TestCase):
    setUpClass=classmethod(Integration.setUpClass.__func__)
    setUp=Integration.setUp;tearDown=Integration.tearDown;review=Integration.review;rebind_test_manifest=Integration.rebind_test_manifest
    def prepare(self):
        raw=manifest(tags=fixture_tags());self.rebind_test_manifest(raw);self.path.write_bytes(raw);return model_for(raw)
    def test_project_publish_only_after_all_pin_checks(self):
        model=self.prepare()
        with patch.object(m,'for_ckey',return_value=model):q,private=self.review()
        self.assertEqual(q['status'],'bound_download_diagnostic_projection_complete');self.assertEqual(q['diagnostic_projection']['diagnostic_selected_records'],4);self.assertTrue(q['target_Download_tag_projection_computed']);self.assertFalse(q['actual_required_install_set_known']);self.assertIsNone(q['required_network_download_bytes']);self.assertFalse(q['installation_ready'])
        final=s.publish(q,private,self.root/'new');self.assertEqual(json.loads(final.read_text()),q)
    def test_model_sha_failure_prevents_report(self):
        model=self.prepare()
        with patch.object(m,'for_ckey',return_value=replace(model,sha256='0'*64)):
            with self.assertRaisesRegex(b.BindingError,'pinned_model_sha256_mismatch'):self.review()
        self.assertFalse((self.root/'new').exists())
    def test_model_ckey_failure_prevents_report(self):
        model=self.prepare()
        with patch.object(m,'for_ckey',return_value=replace(model,ckey='0'*32)):
            with self.assertRaisesRegex(b.BindingError,'pinned_model_ckey_mismatch'):self.review()
    def test_public_report_never_imported_as_proof(self):
        model=self.prepare();other=self.f.objects/'SCOPE-REVIEW-to-share.json';other.write_text('{"installation_ready":true,"selected_records":99999999}')
        original=Path.open
        def check(path,*args,**kw):
            if path==other:raise AssertionError('public report must not be imported')
            return original(path,*args,**kw)
        with patch.object(m,'for_ckey',return_value=model),patch.object(Path,'open',check):q,_=self.review()
        self.assertEqual(q['diagnostic_projection']['diagnostic_selected_records'],4);self.assertFalse(q['installation_ready'])
    def test_pinned_review_never_reads_archive_or_network(self):
        model=self.prepare();original=Path.open
        def check(path,*args,**kw):
            if path==self.f.archive:raise AssertionError('archive payload forbidden')
            return original(path,*args,**kw)
        with patch.object(m,'for_ckey',return_value=model),patch.object(Path,'open',check),patch.object(s.a.Fetcher,'get',side_effect=AssertionError('network forbidden')):q,_=self.review()
        self.assertEqual(q['scope']['archive_payload_bytes_read'],0);self.assertEqual(q['network_requests'],0)
    def test_postreview_metadata_change_still_rejected(self):
        model=self.prepare()
        with patch.object(m,'for_ckey',return_value=model):q,private=self.review()
        self.path.write_bytes(self.raw+b'changed')
        with self.assertRaises(b.BindingError):s.publish(q,private,self.root/'new')

del Integration
