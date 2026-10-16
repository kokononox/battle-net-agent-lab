"""Regression fixtures for observed .build.info grammar; no real user row used."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import content_plan
import downloader_controller as controller
import installed_metadata
import repair_core as core
import update_scope as scope
import test_metadata_delta as mt
import test_update_scope as st

EXAMPLE=('Windows x86_64 EU? acct-ENG? geoip-US? enUS speech?:'
         'Windows x86_64 EU? acct-ENG? geoip-US? enUS text?')

def identity(tags):return type('Identity',(),{'row':{'tags':tags}})()

class TagSyntaxTests(unittest.TestCase):
    def test_known_trailing_question_marks_normalized(self):
        self.assertEqual(scope.installed_profile(identity('Windows x86_64 EU? enUS speech?:Windows x86_64 EU? enUS text?')),content_plan.Profile(('enUS',)))
    def test_documented_example_grammar_with_auxiliary_qualifiers(self):
        p,c=scope.profile_details(identity(EXAMPLE));self.assertEqual(p,content_plan.Profile(('enUS',)))
        self.assertEqual(c['optional_suffix_count'],8);self.assertEqual(c['account_qualifier_count'],2);self.assertEqual(c['geoip_qualifier_count'],2)
    def test_all_known_tokens_may_have_single_marker(self):
        self.assertEqual(scope.installed_profile(identity('Windows? x86_64? EU? enUS? text?')),content_plan.Profile(('enUS',)))
    def test_optional_locale_union_preserves_languages(self):
        self.assertEqual(scope.installed_profile(identity('Windows x86_64 EU? enUS? speech?:Windows x86_64 EU? frFR? text?')).locales,('enUS','frFR'))
    def test_auxiliary_region_cannot_replace_explicit_region(self):
        with self.assertRaisesRegex(core.RepairError,'missing_or_ambiguous'):
            scope.installed_profile(identity('Windows x86_64 acct-EU? geoip-EU? enUS'))
    def test_optional_multiple_regions_still_ambiguous(self):
        with self.assertRaisesRegex(core.RepairError,'missing_or_ambiguous'):
            scope.installed_profile(identity('Windows x86_64 EU? US? enUS'))
    def test_unknown_optional_tag_still_fails_closed(self):
        with self.assertRaises(scope.ProfileTagError) as got:scope.installed_profile(identity('Windows x86_64 EU? enUS SECRET_PRIVATE?'))
        self.assertEqual(got.exception.safe_profile_tag_diagnostic['unknown_optional_count'],1)
        self.assertNotIn('SECRET_PRIVATE',str(got.exception))
    def test_unknown_mandatory_qualifier_not_silently_ignored(self):
        with self.assertRaises(scope.ProfileTagError):scope.installed_profile(identity('Windows x86_64 EU enUS acct-ENG'))
    def test_account_identifier_content_not_in_public_counts(self):
        p,c=scope.profile_details(identity('Windows x86_64 EU? enUS acct-SECRET123? geoip-PRIVATE456?'))
        self.assertNotIn('SECRET',json.dumps(c));self.assertNotIn('PRIVATE',json.dumps(c));self.assertEqual(set(c),set(scope.TAG_DIAGNOSTIC_FIELDS))
    def test_double_marker_or_internal_punctuation_rejected(self):
        for bad in ('EU??','?EU','E?U','acct-ENG??','acct-?','geoip-?','acct-/secret?'):
            with self.subTest(bad=bad):
                with self.assertRaises(scope.ProfileTagError):scope.installed_profile(identity('Windows x86_64 EU enUS '+bad))
    def test_no_substring_or_arbitrary_question_mark_stripping(self):
        for bad in ('EUX?','XWindows?','enUSsuffix?','Windows??'):
            with self.assertRaises(scope.ProfileTagError):scope.installed_profile(identity('Windows x86_64 EU enUS '+bad))
    def test_error_report_contains_safe_counts_not_raw_unknown_values(self):
        with tempfile.TemporaryDirectory() as temp:
            lab=core.Lab.create(Path(temp).resolve()/'lab')
            try:scope.installed_profile(identity('Windows x86_64 EU? enUS acct-SECRET123? geoip-PRIVATE456? SECRET_TOKEN?'))
            except scope.ProfileTagError as e:result=controller.report_error(lab,e)
            self.assertEqual(result['profile_tag_syntax_counts']['unknown_optional_count'],1)
            raw=next((lab.root/'objects').glob('Retail-Queue-UI-Error-to-share-*.json')).read_text()
            for secret in ('SECRET','PRIVATE','ENG','geoip-','acct-',str(temp)):self.assertNotIn(secret,raw)
    def test_error_report_rejects_injected_extra_fields(self):
        e=core.RepairError('validation_failed');e.safe_profile_tag_diagnostic=dict.fromkeys(scope.TAG_DIAGNOSTIC_FIELDS,0)
        e.safe_profile_tag_diagnostic['raw_tags']='SECRET'
        self.assertNotIn('profile_tag_syntax_counts',controller.report_error(None,e))
    def test_error_report_rejects_non_numeric_or_unbounded_counts(self):
        for value in ('SECRET',-1,4097,True):
            e=core.RepairError('validation_failed');e.safe_profile_tag_diagnostic=dict.fromkeys(scope.TAG_DIAGNOSTIC_FIELDS,0);e.safe_profile_tag_diagnostic['token_count']=value
            self.assertNotIn('profile_tag_syntax_counts',controller.report_error(None,e))
    def test_duplicate_marked_and_plain_names_deduplicated_for_profile(self):
        self.assertEqual(scope.installed_profile(identity('Windows Windows? x86_64 EU EU? enUS enUS?')),content_plan.Profile(('enUS',)))


class TagEntrypointTests(unittest.TestCase):
    setUp=mt.PlannerTests.setUp
    cache_old=mt.PlannerTests.cache_old
    source_hashes=mt.PlannerTests.source_hashes
    queue=st.EntrypointTests.queue
    tagged=st.EntrypointTests.tagged
    def install_tags(self,tags):
        raw=(self.game/'.build.info').read_bytes();key=installed_metadata.select_row(raw)['buildkey']
        (self.game/'.build.info').write_bytes(mt.info(key,tags=tags))
    def test_tagged_full_scope_same_as_plain_profile_without_network_or_game_writes(self):
        self.tagged();self.install_tags(EXAMPLE);q=self.queue();before=self.source_hashes();state=self.state.read_bytes();queue_bytes=q.read_bytes()
        r=scope.plan_from_queue(self.lab,self.plan,q)
        self.assertEqual(r['status'],'profile_and_local_proof_scope_complete')
        self.assertEqual(r['update_scope']['policy']['profile']['locales'],['enUS'])
        self.assertEqual(r['update_scope']['installed_tag_syntax_counts']['optional_suffix_count'],8)
        self.assertFalse(r['update_scope']['account_geoip_qualifiers_used_for_selection'])
        self.assertEqual(r['update_scope']['retained_profile_without_encoded_proof_objects'],2)
        self.assertIsNone(r['required_network_download_bytes']);self.assertFalse(r['installation_ready']);self.assertEqual(r['network_requests'],0)
        self.assertEqual(before,self.source_hashes());self.assertEqual(state,self.state.read_bytes());self.assertEqual(queue_bytes,q.read_bytes())
        public=json.dumps(r)
        for secret in ('acct-','geoip-','ENG',str(self.base)):self.assertNotIn(secret,public)
    def test_truly_unknown_optional_fails_before_metadata_workspace_with_safe_report(self):
        self.tagged();self.install_tags(EXAMPLE+' SECRET_PRIVATE?');q=self.queue();before=self.state.read_bytes()
        with self.assertRaises(scope.ProfileTagError) as got:scope.plan_from_queue(self.lab,self.plan,q)
        info=controller.report_error(self.lab,got.exception)
        self.assertEqual(info['profile_tag_syntax_counts']['unknown_optional_count'],1)
        self.assertFalse(list(self.lab.root.glob('metadata-planning-*')));self.assertEqual(before,self.state.read_bytes())
        self.assertNotIn('SECRET',json.dumps(info))
