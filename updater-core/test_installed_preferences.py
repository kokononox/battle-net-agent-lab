import copy,hashlib,json,unittest
from installed_preferences import inspect_preferences,review_target_preferences
from release_core import InvalidRelease
from installed_identity import InvalidMetadata
from test_installed_identity import CONFIG,info
from test_product_policy_facts import fixture
BASE='Windows x86_64 EU? enUS speech?:Windows x86_64 EU? enUS text?'
class PreferenceTests(unittest.TestCase):
 def r(self,tags=BASE):return inspect_preferences(info(tags=tags),CONFIG)
 def bad(self,tags):
  with self.assertRaises((InvalidRelease,InvalidMetadata)):self.r(tags)
 def test_exact_two_clauses(self):
  r=self.r();self.assertEqual(len(r['public_clauses']),2);self.assertEqual(r['profile'],{'platform':'Windows','architecture':'x86_64','region':'EU','text_locales':['enUS'],'speech_locales':['enUS']});self.assertTrue(r['clause_pairing_preserved'])
 def test_optional_markers_preserved(self):
  t=self.r()['public_clauses'][0];self.assertEqual([(x['name'],x['optional'])for x in t],[('Windows',False),('x86_64',False),('EU',True),('enUS',False),('speech',True)])
 def test_speech_text_pairing_not_union(self):
  r=self.r('Windows x86_64 EU? deDE speech?:Windows x86_64 EU? enUS text?');self.assertEqual(r['profile']['speech_locales'],['deDE']);self.assertEqual(r['profile']['text_locales'],['enUS'])
 def test_text_only_not_implied_speech(self):r=self.r('Windows x86_64 EU enUS text');self.assertEqual(r['profile']['speech_locales'],[])
 def test_speech_only_not_implied_text(self):r=self.r('Windows x86_64 EU enUS speech');self.assertEqual(r['profile']['text_locales'],[])
 def test_same_type_locale_ambiguity_refused(self):self.bad('Windows x86_64 EU enUS deDE speech')
 def test_two_categories_refused(self):self.bad('Windows x86_64 EU enUS speech text')
 def test_missing_category_not_both(self):self.bad('Windows x86_64 EU enUS')
 def test_missing_region_no_fallback(self):self.bad('Windows x86_64 enUS speech')
 def test_optional_architecture_refused(self):self.bad('Windows x86_64? EU enUS speech')
 def test_optional_locale_refused(self):self.bad('Windows x86_64 EU enUS? speech')
 def test_optional_platform_refused(self):self.bad('Windows? x86_64 EU enUS speech')
 def test_duplicate_public_token(self):self.bad('Windows x86_64 EU enUS speech speech')
 def test_private_qualifiers_do_not_escape(self):
  r=self.r('Windows x86_64 EU? enUS speech? acct-SECRET? geoip-SECRET?');self.assertEqual(r['private_optional_qualifiers_withheld'],2);self.assertNotIn('SECRET',json.dumps(r))
 def test_unknown_feature_no_default(self):self.bad('Windows x86_64 EU enUS speech HighRes')
 def test_private_unknown_no_error_echo(self):
  try:self.r('Windows x86_64 EU enUS speech SECRET-PATH')
  except (InvalidRelease,InvalidMetadata)as e:self.assertNotIn('SECRET',str(e))
  else:self.fail('must reject')
 def test_clause_scope_conflict(self):self.bad('Windows x86_64 EU enUS text:Windows x86_64 US deDE speech')
 def test_clause_architecture_conflict(self):self.bad('Windows x86_64 EU enUS text:Windows ARM64 EU enUS speech')
 def test_arm64_explicit_normalization(self):
  r=self.r('Windows ARM64 EU enUS speech');self.assertEqual(r['profile']['architecture'],'arm64');self.assertTrue(r['architecture_normalization_applied']);self.assertEqual(r['public_clauses'][0][1]['name'],'ARM64')
 def test_no_live_or_generation_promotion(self):
  r=self.r()
  for k in ('live_installation_state_revalidated','fresh_installed_preferences_proven','active_generation_proven','required_set_selected','installation_ready','apply_authorized'):self.assertFalse(r[k])
 def test_maximum_clause_budget(self):self.bad(':'.join(['Windows x86_64 EU enUS text']*17))
 def test_multiple_locales_preserved_per_category(self):
  r=self.r(BASE+':Windows x86_64 EU deDE text');self.assertEqual(r['profile']['text_locales'],['deDE','enUS']);self.assertEqual(r['profile']['speech_locales'],['enUS'])
 def test_target_config_integration(self):
  t,vr,c,p=fixture();r=review_target_preferences(info(tags=BASE),CONFIG,t,vr,c);self.assertTrue(r['target_product_config_facts']['release_table_and_content_key_bound']);self.assertFalse(r['canonical_locale_replan_review_required'])
 def test_alias_replan_signalled(self):
  t,vr,c,p=fixture();r=review_target_preferences(info(tags=BASE.replace('enUS','enGB')),CONFIG,t,vr,c);self.assertTrue(r['canonical_locale_replan_review_required']);self.assertEqual(r['profile']['text_locales'],['enGB'])
 def test_target_region_conflict_refused(self):
  t,vr,c,p=fixture('cn')
  with self.assertRaises(InvalidRelease):review_target_preferences(info(tags=BASE),CONFIG,t,vr,c)
 def test_inputs_not_modified(self):
  raw=info(tags=BASE);before=raw[:];r=inspect_preferences(raw,CONFIG);self.assertEqual(raw,before)
if __name__=='__main__':unittest.main()
