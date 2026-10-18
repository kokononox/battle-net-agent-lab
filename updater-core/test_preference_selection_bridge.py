import copy,json,unittest
from unittest.mock import patch
from release_core import InvalidRelease
from test_installed_identity import info,CONFIG
from test_installed_preferences import BASE
from test_selection_policy import tags
import test_selection_policy as selection_fixtures
from preference_selection_bridge import review_preference_tags,review_preference_candidate
from test_product_policy_facts import fixture

def ts_without(names):return [(i,n,k,b)for i,(o,n,k,b)in enumerate(t for t in tags()if t[1]not in names)]
class BridgePure(unittest.TestCase):
 def r(self,text=BASE,it=None,dt=None):
  it=tags()if it is None else it;dt=it if dt is None else dt
  return review_preference_tags(info(tags=text),CONFIG,it,8,dt,8)
 def test_observed_optional_markers_kept(self):
  m,r=self.r();self.assertEqual(r['manifests']['install']['expression'],BASE);self.assertEqual(m['install'],b'\xa0')
 def test_strict_model_agrees_when_all_public_tags_present(self):
  m,r=self.r();self.assertTrue(r['manifests']['download']['strict_profile_comparison']['same_bitmap'])
 def test_different_text_speech_locales(self):
  m,r=self.r('Windows x86_64 EU? deDE speech?:Windows x86_64 EU? enUS text?');self.assertEqual(m['install'],b'\x60')
 def test_text_only(self):self.assertEqual(self.r('Windows x86_64 EU? enUS text?')[0]['install'],b'\x20')
 def test_speech_only(self):self.assertEqual(self.r('Windows x86_64 EU? enUS speech?')[0]['install'],b'\x80')
 def test_multiple_text_locales_not_cross_product(self):self.assertEqual(self.r(BASE+':Windows x86_64 EU? deDE text?')[0]['install'],b'\xb0')
 def test_missing_optional_category_is_reported_not_mandatory(self):
  m,r=self.r(it=ts_without({'speech'}));self.assertEqual(m['install'],b'\xa0');self.assertFalse(r['manifests']['install']['strict_profile_comparison_available']);self.assertEqual(r['manifests']['install']['optional_public_dimensions_absent'][0]['name'],'speech')
 def test_missing_optional_region_no_strict_fallback(self):
  m,r=self.r(it=ts_without({'EU'}));self.assertEqual(m['install'],b'\xa0');self.assertIsNone(r['manifests']['install']['strict_profile_comparison'])
 def test_missing_mandatory_category_refused(self):
  with self.assertRaises(InvalidRelease):self.r(BASE.replace('speech?','speech'),it=ts_without({'speech'}))
 def test_missing_mandatory_locale_refused(self):
  with self.assertRaises(InvalidRelease):self.r(it=ts_without({'enUS'}))
 def test_missing_platform_refused(self):
  with self.assertRaises(InvalidRelease):self.r(it=ts_without({'Windows'}))
 def test_optional_known_wrong_kind_not_ignored(self):
  it=tags();it[3]=(3,'EU',16384,b'\xff')
  with self.assertRaises(InvalidRelease):self.r(it=it)
 def test_private_absent_qualifiers_withheld(self):
  m,r=self.r(BASE.replace('speech?','speech? acct-SECRET? geoip-PRIVATE?'));self.assertEqual(r['private_optional_qualifiers_withheld'],2);self.assertNotIn('SECRET',json.dumps(r));self.assertNotIn('PRIVATE',json.dumps(r))
 def test_private_present_install_must_stop_no_echo(self):
  it=tags()+[(9,'acct-SECRET',16384,b'\x80')]
  with self.assertRaisesRegex(InvalidRelease,'^bridge_private_qualifier_present_in_manifest$'):self.r(BASE.replace('speech?','speech? acct-SECRET?'),it=it,dt=tags())
 def test_private_present_download_must_stop(self):
  dt=tags()+[(9,'geoip-SECRET',16384,b'\x80')]
  with self.assertRaises(InvalidRelease):self.r(BASE.replace('text?','text? geoip-SECRET?'),dt=dt)
 def test_different_optional_availability_between_manifests(self):
  m,r=self.r(it=ts_without({'speech'}),dt=tags());self.assertFalse(r['manifests']['install']['strict_profile_comparison_available']);self.assertTrue(r['manifests']['download']['strict_profile_comparison_available'])
 def test_duplicate_public_clauses_fail(self):
  with self.assertRaises(InvalidRelease):self.r('Windows x86_64 EU? enUS text?:Windows x86_64 EU? enUS text?')
 def test_private_difference_does_not_hide_duplicate_public_clause(self):
  with self.assertRaises(InvalidRelease):self.r('Windows x86_64 EU? enUS text? acct-A?:Windows x86_64 EU? enUS text? acct-B?')
 def test_unknown_feature_preference_fails(self):
  with self.assertRaises(ValueError):self.r(BASE+' HighRes?')
 def test_unused_unknown_kind_refused(self):
  with self.assertRaises(InvalidRelease):self.r(it=tags()+[(9,'FutureTag',900,b'\0')])
 def test_bad_geometry_refused(self):
  it=tags();it[0]=(0,'Windows',1,b'\xff\xff')
  with self.assertRaises(InvalidRelease):self.r(it=it)
 def test_padding_never_selected(self):
  it=[(i,n,k,b'\xff')for i,(o,n,k,b)in enumerate(tags())];m,r=review_preference_tags(info(tags=BASE),CONFIG,it,3,it,3);self.assertEqual(m['install'],b'\xe0')
 def test_unknown_architecture_mapping_no_implicit_conversion(self):
  with self.assertRaises(InvalidRelease):self.r(BASE.replace('x86_64','ARM64'))
 def test_no_input_mutation(self):
  it=tags();before=copy.deepcopy(it);self.r(it=it);self.assertEqual(it,before)
 def test_metadata_config_identity_gate(self):
  with self.assertRaises(ValueError):review_preference_tags(info(tags=BASE),CONFIG+b'bad',tags(),8,tags(),8)
 def test_no_live_required_set_or_authority(self):
  r=self.r()[1]
  for k in ('fresh_installed_preferences_proven','active_generation_proven','vendor_selection_policy_qualified','required_set_selected','promotion_to_required_set_permitted','candidate_plan_modified','game_access','installation_ready','apply_authorized'):self.assertFalse(r[k])
  self.assertIsNone(r['required_network_download_bytes']);self.assertEqual(r['network_requests'],0)

# Reuse setup, not inherited tests (avoid silently duplicating old test counts).
class BridgeIntegration(unittest.TestCase):
 def setUp(self):
  import tempfile,hashlib,contextlib,io
  from pathlib import Path
  from test_build_catalogue import fixture as catalogue_fixture
  from build_catalogue import build
  from candidate_plan import build_candidate
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  original=tags()
  with patch('test_selection_policy.tags',return_value=original+[(9,'enGB',3,b'\xff')]),patch('test_build_catalogue.install',selection_fixtures.full_install),patch('test_build_catalogue.download',selection_fixtures.full_download):
   self.base,self.objects=catalogue_fixture(self.root)
  path=self.objects/'METADATA-VERIFIED-to-share.json';receipt=json.loads(path.read_bytes());t=receipt['target']
  self.product=fixture(version=t['version'])[2];key=hashlib.md5(self.product).hexdigest()
  self.versions=(f"Region|BuildConfig|CDNConfig|BuildId|VersionsName|ProductConfig\neu|{t['build_config']}|{t['cdn_config']}|{t['build_id']}|{t['version']}|{key}\n").encode()
  # Build a consistently bound synthetic lineage BEFORE producing catalogue/plan.
  t['versions_sha256']=hashlib.sha256(self.versions).hexdigest();path.write_text(json.dumps(receipt))
  with contextlib.redirect_stdout(io.StringIO()):build(self.base,self.objects)
  self.plan=self.root/'plan';build_candidate(self.base,self.objects,self.plan,'Windows x86_64 EU enUS speech:Windows x86_64 EU enUS text')
 def run_bridge(self,text=BASE,config=CONFIG,versions=None,product=None):
  return review_preference_candidate(self.base,self.objects,self.plan,info(tags=text),config,self.versions if versions is None else versions,self.product if product is None else product)
 def test_full_candidate_gate_and_bitmaps(self):
  r=self.run_bridge();self.assertTrue(r['existing_candidate_identity_reverified']);self.assertTrue(r['existing_candidate_bitmaps_unchanged']);self.assertEqual(r['target']['version'],'19.1.0.99000')
 def test_plan_tamper_cannot_bypass(self):
  p=self.plan/'CANDIDATE-PLAN.sqlite';p.write_bytes(p.read_bytes()+b'bad')
  with self.assertRaises(InvalidRelease):self.run_bridge()
 def test_catalogue_tamper_cannot_bypass(self):
  p=self.objects/'TARGET-CATALOGUE.sqlite';p.write_bytes(p.read_bytes()+b'bad')
  with self.assertRaises(InvalidRelease):self.run_bridge()
 def test_alias_requires_replan(self):
  with self.assertRaisesRegex(InvalidRelease,'bridge_locale_alias_replan_required'):self.run_bridge(BASE.replace('enUS','enGB'))
 def test_product_hash_mismatch_refused(self):
  with self.assertRaises(InvalidRelease):self.run_bridge(versions=b'wrong',product=b'{}')
 def test_no_plan_writes(self):
  before={p.name:p.read_bytes()for p in self.plan.iterdir()};self.run_bridge();self.assertEqual(before,{p.name:p.read_bytes()for p in self.plan.iterdir()})
if __name__=='__main__':unittest.main()
