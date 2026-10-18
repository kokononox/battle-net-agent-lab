import copy,hashlib,json,unittest
from pathlib import Path
from release_core import TargetSnapshot,Scope,InvalidRelease
from product_policy_facts import inspect_product_config

def fixture(region='eu',version='20.2.1.91234',mutate=None):
 c={'all':{'config':{'product':'WoW','update_method':'ngdp','shared_container_default_subfolder':'_retail_','supported_locales':['enUS','deDE','zhCN'],'replacement_locales':{'enGB':'enUS'},'enable_block_copy_patch':True}},'platform':{'win':{'config':{'tags':['Windows'],'tags_64bit':['x86_64'],'tags_arm64':['arm64']}}},'cn':{'config':{'extra_tags':['Alternate']}}}
 if mutate:mutate(c)
 raw=json.dumps(c,separators=(',',':')).encode();key=hashlib.md5(raw).hexdigest();bid=int(version.split('.')[-1]);vr=('Region|BuildConfig|CDNConfig|BuildId|VersionsName|ProductConfig\n'+f'{region}|'+('a'*32)+'|'+('b'*32)+f'|{bid}|{version}|{key}\n').encode()
 t=TargetSnapshot(Scope(region=region),version,bid,'a'*32,'b'*32,('https://cdn.blizzard.com',),hashlib.sha256(vr).hexdigest(),'c'*64)
 p={'platform':'Windows','architecture':'x86_64','region':region.upper(),'text_locales':['enUS'],'speech_locales':['enUS']}
 return t,vr,raw,p
class ProductFacts(unittest.TestCase):
 def test_bound_future_version_not_hardcoded(self):
  r=inspect_product_config(*fixture());self.assertTrue(r['release_table_and_content_key_bound']);self.assertEqual(r['target']['version'],'20.2.1.91234');self.assertFalse(r['installation_ready'])
 def test_no_extra_is_not_disabled(self):r=inspect_product_config(*fixture());self.assertEqual(r['applicable_explicit_extra_tag_declarations'],[]);self.assertFalse(r['absent_extra_tags_mean_disabled'])
 def test_cn_declaration_not_eu(self):self.assertEqual(inspect_product_config(*fixture('cn'))['applicable_explicit_extra_tag_declarations'],[{'source':'cn.config.extra_tags','tags':['Alternate']}])
 def test_zhcn_does_not_select_country(self):
  a=list(fixture());a[3]['text_locales']=['zhCN'];self.assertEqual(inspect_product_config(*a)['applicable_explicit_extra_tag_declarations'],[])
 def test_alias_explicitly_normalized(self):
  a=list(fixture());a[3]['text_locales']=['enGB'];r=inspect_product_config(*a);self.assertEqual(r['canonical_locale_facts']['text_locales'],['enUS']);self.assertEqual(r['profile_input']['text_locales'],['enGB'])
 def test_multi_locale_pairing_not_flattened(self):
  a=list(fixture());a[3]['speech_locales']=['deDE'];r=inspect_product_config(*a);self.assertEqual(r['canonical_locale_facts'],{'text_locales':['enUS'],'speech_locales':['deDE']})
 def test_unknown_locale(self):
  a=list(fixture());a[3]['text_locales']=['xxXX']
  with self.assertRaises(InvalidRelease):inspect_product_config(*a)
 def test_cycle_even_when_alias_unused(self):
  a=fixture(mutate=lambda c:c['all']['config']['replacement_locales'].update({'a':'b','b':'a'}))
  with self.assertRaises(InvalidRelease):inspect_product_config(*a)
 def test_alias_destination_unsupported(self):
  with self.assertRaises(InvalidRelease):inspect_product_config(*fixture(mutate=lambda c:c['all']['config']['replacement_locales'].update({'x':'xxXX'})))
 def test_version_bytes_changed(self):
  a=list(fixture());a[1]+=b'\n'
  with self.assertRaises(InvalidRelease):inspect_product_config(*a)
 def test_config_bytes_changed(self):
  a=list(fixture());a[2]+=b'\n'
  with self.assertRaises(InvalidRelease):inspect_product_config(*a)
 def test_target_disagrees_with_bound_row(self):
  a=list(fixture());t=a[0];d=t.public();d['build_config']='d'*32;a[0]=TargetSnapshot.restore(d)
  with self.assertRaises(InvalidRelease):inspect_product_config(*a)
 def test_duplicate_region_row(self):
  a=list(fixture());a[1]+=a[1].splitlines(keepends=True)[1];d=a[0].public();d['versions_sha256']=hashlib.sha256(a[1]).hexdigest();a[0]=TargetSnapshot.restore(d)
  with self.assertRaises(InvalidRelease):inspect_product_config(*a)
 def test_profile_scope(self):
  a=list(fixture());a[3]['region']='US'
  with self.assertRaises(InvalidRelease):inspect_product_config(*a)
 def test_architecture_derived_not_assumed(self):
  a=list(fixture());a[3]['architecture']='arm64';self.assertEqual(inspect_product_config(*a)['windows_architecture_tags'],['arm64'])
 def test_missing_architecture_mapping(self):
  with self.assertRaises(InvalidRelease):inspect_product_config(*fixture(mutate=lambda c:c['platform']['win']['config'].pop('tags_64bit')))
 def test_unknown_layout(self):
  with self.assertRaises(InvalidRelease):inspect_product_config(*fixture(mutate=lambda c:c['all']['config'].update({'update_method':'other'})))
 def test_duplicate_tokens(self):
  with self.assertRaises(InvalidRelease):inspect_product_config(*fixture(mutate=lambda c:c['platform']['win']['config'].update({'tags':['Windows','Windows']})))
 def test_locale_extra_declaration(self):
  r=inspect_product_config(*fixture(mutate=lambda c:c.update({'enus':{'config':{'extra_tags':['FutureFeature']}}})));self.assertEqual(r['applicable_explicit_extra_tag_declarations'][0]['tags'],['FutureFeature']);self.assertFalse(r['feature_selection_semantics_qualified'])
 def test_actions_are_never_interpreted(self):
  a=fixture(mutate=lambda c:c['platform']['win']['config'].update({'install':[{'delete_folder':{'root':'%game%'}}]}));r=inspect_product_config(*a);self.assertFalse(r['install_uninstall_actions_interpreted']);self.assertFalse(r['external_paths_used'])
 def test_no_authority_from_config(self):
  r=inspect_product_config(*fixture(mutate=lambda c:c.update({'apply_authorized':True,'required_set_selected':True})));self.assertFalse(r['apply_authorized']);self.assertFalse(r['required_set_selected'])
 def test_no_input_mutation(self):
  a=fixture();before=copy.deepcopy(a);inspect_product_config(*a);self.assertEqual(a,before)
 def test_historical_public_fixture(self):
  d=Path(__file__).parent/'research/fixtures';vr=(d/'versions-70448.txt').read_bytes();raw=(d/'product-config-53020d32.json').read_bytes();bid=70448;t=TargetSnapshot(Scope(),f'12.1.5.{bid}',bid,'88d5e8ef05ec5a8446cdec93d142d7c6','f065eade5276a5ac05606e60a4c5a1f7',('https://cdn.blizzard.com',),hashlib.sha256(vr).hexdigest(),'d'*64);r=inspect_product_config(t,vr,raw,fixture()[3]);self.assertEqual(r['product_config_key'],'53020d32e1a25648c8e1eafd5771935f');self.assertEqual(r['product_config_bytes'],15764);self.assertEqual(r['replacement_locales']['enGB'],'enUS');self.assertFalse(r['vendor_selection_policy_qualified'])
class CandidateIntegration(unittest.TestCase):
 def test_candidate_identity_gate_is_used(self):
  from unittest.mock import patch
  from product_policy_facts import review_candidate_product_facts
  t,vr,raw,p=fixture();receipt={'target':t.public(),'candidate_database_sha256':'f'*64,'source_metadata_sha256':{'install':'e'*64}}
  with patch('selection_policy.review_existing_candidate',return_value=receipt)as gate:
   r=review_candidate_product_facts('base','objects','plan',p,vr,raw)
  gate.assert_called_once_with('base','objects','plan',p);self.assertTrue(r['existing_candidate_identity_reverified']);self.assertFalse(r['candidate_plan_modified']);self.assertFalse(r['promotion_to_required_set_permitted'])
 def test_candidate_failure_not_bypassed(self):
  from unittest.mock import patch
  from product_policy_facts import review_candidate_product_facts
  with patch('selection_policy.review_existing_candidate',side_effect=InvalidRelease('identity_failed')):
   with self.assertRaises(InvalidRelease):review_candidate_product_facts(None,None,None,None,None,None)
 def test_alias_change_flags_replan_not_mutation(self):
  from unittest.mock import patch
  from product_policy_facts import review_candidate_product_facts
  t,vr,raw,p=fixture();p['text_locales']=['enGB'];receipt={'target':t.public(),'candidate_database_sha256':'f'*64,'source_metadata_sha256':{}}
  with patch('selection_policy.review_existing_candidate',return_value=receipt):r=review_candidate_product_facts(None,None,None,p,vr,raw)
  self.assertTrue(r['locale_alias_replan_review_required']);self.assertFalse(r['candidate_plan_modified'])
if __name__=='__main__':unittest.main()
