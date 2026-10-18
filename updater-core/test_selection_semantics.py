"""Regression of concrete semantic disagreements; not official-client tests."""
import copy,hashlib,unittest
from release_core import InvalidRelease
from selection_policy import review_tags,compile_profile,tag_table
from required_set import select_bitmap
from selection_semantics import discriminate

def fixture():
 # Four rows: enUS/text, enUS/speech, deDE/text, deDE/speech.
 names=[('Windows',1,0xf0),('x86_64',2,0xf0),('EU',4,0xf0),('enUS',3,0xc0),('deDE',3,0x30),('text',5,0xa0),('speech',5,0x50),('Alternate',16384,0x80),('Talebound',16384,0x40)]
 tags=[(i,n,k,bytes([b]))for i,(n,k,b)in enumerate(names)]
 p=dict(platform='Windows',architecture='x86_64',region='EU',text_locales=['enUS'],speech_locales=['deDE']);return tags,p
class Cases(unittest.TestCase):
 def run_review(self,tags=None,p=None):
  t,q=fixture();tags=t if tags is None else tags;p=q if p is None else p
  expression,_=compile_profile(p,tag_table(tags,4));mask,_=select_bitmap(tags,4,expression);return discriminate(tags,4,p,mask)
 def test_cross_pairing_counterexample(self):
  r=self.run_review();self.assertEqual(r['paired_candidate']['records'],2);self.assertEqual(r['grouped_hypothesis']['records'],4);self.assertEqual(r['grouped_only']['earliest_ordinals'],[1,2])
 def test_single_locale_agreement_never_qualifies(self):
  t,p=fixture();p['speech_locales']=['enUS'];r=self.run_review(t,p);self.assertTrue(r['grouping_hypotheses_agree_for_this_input']);self.assertFalse(r['agreement_qualifies_vendor_policy']);self.assertFalse(r['promotion_to_required_set_permitted'])
 def test_member_or_untagged_is_not_strict_membership(self):
  r=self.run_review();a=r['opaque_kind_16384_hypotheses'][0];self.assertEqual(a['tag'],'Alternate');self.assertEqual(a['strict_membership']['records'],1);self.assertEqual(a['member_or_untagged_in_kind']['records'],3);self.assertEqual(a['exclude_this_tag']['records'],3)
 def test_unknown_required_dimension_no_all_selected(self):
  t,p=fixture();p['architecture']='unknown'
  with self.assertRaises(InvalidRelease):self.run_review(t,p)
 def test_no_profile_feature_guessing(self):
  t,p=fixture();p['Alternate']=False
  with self.assertRaises(InvalidRelease):self.run_review(t,p)
 def test_wrong_bitmap_rejected(self):
  t,p=fixture()
  with self.assertRaises(InvalidRelease):discriminate(t,4,p,b'\xf0')
 def test_integration_both_manifests_unchanged(self):
  t,p=fixture();before=copy.deepcopy(t);e,m,r=review_tags(t,4,t,4,p);self.assertEqual(m['install'],b'\x90');self.assertEqual(t,before)
  for name in ('install','download'):self.assertEqual(r['manifests'][name]['semantic_discrimination']['paired_candidate']['bitmap_sha256'],hashlib.sha256(m[name]).hexdigest())
 def test_padding_never_selected_even_dirty_source_tail(self):
  t,p=fixture();t=[(i,n,k,bytes([b[0]|15]))for i,n,k,b in t];r=self.run_review(t,p);self.assertEqual(r['grouped_hypothesis']['records'],4);self.assertEqual(r['grouped_hypothesis']['bitmap_sha256'],hashlib.sha256(b'\xf0').hexdigest())
 def test_independent_per_record_oracle(self):
  t,p=fixture();r=self.run_review(t,p);by={n:(k,b[0])for _,n,k,b in t};expected=[]
  for i in range(4):
   bit=128>>i
   common=all(by[n][1]&bit for n in ('Windows','x86_64','EU'))
   paired=bool(common and ((by['enUS'][1]&bit and by['text'][1]&bit)or(by['deDE'][1]&bit and by['speech'][1]&bit)))
   grouped=bool(common and any(by[n][1]&bit for n in ('enUS','deDE'))and any(by[n][1]&bit for n in ('text','speech')))
   if grouped and not paired:expected.append(i)
  self.assertEqual(expected,r['grouped_only']['earliest_ordinals'])
 def test_no_exhaustiveness_or_install_authority(self):
  r=self.run_review()
  for k in ('hypotheses_exhaustive','hypothesis_intersection_is_required_set','hypothesis_union_is_required_set','independent_reference_available','vendor_selection_policy_qualified','dependency_and_variant_policy_qualified','patch_route_policy_qualified','required_set_selected','installation_ready','apply_authorized'):self.assertFalse(r[k],k)
  self.assertIsNone(r['required_network_download_bytes'])
