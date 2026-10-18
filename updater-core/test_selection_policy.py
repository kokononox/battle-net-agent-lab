import contextlib,copy,io,json,struct,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from selection_policy import normalize_profile,review_tags,review_existing_candidate
from release_core import InvalidRelease
from test_catalogue_readers import CK,EK
from test_build_catalogue import fixture
from build_catalogue import build
from candidate_plan import build_candidate

PROFILE={'platform':'Windows','architecture':'x86_64','region':'EU','text_locales':['enUS'],'speech_locales':['enUS']}
def tags():
 return [(i,n,k,b)for i,(n,k,b)in enumerate([('Windows',1,b'\xf0'),('OSX',1,b'\x0f'),('x86_64',2,b'\xff'),('EU',4,b'\xff'),('enUS',3,b'\xaa'),('deDE',3,b'\x55'),('speech',5,b'\xcc'),('text',5,b'\x33'),('HighRes',16384,b'\x80')])]
def review(ts=None,p=None):
 ts=tags()if ts is None else ts
 return review_tags(ts,8,ts,8,PROFILE if p is None else p)
class Pure(unittest.TestCase):
 def test_typed_expression(self):
  e,m,r=review();self.assertEqual(e,'Windows x86_64 EU enUS speech:Windows x86_64 EU enUS text');self.assertEqual(m['install'],b'\xa0');self.assertFalse(r['promotion_to_required_set_permitted'])
 def test_feature_intersection_is_not_preference(self):
  r=review()[2];f=r['manifests']['download']['unresolved_feature_tags'][0];self.assertEqual((f['selected_members'],f['selected_nonmembers']),(1,1));self.assertFalse(f['meaning_and_preference_qualified'])
 def test_speech_locale_not_cross_product_with_text(self):
  p=copy.deepcopy(PROFILE);p['speech_locales']=['deDE'];e,m,r=review(p=p);self.assertEqual(m['install'],b'\x60');self.assertNotIn('enUS speech',e);self.assertNotIn('deDE text',e)
 def test_multiple_text_locales(self):
  p=copy.deepcopy(PROFILE);p['text_locales']=['deDE','enUS'];e,m,r=review(p=p);self.assertEqual(m['install'],b'\xb0')
 def test_text_only(self):
  p=copy.deepcopy(PROFILE);p['speech_locales']=[];self.assertEqual(review(p=p)[1]['install'],b'\x20')
 def test_speech_only(self):
  p=copy.deepcopy(PROFILE);p['text_locales']=[];self.assertEqual(review(p=p)[1]['install'],b'\x80')
 def test_empty_locales(self):
  p=copy.deepcopy(PROFILE);p['text_locales']=[];p['speech_locales']=[]
  with self.assertRaises(InvalidRelease):review(p=p)
 def test_private_or_authority_field_not_accepted(self):
  p=copy.deepcopy(PROFILE);p['apply_authorized']=True
  with self.assertRaises(InvalidRelease):review(p=p)
 def test_duplicate_locale(self):
  p=copy.deepcopy(PROFILE);p['text_locales']=['enUS','enUS']
  with self.assertRaises(InvalidRelease):review(p=p)
 def test_expression_injection(self):
  p=copy.deepcopy(PROFILE);p['platform']='Windows:OSX'
  with self.assertRaises(InvalidRelease):review(p=p)
 def test_no_optional_dimension(self):
  p=copy.deepcopy(PROFILE);p['region']='EU?'
  with self.assertRaises(InvalidRelease):review(p=p)
 def test_missing_dimension_stops(self):
  p=copy.deepcopy(PROFILE);p['architecture']='arm64'
  with self.assertRaises(InvalidRelease):review(p=p)
 def test_wrong_dimension_kind_stops(self):
  ts=tags();ts[2]=(2,'x86_64',3,b'\xff')
  with self.assertRaises(InvalidRelease):review(ts=ts)
 def test_unknown_kind_stops(self):
  ts=tags();ts[-1]=(8,'HighRes',900,b'\x80')
  with self.assertRaises(InvalidRelease):review(ts=ts)
 def test_manifest_schema_disagreement(self):
  ts=tags();ds=tags();ds[-1]=(8,'Other',16384,b'\x80')
  with self.assertRaises(InvalidRelease):review_tags(ts,8,ds,8,PROFILE)
 def test_duplicate_name_stops(self):
  ts=tags();ts[-1]=(8,'Windows',16384,b'\x80')
  with self.assertRaises(InvalidRelease):review(ts=ts)
 def test_wrong_bitmap_width(self):
  ts=tags();ts[0]=(0,'Windows',1,b'\xff\x00')
  with self.assertRaises(InvalidRelease):review(ts=ts)
 def test_no_feature_still_not_vendor_qualified(self):
  r=review(ts=tags()[:-1])[2];self.assertFalse(r['vendor_selection_policy_qualified']);self.assertFalse(r['required_set_selected']);self.assertIsNone(r['required_network_download_bytes'])
 def test_bool_locale_rejected(self):
  p=copy.deepcopy(PROFILE);p['text_locales']=[True]
  with self.assertRaises(InvalidRelease):review(p=p)
 def test_locale_order_canonical(self):
  p=copy.deepcopy(PROFILE);p['text_locales']=['enUS','deDE'];q=copy.deepcopy(p);q['text_locales'].reverse();self.assertEqual(normalize_profile(p),normalize_profile(q))

def full_install():
 ts=tags();tb=b''.join(n.encode()+b'\0'+k.to_bytes(2,'big')+b'\x80'for _,n,k,b in ts)
 return struct.pack('>2sBBHI',b'IN',1,16,len(ts),1)+tb+b'metadata-label\0'+CK+(5).to_bytes(4,'big')
def full_download():
 ts=tags();tb=b''.join(n.encode()+b'\0'+k.to_bytes(2,'big')+b'\x80'for _,n,k,b in ts)
 return b'DL\1\x10\0'+(1).to_bytes(4,'big')+len(ts).to_bytes(2,'big')+EK+(40).to_bytes(5,'big')+b'\0'+tb
class Integration(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  with patch('test_build_catalogue.install',full_install),patch('test_build_catalogue.download',full_download):self.base,self.objects=fixture(self.root)
  with contextlib.redirect_stdout(io.StringIO()):build(self.base,self.objects)
  self.plan=self.root/'plan';build_candidate(self.base,self.objects,self.plan,'Windows x86_64 EU enUS speech:Windows x86_64 EU enUS text')
 def run_review(self,p=None):return review_existing_candidate(self.base,self.objects,self.plan,PROFILE if p is None else p)
 def test_full_owned_chain(self):
  r=self.run_review();self.assertTrue(r['candidate_bitmaps_agree_with_typed_profile']);self.assertFalse(r['apply_authorized']);self.assertEqual(r['target']['version'],'19.1.0.99000')
 def test_plan_database_tamper(self):
  p=self.plan/'CANDIDATE-PLAN.sqlite';p.write_bytes(p.read_bytes()+b'bad')
  with self.assertRaises(InvalidRelease):self.run_review()
 def test_catalogue_database_tamper(self):
  p=self.objects/'TARGET-CATALOGUE.sqlite';p.write_bytes(p.read_bytes()+b'bad')
  with self.assertRaises(InvalidRelease):self.run_review()
 def test_metadata_tamper(self):
  p=self.objects/'install.decoded';raw=p.read_bytes();p.write_bytes(raw[:-1]+b'x')
  with self.assertRaises(InvalidRelease):self.run_review()
 def test_different_target_region(self):
  p=copy.deepcopy(PROFILE);p['region']='US'
  with self.assertRaises(InvalidRelease):self.run_review(p)
 def test_target_disagreement(self):
  p=self.objects/'CATALOGUE-VERIFIED-to-share.json';r=json.loads(p.read_bytes());r['target']['version']='20.0.0.100001';p.write_text(json.dumps(r))
  with self.assertRaises(InvalidRelease):self.run_review()
 def test_fake_plan_bitmap_digest(self):
  p=self.plan/'CANDIDATE-PLAN-to-share.json';r=json.loads(p.read_bytes());r['install_selection']['bitmap_sha256']='0'*64;p.write_text(json.dumps(r))
  with self.assertRaises(InvalidRelease):self.run_review()
 def test_no_plan_writes(self):
  before={p.name:p.read_bytes()for p in self.plan.iterdir()};self.run_review();self.assertEqual(before,{p.name:p.read_bytes()for p in self.plan.iterdir()})
if __name__=='__main__':unittest.main()
