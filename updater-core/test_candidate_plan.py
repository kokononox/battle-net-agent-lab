import contextlib,dataclasses,io,json,random,tempfile,unittest
from pathlib import Path
from test_build_catalogue import fixture
from build_catalogue import build
from candidate_plan import build_candidate,reference_mask
from required_set import select_bitmap
from release_core import InvalidRelease
class Tests(unittest.TestCase):
 def case(self,root,v='19.1.0.99000'):
  b,o=fixture(root,v)
  with contextlib.redirect_stdout(io.StringIO()):build(b,o)
  return b,o
 def test_dynamic_candidate(self):
  with tempfile.TemporaryDirectory()as d:
   r=Path(d);b,o=self.case(r);p=build_candidate(b,o,r/'plan','Windows');self.assertEqual(p['selected_install_paths'],1);self.assertEqual(p['selected_download_objects'],1);self.assertTrue(p['independent_per_bit_reference_agrees']);self.assertFalse(p['required_set_selected']);self.assertIsNone(p['required_network_download_bytes'])
 def test_other_version_same_code(self):
  with tempfile.TemporaryDirectory()as d:
   r=Path(d);b,o=self.case(r,'20.0.0.100001');self.assertEqual(build_candidate(b,o,r/'plan','Windows')['target']['version'],'20.0.0.100001')
 def test_tampered_catalogue(self):
  with tempfile.TemporaryDirectory()as d:
   r=Path(d);b,o=self.case(r);p=o/'TARGET-CATALOGUE.sqlite';data=p.read_bytes();p.write_bytes(data[:-1]+bytes([data[-1]^1]))
   with self.assertRaises(InvalidRelease):build_candidate(b,o,r/'plan','Windows')
   self.assertFalse((r/'plan').exists())
 def test_tampered_manifest(self):
  with tempfile.TemporaryDirectory()as d:
   r=Path(d);b,o=self.case(r);p=o/'install.decoded';p.write_bytes(p.read_bytes()[:-1]+b'x')
   with self.assertRaises(InvalidRelease):build_candidate(b,o,r/'plan','Windows')
 def test_target_disagreement(self):
  with tempfile.TemporaryDirectory()as d:
   r=Path(d);b,o=self.case(r);p=o/'CATALOGUE-VERIFIED-to-share.json';v=json.loads(p.read_bytes());v['target']['version']='99.0.0.999';p.write_text(json.dumps(v))
   with self.assertRaises(InvalidRelease):build_candidate(b,o,r/'plan','Windows')
 def test_existing_output_not_replaced(self):
  with tempfile.TemporaryDirectory()as d:
   r=Path(d);b,o=self.case(r);(r/'plan').mkdir()
   with self.assertRaises(InvalidRelease):build_candidate(b,o,r/'plan','Windows')
 def test_missing_tag_stops_before_output(self):
  with tempfile.TemporaryDirectory()as d:
   r=Path(d);b,o=self.case(r)
   with self.assertRaises(InvalidRelease):build_candidate(b,o,r/'plan','Linux')
   self.assertFalse((r/'plan').exists())
 def test_independent_bitmap_reference_randomized(self):
  rng=random.Random(714)
  for n in range(1,130):
   tags=[(i,c,i+1,rng.randbytes((n+7)//8))for i,c in enumerate('ABCD')];expr='A B: C D? missing?';self.assertEqual(select_bitmap(tags,n,expr)[0],reference_mask(tags,n,expr))
if __name__=='__main__':unittest.main()
