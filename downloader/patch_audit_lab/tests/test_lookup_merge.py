import os,random,unittest
from pathlib import Path
import agent_lookup_merge as m
import agent_bind_contract as b
import patch_audit as a
K='914fcad4f4fcf4abb0ba52b197bb066f';R=b.record(K,480,188);ORACLE=Path(os.environ.get('LOOKUP_MERGE_ORACLE','/missing'))
class LookupPolicy(unittest.TestCase):
 def run_model(self,primary=None,tail=(),start=0,length=m.MASK):return m.predict(m.build_index([R] if primary is None else primary,list(tail),5),5,K,start,length)['lookup']
 def test_primary_whole(self):self.assertEqual(self.run_model()['range'],[480,188])
 def test_suffix(self):self.assertEqual(self.run_model(start=30)['range'],[510,158])
 def test_empty_at_end(self):self.assertEqual(self.run_model(start=188,length=0)['status'],0)
 def test_missing(self):self.assertEqual(self.run_model(primary=[])['status'],2)
 def test_bad_relative_range(self):self.assertEqual(self.run_model(start=189)['status'],4)
 def test_tail_delete(self):self.assertEqual(self.run_model(tail=[(R,3)])['status'],2)
 def test_tail_hole(self):self.assertEqual(self.run_model(tail=[(b.record(K,500,20),7)])['status'],3)
 def test_tail_only_set(self):self.assertEqual(self.run_model(primary=[],tail=[(R,1)])['range'],[480,188])
 def test_base_descriptor_without_coverage(self):self.assertEqual(self.run_model(primary=[],tail=[(R,2)])['status'],3)
 def test_inline_capacity_rejected(self):
  with self.assertRaises(a.AuditError):self.run_model(primary=[R]*8)
 def test_wrapping_value_rejected(self):
  with self.assertRaises(a.AuditError):self.run_model(primary=[b.record(K,m.MASK,2)])
 def test_wrapping_request_rejected(self):
  with self.assertRaises(a.AuditError):self.run_model(start=m.MASK,length=2)
 def test_invalid_tail_flag(self):
  with self.assertRaises(a.AuditError):m.build_index([],[ (R,8) ],5)
 def test_coverage_sweep(self):self.assertEqual(m.merge([(480,1),(668,-1),(500,-0x40000000),(520,0x40000000)]),[(480,1),(500,-1),(520,1),(668,-1)])

@unittest.skipUnless(ORACLE.is_file(),'original bounded lookup/iterator/merge oracle required')
class LookupNative(unittest.TestCase):
 def cmp(self,primary=None,tail=(),start=0,length=m.MASK,bucket=5,query=K,map_error=0):return m.compare(ORACLE,m.build_index([R] if primary is None else primary,list(tail),bucket),bucket,query,start,length,map_error)['lookup']
 def test_primary_whole(self):self.assertEqual(self.cmp()['range'],[480,188])
 def test_all_buckets(self):
  for i in range(16):self.assertEqual(self.cmp(bucket=i)['status'],0)
 def test_suffix(self):self.assertEqual(self.cmp(start=30)['range'],[510,158])
 def test_no_key(self):self.assertEqual(self.cmp(query='00'*16)['status'],2)
 def test_outside_extent(self):self.assertEqual(self.cmp(start=189)['status'],4)
 def test_empty_boundary(self):self.assertEqual(self.cmp(start=188,length=0)['status'],0)
 def test_tail_only(self):self.assertEqual(self.cmp(primary=[],tail=[(R,1)])['value'],[480,188])
 def test_all_seven_operations(self):
  for flag in range(1,8):self.cmp(tail=[(R,flag)])
 def test_tail_overrides_primary_base(self):self.assertEqual(self.cmp(tail=[(b.record(K,668,188),1)])['range'],[668,188])
 def test_clear_removes_presence(self):self.assertEqual(self.cmp(tail=[(R,3)])['status'],2)
 def test_tail_hole_rejects_whole(self):self.assertEqual(self.cmp(tail=[(b.record(K,500,20),7)])['status'],3)
 def test_hole_allows_covered_prefix(self):self.assertEqual(self.cmp(tail=[(b.record(K,500,20),7)],length=20)['status'],0)
 def test_hole_allows_covered_suffix(self):self.assertEqual(self.cmp(tail=[(b.record(K,500,20),7)],start=40)['status'],0)
 def test_hole_refilled(self):self.assertEqual(self.cmp(tail=[(b.record(K,500,20),7),(b.record(K,500,20),6)])['status'],0)
 def test_duplicates_descriptor_plus_coverage(self):self.assertEqual(self.cmp(primary=[R,R])['status'],0)
 def test_duplicates_gapped_coverage(self):self.assertEqual(self.cmp(primary=[R,b.record(K,480,20),b.record(K,520,148)])['status'],3)
 def test_same9_different16(self):
  other=K[:18]+'00'*7;rows=[R,b.record(other,668,188)];self.assertEqual(self.cmp(primary=rows,query=other)['range'],[668,188])
 def test_tail_across_pages_nonmatching_skipped(self):
  tail=[(b.record('22'*16,100+i,1),1) for i in range(26)]+[(R,1)];self.assertEqual(self.cmp(primary=[],tail=tail)['status'],0)
 def test_mapping_failure_does_not_claim_lookup(self):self.assertFalse(self.cmp(map_error=73)['performed'])
 def test_all_inline_capacity_seven_matches(self):self.assertEqual(self.cmp(primary=[R],tail=[(R,6)]*6)['status'],0)
 def test_256_deterministic_combinations(self):
  rng=random.Random(982473)
  for i in range(256):
   primary=[R] if rng.randrange(2) else [];tail=[(b.record(K,rng.randrange(450,730),rng.randrange(70)),rng.randrange(1,8)) for j in range(rng.randrange(7-len(primary)+1))];self.cmp(primary,tail,rng.randrange(220),rng.choice((0,m.MASK,1,30,100)))
