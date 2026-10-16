import os,random,unittest
from pathlib import Path
import agent_value_range as v
import patch_audit as a
ORACLE=Path(os.environ.get('VALUE_RANGE_ORACLE','/missing'))
class ValueModel(unittest.TestCase):
 def test_whole_extent_sentinel(self):self.assertEqual(v.model(0,v.MASK,480,188),{'valid':True,'length':188})
 def test_suffix_sentinel(self):self.assertEqual(v.model(30,v.MASK,480,188),{'valid':True,'length':158})
 def test_end_empty_allowed(self):self.assertTrue(v.model(188,0,480,188)['valid'])
 def test_start_past_extent(self):self.assertEqual(v.model(189,0,480,188),{'valid':False,'length':0})
 def test_range_past_extent(self):self.assertEqual(v.model(1,188,480,188),{'valid':False,'length':188})
 def test_bad_u64(self):
  for x in (-1,True,1<<64,None):
   with self.assertRaises(a.AuditError):v.model(x,0,0,188)
 def test_primitive_wrap_is_not_safe_policy(self):self.assertTrue(v.model(v.MASK,1,0,v.MASK)['valid']);self.assertFalse(v.strict_policy(v.MASK,1,0,v.MASK))
 def test_absolute_base_overflow_rejected_by_policy(self):self.assertTrue(v.model(0,188,v.MASK,188)['valid']);self.assertFalse(v.strict_policy(0,188,v.MASK,188))
 def test_base_not_read_by_primitive(self):self.assertEqual(v.model(30,158,0,188),v.model(30,158,v.MASK,188))

@unittest.skipUnless(ORACLE.is_file(),'original pure range validator oracle required')
class ValueNative(unittest.TestCase):
 def cmp(self,*args):return v.compare(ORACLE,*args)
 def test_real_span_range(self):
  for base in (480,668):self.assertEqual(self.cmp(0,v.MASK,base,188)['length'],188)
 def test_end_boundary(self):self.assertTrue(self.cmp(188,0,480,188)['valid'])
 def test_past_extent(self):self.assertFalse(self.cmp(189,0,480,188)['valid'])
 def test_past_end(self):self.assertFalse(self.cmp(30,159,480,188)['valid'])
 def test_sentinel_suffix(self):self.assertEqual(self.cmp(30,v.MASK,480,188)['length'],158)
 def test_wrap_bounded_observation(self):self.assertTrue(self.cmp(v.MASK,1,0,v.MASK)['valid'])
 def test_u64_random_and_boundaries(self):
  rng=random.Random(982472)
  for i in range(512):
   extent=rng.getrandbits(64);start=rng.choice((0,extent,extent//2,rng.getrandbits(64)));length=rng.choice((0,v.MASK,rng.getrandbits(64)));self.cmp(start,length,rng.getrandbits(64),extent)
