"""Owned byte fixtures, decoded as data; NO machine code is executed."""
import unittest
from reachability import walk,truth,UNKNOWN
class ModelTests(unittest.TestCase):
 def run_bytes(self,h,cap=10000):
  b=bytes.fromhex(h);base=0x1000
  def read(a,n):
   assert base<=a and a+n<=base+len(b)
   return b[a-base:a-base+n]
  return walk(read,base,base+len(b),cap)
 def test_unknown_conditional_remains_unknown(self):
  for j in ['je','jne','ja','jbe','jg','jle','jp']:self.assertIsNone(truth(j,UNKNOWN))
 def test_complementary_pair_skips_embedded_reference(self):
  r,n=self.run_bytes('740a7508488d050000000090c3');self.assertTrue(r['closed_under_stated_model']);self.assertEqual(r['normalized_complementary_pairs'],1);self.assertNotIn(0x1004,n)
 def test_zero_xor_drops_impossible_jne(self):
  r,n=self.run_bytes('31c07502c3900f0b');self.assertTrue(r['closed_under_stated_model']);self.assertNotIn(0x1006,n)
 def test_test_clears_carry(self):
  r,n=self.run_bytes('85c07202c3900f0b');self.assertTrue(r['closed_under_stated_model']);self.assertNotIn(0x1006,n)
 def test_stc_takes_carry_branch(self):
  r,n=self.run_bytes('f972020f0bc3');self.assertTrue(r['closed_under_stated_model']);self.assertNotIn(0x1003,n)
 def test_call_loses_known_flags(self):
  r,n=self.run_bytes('31c0e8000000007401c30f0b');self.assertFalse(r['closed_under_stated_model']);self.assertIn(0x100a,n)
 def test_overlap_not_accepted(self):
  r,n=self.run_bytes('74014889c0c3');self.assertFalse(r['closed_under_stated_model']);self.assertTrue(r['overlapping_instruction_pairs'])
 def test_indirect_exit_not_closed(self):
  r,n=self.run_bytes('ffe0');self.assertFalse(r['closed_under_stated_model']);self.assertEqual(r['indirect_jumps'],[0x1000])
 def test_bad_decode_not_closed(self):
  r,n=self.run_bytes('0f');self.assertFalse(r['closed_under_stated_model']);self.assertEqual(r['bad_decode_rvas'],[0x1000])
 def test_budget_stop_not_closed(self):
  r,n=self.run_bytes('909090c3',cap=2);self.assertFalse(r['closed_under_stated_model']);self.assertTrue(r['budget_exhausted'])
 def test_external_direct_jump_not_closed(self):
  r,n=self.run_bytes('e900100000');self.assertFalse(r['closed_under_stated_model']);self.assertTrue(r['outside_range_successors'])
 def test_shift_zero_preserves_flags(self):
  r,n=self.run_bytes('f9c1e00072020f0bc3');self.assertTrue(r['closed_under_stated_model']);self.assertNotIn(0x1006,n)
 def test_complementary_different_targets_cannot_fall_through(self):
  r,n=self.run_bytes('720c88db7309488d0500000000c3c3c3');self.assertTrue(r['closed_under_stated_model']);self.assertNotIn(0x1006,n)
 def test_repeated_jbe_preserves_cf_zf_correlation(self):
  # First JBE taken -> second identical JBE must be taken; fallthrough LEA is impossible.
  r,n=self.run_bytes('7601c37608488d0500000000c3c3');self.assertTrue(r['closed_under_stated_model']);self.assertNotIn(0x1005,n)
 def test_fpu_metadata_never_inferred_as_integer_flags(self):
  r,n=self.run_bytes('f9d9e872020f0bc3');self.assertFalse(r['closed_under_stated_model']);self.assertIn(0x1005,n)
if __name__=='__main__':unittest.main(verbosity=2)
