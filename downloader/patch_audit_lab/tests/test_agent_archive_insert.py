import hashlib,json,os,tempfile,unittest
from pathlib import Path
import agent_archive_insert as n
import agent_archive_cache as prior
import agent_static_audit as identity
import patch_audit as a
ORACLE=Path(os.environ['ARCHIVE_INSERT_ORACLE']).resolve()
class InsertTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.p=Path(self.tmp.name).resolve();(self.p/n.MARKER).write_text(json.dumps({'format':'archive-insert-owned-fixture-1'}))
  for ar in [0,3,4,1022]:(self.p/f'data.{ar:03d}').write_bytes(bytes((i*17+ar)%256 for i in range(2048)))
  self.before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.p.iterdir()}
 def tearDown(self):
  self.assertEqual(self.before,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.p.iterdir()});self.tmp.cleanup()
 def run_case(self,ads=[480,668,480,668],length=188,**kw):return n.compare(ORACLE,self.p,ads,length,**kw)
 def test_single_miss(self):
  r=self.run_case([480]);self.assertEqual((r[0][0]['create_calls'],r[0][0]['constructor_calls']),(1,1))
 def test_reuse_after_miss(self):
  r=self.run_case();self.assertEqual([x['create_calls'] for x,_ in r],[1]*4)
 def test_original_cache_reference(self):
  for x,_ in self.run_case():self.assertEqual((x['new_reference_during_read'],x['new_reference_after']),(2,1))
 def test_two_archives_alternating(self):
  r=self.run_case([480,(3<<30)+480,668,(3<<30)+668]);self.assertEqual([x['constructor_calls'] for x,_ in r],[1,2,2,2])
 def test_four_archives(self):self.run_case([(ar<<30)+480 for ar in [0,3,4,1022]])
 def test_collision_chain_reuse(self):
  ar=next(ar for ar in range(1,1023) if prior.key_hash(0,0)&7==prior.key_hash(ar,0)&7)
  p=self.p/f'data.{ar:03d}'
  if not p.exists():p.write_bytes((self.p/'data.000').read_bytes());self.before[p.name]=hashlib.sha256(p.read_bytes()).hexdigest()
  r=self.run_case([480,(ar<<30)+480,668,(ar<<30)+668]);self.assertEqual([x['create_calls'] for x,_ in r],[1,2,2,2])
 def test_lru_moves_back(self):
  r=self.run_case([480,(3<<30)+480,668,(3<<30)+668]);self.assertEqual([x['list_head'] for x,_ in r],[0,1,0,1])
 def test_open_error2_then_retry(self):self.run_case(open_error=2,open_error_on=1)
 def test_open_error5_maps8_then_retry(self):self.assertEqual(self.run_case(open_error=5,open_error_on=1)[0][0]['status'],8)
 def test_open_error32_maps24(self):self.assertEqual(self.run_case(open_error=32,open_error_on=1)[0][0]['status'],24)
 def test_open_error_on_cache_hit_is_not_called(self):self.run_case(open_error=5,open_error_on=2)
 def test_second_archive_open_failure_keeps_first(self):self.run_case([480,(3<<30)+480,668,(3<<30)+668],open_error=5,open_error_on=2)
 def test_read_error_then_reuse(self):
  r=self.run_case(read_error=5,read_error_on=1);self.assertEqual([x['create_calls'] for x,_ in r],[1]*4)
 def test_read_error_third_only(self):self.run_case(read_error=5,read_error_on=3)
 def test_read_eof_success_is_not_exact(self):
  r=self.run_case(read_error=38,read_error_on=1)
  with self.assertRaises(a.AuditError):n.require_exact(r,188)
 def test_short_read_success_is_not_exact(self):
  r=self.run_case([2000],188);self.assertEqual(r[0][0]['status'],0)
  with self.assertRaises(a.AuditError):n.require_exact(r,188)
 def test_exact_read_accepted(self):n.require_exact(self.run_case(),188)
 def test_write_request_is_denied(self):self.assertEqual(self.run_case(mode=0)[0][0]['status'],8)
 def test_fast_read_share1(self):self.assertEqual(self.run_case(fast=1)[0][0]['share_mode'],1)
 def test_default_share7(self):self.assertEqual(self.run_case()[0][0]['share_mode'],7)
 def test_formatter_guard(self):self.run_case(format_override=780)
 def test_empty_read_no_open(self):self.run_case(length=0)
 def test_archive1023_rejected(self):self.run_case([(1023<<30)+480])
 def test_segment_boundary_rejected(self):self.run_case([(1<<30)-100],188)
 def test_missing_file_does_not_create(self):self.run_case([(999<<30)+480])
 def test_oversized_request_rejected(self):
  with self.assertRaises(Exception):self.run_case(length=4097)
 def test_too_many_reads_rejected(self):
  with self.assertRaises(a.AuditError):self.run_case([480]*5)
 def test_allocator_trap_not_success(self):
  with self.assertRaises(a.AuditError):self.run_case(allocation_trap_on=1)
 def test_symlink_rejected(self):
  p=self.p/'data.010';p.symlink_to(self.p/'data.000')
  try:
   with self.assertRaises(Exception):self.run_case([(10<<30)+480])
  finally:p.unlink()
 def test_unmarked_directory_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(Exception):n.native(ORACLE,Path(d).resolve(),[480],188)
 def test_wrong_marker_rejected(self):
  p=self.p/n.MARKER;p.write_text('{}')
  try:
   with self.assertRaises(a.AuditError):self.run_case()
  finally:p.write_text(json.dumps({'format':'archive-insert-owned-fixture-1'}))
if __name__=='__main__':unittest.main(verbosity=2)
