import json,os,random,tempfile,unittest
from pathlib import Path
import agent_archive_cache as c
import agent_archive_io as old
import source_binding as b
import patch_audit as a
import synthetic_casc_format as fmt
O=Path(os.environ.get('ARCHIVE_CACHE_ORACLE','/missing'));S=Path(os.environ.get('SPAN_READER_ORACLE','/missing'));P=Path(os.environ.get('SPAN_PRIOR_STORE','/missing'))
K='914fcad4f4fcf4abb0ba52b197bb066f';CK='98ad7b81687304aa0e99cf326200adfe';T='faedca88d0a0ab30dae5519239582d31';TC='3d42bf2e42127f313b0ec64cb440cde9'
class Policy(unittest.TestCase):
 def test_mix_zero(self):self.assertEqual(c.mix32(0),0)
 def test_hash_zero(self):self.assertEqual(c.key_hash(0,0),0x9e3779b9)
 def test_flag_changes_hash(self):self.assertNotEqual(c.key_hash(0,0),c.key_hash(0,1))
 def test_bool(self):
  with self.assertRaises(a.AuditError):c.inputs(True,188)
 def test_scenario(self):
  with self.assertRaises(a.AuditError):c.inputs(480,188,scenario=7)
 def test_fast(self):
  with self.assertRaises(a.AuditError):c.inputs(480,188,fast=2)
 def test_override(self):
  with self.assertRaises(a.AuditError):c.inputs(480,188,format_override=-1)
 def test_size(self):
  with self.assertRaises(a.AuditError):c.inputs(480,4097)
 def test_mode(self):
  with self.assertRaises(a.AuditError):c.inputs(480,188,mode=2)
@unittest.skipUnless(O.is_file(),'original archive cache oracle required')
class Native(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name);self.raw=bytes(range(256))*4;(self.root/'data.000').write_bytes(self.raw);self.p0=self.root/'first';self.p1=self.root/'second';self.p0.write_bytes(b'A'*1024);self.p1.write_bytes(b'B'*1024)
 def tearDown(self):self.t.cleanup()
 def runio(self,address=480,length=188,**kw):return c.compare(O,self.root,address,length,**kw)
 def test_miss_original_open(self):r,data=self.runio();self.assertEqual(data,self.raw[480:668]);self.assertEqual(r['create_calls'],1)
 def test_hit_no_os_open(self):r,_=self.runio(scenario=1);self.assertEqual(r['create_calls'],0)
 def test_hit_ignores_injected_os_open_error(self):self.assertEqual(self.runio(scenario=1,open_error=7)[0]['status'],0)
 def test_wrong_archive_misses(self):self.assertEqual(self.runio(scenario=2)[0]['constructor_calls'],1)
 def test_wrong_flag_misses(self):self.assertEqual(self.runio(scenario=3)[0]['constructor_calls'],1)
 def test_high_dword_matters_despite_hash(self):r,_=self.runio(scenario=4);self.assertEqual(r['entry0_hash'],c.key_hash(0,0));self.assertEqual(r['constructor_calls'],1)
 def test_collision_selects_second_file(self):r,data=self.runio(scenario=5,cache_paths=(self.p0,self.p1));self.assertEqual(data,b'B'*188);self.assertEqual(r['list_head'],1)
 def test_first_selects_first_file(self):r,data=self.runio(scenario=6,cache_paths=(self.p0,self.p1));self.assertEqual(data,b'A'*188);self.assertEqual(r['list_head'],0)
 def test_original_retain_then_release(self):r,_=self.runio(scenario=1);self.assertEqual((r['reference0_during_read'],r['reference0_after']),(2,1))
 def test_second_original_retain_release(self):r,_=self.runio(scenario=5);self.assertEqual((r['reference1_during_read'],r['reference1_after']),(2,1))
 def test_release_on_read_error(self):r,_=self.runio(scenario=1,read_error=5);self.assertEqual(r['status'],8);self.assertEqual(r['reference0_after'],1)
 def test_new_driver_reference_kept(self):r,_=self.runio();self.assertEqual((r['new_reference_during_read'],r['new_reference_after']),(2,1))
 def test_locks_trace_balanced(self):r,_=self.runio();self.assertEqual((r['locks'],r['unlocks']),(1,1))
 def test_rejected_range_no_lock(self):self.assertEqual(self.runio((1023<<30)+480)[0]['locks'],0)
 def test_zero_length_no_lock(self):self.assertEqual(self.runio(length=0)[0]['locks'],0)
 def test_read_only_windows_arguments(self):r,_=self.runio();self.assertEqual((r['desired_access'],r['disposition'],r['share_mode']),(0x80000000,3,7))
 def test_fast_original_route(self):r,_=self.runio(fast=1);self.assertEqual((r['desired_access'],r['disposition'],r['share_mode']),(0x80000000,3,1))
 def test_write_mode_denied_not_downgraded(self):r,_=self.runio(mode=0);self.assertEqual((r['status'],r['desired_access'],r['disposition']),(5,0xc0000000,4))
 def test_write_mode_does_not_create(self):p=self.root/'data.000';p.unlink();r,_=self.runio(mode=0);self.assertEqual(r['status'],5);self.assertFalse(p.exists())
 def test_read_only_missing_no_create(self):p=self.root/'data.000';p.unlink();r,_=self.runio();self.assertEqual(r['status'],2);self.assertFalse(p.exists())
 def test_format_capacity_rejects_before_constructor(self):r,_=self.runio(format_override=780);self.assertEqual((r['status'],r['constructor_calls'],r['unlocks']),(10,0,1))
 def test_open_error_unlocks(self):r,_=self.runio(open_error=7);self.assertEqual((r['status'],r['unlocks'],r['read_calls']),(7,1,0))
 def test_short_success_count(self):r,_=self.runio(1020,20);self.assertEqual((r['status'],r['actual_bytes']),(0,4))
 def test_read_error38_success_zero(self):r,_=self.runio(read_error=38);self.assertEqual((r['status'],r['actual_bytes']),(0,0))
 def test_unmodified(self):before={p.name:p.read_bytes() for p in self.root.iterdir()};self.runio();self.assertEqual(before,{p.name:p.read_bytes() for p in self.root.iterdir()})
 def test_filename_1022(self):(self.root/'data.1022').write_bytes(self.raw);self.assertEqual(self.runio((1022<<30)+480)[0]['filename'],'data.1022')
 def test_symlink_rejected(self):
  p=self.root/'data.000';p.unlink();p.symlink_to(self.p0)
  with self.assertRaises(b.BindingError):self.runio()
 def test_hardlink_rejected(self):
  os.link(self.root/'data.000',self.root/'link')
  with self.assertRaises(b.BindingError):self.runio()
 def test_bad_binary(self):
  p=self.root/'oracle';p.write_bytes(O.read_bytes()+b'x');p.chmod(0o700);(p.parent/'BUILD-RECEIPT.json').write_bytes((O.parent/'BUILD-RECEIPT.json').read_bytes())
  with self.assertRaises(a.AuditError):c.native(p,self.root,480,188)
 def test_matrix(self):
  rng=random.Random(982471)
  for _ in range(150):self.runio(rng.choice((480,1020,1024,(1<<30)-1)),rng.randrange(50),mode=rng.randrange(2),scenario=rng.randrange(7),read_error=rng.choice((0,5,38)),open_error=rng.choice((0,7)),format_override=rng.choice((0,780)),fast=rng.randrange(2))
@unittest.skipUnless(O.is_file() and S.is_file() and (P/'data.000').is_file(),'cache/span oracles and research source required')
class Bridge(unittest.TestCase):
 def setUp(self):self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name);self.p=self.root/'data.000';self.raw=(P/'data.000').read_bytes();self.p.write_bytes(self.raw)
 def tearDown(self):self.t.cleanup()
 def read(self,off=480,key=K,ck=CK,scenario=0,size=188):return c.read_numbered(O,S,{0:self.p},off,size,key,33940,ck,scenario)
 def test_real_miss(self):self.assertEqual(self.read()['decoded_bytes'],33940)
 def test_real_hit(self):self.assertTrue(self.read(scenario=1)['cache_hit'])
 def test_real_collision(self):self.assertTrue(self.read(scenario=5)['cache_hit'])
 def test_target(self):self.assertEqual(self.read(668,T,TC)['decoded_md5'],TC)
 def test_short_rejected(self):
  self.p.write_bytes(self.raw[:600])
  with self.assertRaisesRegex(a.AuditError,'cache_exact_read_required'):self.read()
 def test_header_corruption(self):
  raw=bytearray(self.raw);raw[506]^=1;self.p.write_bytes(raw)
  with self.assertRaisesRegex(a.AuditError,'cache_original_header_rejected'):self.read()
 def test_wrong_key(self):
  with self.assertRaisesRegex(a.AuditError,'cache_key_size_flag'):self.read(key=T)
 def test_wrong_ck(self):
  with self.assertRaises(fmt.FormatError):self.read(ck=TC)
 def test_size_limit(self):
  with self.assertRaisesRegex(a.AuditError,'cache_reader_size_profile'):self.read(size=4097)
 def test_1023_denied(self):
  with self.assertRaisesRegex(a.AuditError,'cache_reader_address_profile'):self.read(off=(1023<<30)+480)
 def test_no_constructor_claim(self):self.assertFalse(self.read()['original_constructor_allocation_insertion_executed'])
 def test_no_windows_claim(self):self.assertFalse(self.read()['windows_executed'])
