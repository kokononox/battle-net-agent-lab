import json,struct,tempfile,unittest
from pathlib import Path
import analyzer,diagnostics,verify_report
from test_analyzer import fixture

class DiagnosticsTests(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'fixture.exe'
 def tearDown(self):self.tmp.cleanup()
 def run_code(self,code):
  b=bytearray(fixture());b[0x400:0x440]=b'\x90'*64;b[0x400:0x400+len(code)]=code
  struct.pack_into('<I',b,0x804,0x1000+len(code));self.path.write_bytes(b)
  return analyzer.analyze(self.path)
 def hit(self,r,site=0x1000):return next(h for h in r['code_candidates'] if h['site_rva']==site)
 def test_cmp_rip_with_trailing_imm8(self):
  r=self.run_code(b'\x80\x3d'+struct.pack('<i',0x2000-0x1007)+b'\x00\xc3');h=self.hit(r)
  self.assertEqual(h['discovery'],'expanded');self.assertEqual(h['encoding'],'rip_relative_modrm');self.assertEqual(h['cfg_status'],'locally_decoded_from_pdata_entry')
 def test_cmp_imm32(self):
  r=self.run_code(b'\x81\x3d'+struct.pack('<i',0x2000-0x100a)+b'\x01\x00\x00\x00\xc3');self.assertEqual(self.hit(r)['target_rva'],0x2000)
 def test_segment_prefix(self):
  r=self.run_code(b'\x65\x48\x8d\x15'+struct.pack('<i',0x2000-0x1008)+b'\xc3');self.assertEqual(self.hit(r)['discovery'],'expanded')
 def test_simd_opcode(self):
  r=self.run_code(b'\xf3\x0f\x6f\x05'+struct.pack('<i',0x2000-0x1008)+b'\xc3');self.assertEqual(self.hit(r)['encoding'],'rip_relative_modrm')
 def test_movabs(self):
  r=self.run_code(b'\x48\xb8'+struct.pack('<Q',0x140002000)+b'\xc3');self.assertEqual(self.hit(r)['encoding'],'absolute_imm64')
 def test_pointer_slot_hop(self):
  r=self.run_code(b'\x48\x8b\x05'+struct.pack('<i',0x2100-0x1007)+b'\xc3');h=self.hit(r)
  self.assertEqual(h['anchor_hops'],1);self.assertEqual(h['pointer_chain'][0]['target_rva'],0x2000);self.assertFalse(h['pointer_dereference_proven'])
 def test_no_ref_is_explicitly_inconclusive(self):
  b=bytearray(fixture());b[0x400:0x600]=b'\xc3'*512;self.path.write_bytes(b);r=analyzer.analyze(self.path)
  self.assertFalse(r['code_candidates']);self.assertEqual(r['diagnosis']['outcome'],'no_reference_found_within_expanded_scope');self.assertFalse(r['diagnosis']['protection_proven'])
 def test_section_entropy_not_protection_proof(self):
  r=self.run_code(b'\xc3');self.assertIn('sections',r['diagnosis']['structural_triage']);self.assertFalse(r['diagnosis']['protection_proven'])
 def test_samples_not_target_functions(self):
  r=self.run_code(b'\xc3');self.assertEqual(len(r['functions']),0);self.assertEqual(len(r['diagnosis']['structural_triage']['function_samples']),1)
 def test_no_auto_protection_claim(self):
  r=self.run_code(b'\xc3');r['diagnosis']['protection_proven']=True
  with self.assertRaises(ValueError):verify_report.verify(self.path,r)
 def test_bad_chain_rejected(self):
  r=self.run_code(b'\x48\x8b\x05'+struct.pack('<i',0x2100-0x1007)+b'\xc3');self.hit(r)['pointer_chain'][0]['target_rva']+=1
  with self.assertRaises(ValueError):verify_report.verify(self.path,r)
 def test_bad_immediate_offset_rejected(self):
  r=self.run_code(b'\x48\xb8'+struct.pack('<Q',0x140002000)+b'\xc3');self.hit(r)['operand_immediate_offset']=100
  with self.assertRaises(ValueError):verify_report.verify(self.path,r)
 def test_false_root_cause_rejected(self):
  r=self.run_code(b'\xc3');r['diagnosis']['root_cause']='protected'
  with self.assertRaises(ValueError):verify_report.verify(self.path,r)
 def test_decode_budget_disclosed(self):
  old=diagnostics.BUDGET['decode_attempts']
  try:
   diagnostics.BUDGET['decode_attempts']=1;r=self.run_code(b'\x80\x3d'+struct.pack('<i',0x2000-0x1007)+b'\x00\xc3');self.assertTrue(r['diagnosis']['budget_limits_hit'])
  finally:diagnostics.BUDGET['decode_attempts']=old
 def test_unknown_build_still_has_no_field_hints(self):
  r=self.run_code(b'\x48\xb8'+struct.pack('<Q',0x140002000)+b'\xc3');self.assertFalse(r['profile']['matched']);self.assertFalse(r['functions'][0]['offset_only_write_candidates'])
 def test_diagnosis_in_zip(self):
  import zipfile
  r=self.run_code(b'\xc3');p=analyzer.write_outputs(r,Path(self.tmp.name)/'out')
  with zipfile.ZipFile(p) as z:self.assertIn('diagnosis.json',z.namelist())
 def test_tampered_local_count_rejected(self):
  r=self.run_code(b'\xc3');r['diagnosis']['expanded_locally_decoded_candidates']=10
  with self.assertRaises(ValueError):verify_report.verify(self.path,r)
 def test_tampered_dataflow_proof_rejected(self):
  r=self.run_code(b'\xc3');r['diagnosis']['hardware_dataflow_proven']=True
  with self.assertRaises(ValueError):verify_report.verify(self.path,r)
 def test_segmented_memory_not_a_flat_anchor_reference(self):
  r=self.run_code(b'\x65\x48\x8b\x05'+struct.pack('<i',0x2000-0x1008)+b'\xc3')
  self.assertFalse(any(h['site_rva']==0x1000 for h in r['code_candidates']))
if __name__=='__main__':unittest.main()
