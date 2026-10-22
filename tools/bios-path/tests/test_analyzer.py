import hashlib,json,struct,sys,tempfile,unittest,zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import analyzer,verify_report

def fixture():
 b=bytearray(0xe00);b[:2]=b'MZ';struct.pack_into('<I',b,0x3c,0x80);b[0x80:0x84]=b'PE\0\0'
 struct.pack_into('<HHIIIHH',b,0x84,0x8664,5,0,0,0,0xf0,0x22)
 o=0x98;struct.pack_into('<H',b,o,0x20b);struct.pack_into('<I',b,o+16,0x1000)
 struct.pack_into('<Q',b,o+24,0x140000000);struct.pack_into('<II',b,o+32,0x1000,0x200)
 struct.pack_into('<II',b,o+56,0x6000,0x400);struct.pack_into('<H',b,o+68,3)
 struct.pack_into('<I',b,o+108,16)
 for idx,rva,size in [(1,0x4000,40),(3,0x3000,12),(5,0x5000,12)]:struct.pack_into('<II',b,o+112+idx*8,rva,size)
 for i,(name,va,off,flags) in enumerate([(b'.text',0x1000,0x400,0x60000020),(b'.rdata',0x2000,0x600,0x40000040),(b'.pdata',0x3000,0x800,0x40000040),(b'.idata',0x4000,0xa00,0xc0000040),(b'.reloc',0x5000,0xc00,0x42000040)]):
  pos=o+0xf0+i*40;struct.pack_into('<8sIIIIIIHHI',b,pos,name,0x200,va,0x200,off,0,0,0,0,flags)
 code=b'\x48\x8d\x15'+struct.pack('<i',0x2000-0x1007)+b'\xff\x15'+struct.pack('<i',0x4050-0x100d)+b'\x48\x89\x41\x60\xeb\x03\x0f\x0b\x90\xc3'
 b[0x400:0x400+len(code)]=code
 decoy=b'\x48\x8d\x15'+struct.pack('<i',0x2000-0x1107)+b'\xc3';b[0x500:0x500+len(decoy)]=decoy
 st='BIOSVendor\0'.encode('utf-16le');b[0x600:0x600+len(st)]=st;struct.pack_into('<Q',b,0x700,0x140002000)
 struct.pack_into('<III',b,0x800,0x1000,0x1000+len(code),0x3100)
 struct.pack_into('<IIIII',b,0xa00,0x4040,0,0,0x4080,0x4050)
 struct.pack_into('<Q',b,0xa40,0x4090);struct.pack_into('<Q',b,0xa50,0x4090)
 b[0xa80:0xa80+13]=b'ADVAPI32.dll\0';name=b'\0\0RegQueryValueExW\0';b[0xa90:0xa90+len(name)]=name
 struct.pack_into('<IIHH',b,0xc00,0x2000,12,0xa100,0)
 return bytes(b)

class Tests(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'fixture.exe';self.path.write_bytes(fixture())
 def tearDown(self):self.tmp.cleanup()
 def run_analysis(self):return analyzer.analyze(self.path)
 def test_literal_discovery(self):
  r=self.run_analysis();self.assertTrue(any(x['text']=='BIOSVendor' and x['occurrences'][0]['rva']==0x2000 for x in r['literals']))
 def test_rip_and_import_cfg_validation(self):
  r=self.run_analysis();hits=r['code_candidates'];self.assertTrue(any(h['site_rva']==0x1000 and h['cfg_status']=='locally_decoded_from_pdata_entry' for h in hits));self.assertTrue(any(h['site_rva']==0x1007 and h['kind']=='import_registry_call' for h in hits))
 def test_unanchored_decoy_not_code_proof(self):
  r=self.run_analysis();self.assertTrue(any(h['site_rva']==0x1100 and h['cfg_status']=='not_checked' for h in r['code_candidates']))
 def test_cfg_skips_unreachable_invalid_bytes(self):
  r=self.run_analysis();text=r['functions'][0]['disassembly'];self.assertNotIn('ud2',text);self.assertIn('ret',text)
 def test_relocation_pointer(self):
  r=self.run_analysis();self.assertTrue(any(x['site_rva']==0x2100 and x['target_rva']==0x2000 for x in r['data_pointer_candidates']))
 def test_unknown_build_disables_field_hints(self):
  r=self.run_analysis();self.assertFalse(r['profile']['matched']);self.assertEqual(r['functions'][0]['offset_only_write_candidates'],[])
 def test_pinned_profile_offset_is_not_object_identity(self):
  old=analyzer.KNOWN_SHA;old_pin=verify_report.PIN
  try:
   analyzer.KNOWN_SHA=hashlib.sha256(self.path.read_bytes()).hexdigest();verify_report.PIN=analyzer.KNOWN_SHA;r=self.run_analysis()
   self.assertTrue(r['profile']['matched']);w=r['functions'][0]['offset_only_write_candidates'];self.assertTrue(w);self.assertFalse(w[0]['object_identity_proven'])
  finally:analyzer.KNOWN_SHA=old;verify_report.PIN=old_pin
 def test_claims_fail_closed(self):self.assertTrue(all(v is False for v in self.run_analysis()['claims'].values()))
 def test_input_unchanged(self):
  before=self.path.read_bytes();self.run_analysis();self.assertEqual(before,self.path.read_bytes())
 def test_zip_no_input_or_full_path(self):
  r=self.run_analysis();z=analyzer.write_outputs(r,Path(self.tmp.name)/'out')
  with zipfile.ZipFile(z) as f:
   self.assertNotIn('fixture.exe',f.namelist());self.assertNotIn(self.tmp.name,f.read('evidence.json').decode());self.assertIn('report.fa.md',f.namelist())
 def test_invalid_file(self):
  self.path.write_bytes(b'not a PE')
  with self.assertRaises(analyzer.InputError):self.run_analysis()
 def test_wrong_arch(self):
  b=bytearray(fixture());struct.pack_into('<H',b,0x84,0x14c);self.path.write_bytes(b)
  with self.assertRaises(analyzer.InputError):self.run_analysis()
 def test_truncated_section(self):
  self.path.write_bytes(fixture()[:0x700])
  with self.assertRaises(analyzer.InputError):self.run_analysis()
 def test_branch_outside_is_disclosed(self):
  b=bytearray(fixture());b[0x411:0x413]=b'\xeb\x7f';self.path.write_bytes(b);r=self.run_analysis();self.assertTrue(any('leaves' in x for x in r['functions'][0]['issues']))
 def test_overlap_disclosed(self):
  b=bytearray(fixture());b[0x411:0x413]=b'\xeb\xee';self.path.write_bytes(b);r=self.run_analysis();self.assertTrue(any('Overlapping' in x for x in r['functions'][0]['issues']))
 def test_budget_disclosed(self):
  old=analyzer.LIMITS['functions']
  try:
   analyzer.LIMITS['functions']=0;r=self.run_analysis();self.assertTrue(r['coverage']['budget_limits_hit']);self.assertEqual(r['functions'],[])
  finally:analyzer.LIMITS['functions']=old
 def test_no_pdata_disclosed(self):
  b=bytearray(fixture());struct.pack_into('<II',b,0x98+112+3*8,0,0);self.path.write_bytes(b);r=self.run_analysis();self.assertFalse(r['functions']);self.assertTrue(any('pdata' in x for x in r['coverage']['warnings']))
 def test_deterministic_except_elapsed(self):
  a=self.run_analysis();b=self.run_analysis();a.pop('elapsed_seconds');b.pop('elapsed_seconds');self.assertEqual(a,b)
 def test_mutated_claim_rejected(self):
  r=self.run_analysis();r['claims']['runtime_send_proven']=True
  with self.assertRaises(ValueError):verify_report.verify(self.path,r)
 def test_mutated_target_rejected(self):
  r=self.run_analysis();r['code_candidates'][0]['target_rva']+=1
  with self.assertRaises(ValueError):verify_report.verify(self.path,r)
 def test_mutated_bytes_rejected(self):
  r=self.run_analysis();r['code_candidates'][0]['bytes']='90'
  with self.assertRaises(ValueError):verify_report.verify(self.path,r)
 def test_wrong_hash_profile_rejected(self):
  r=self.run_analysis();r['profile']['matched']=True
  with self.assertRaises(ValueError):verify_report.verify(self.path,r)
 def test_existing_output_not_reused(self):
  r=self.run_analysis();out=Path(self.tmp.name)/'out';analyzer.write_outputs(r,out)
  with self.assertRaises(FileExistsError):analyzer.write_outputs(r,out)
if __name__=='__main__':unittest.main(verbosity=2)
