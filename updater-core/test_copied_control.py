import struct,unittest,json
from copied_control import inspect_copy
from release_core import InvalidRelease

def fixture(v=5,ext=True,state=1):
 off=0x150 if v==4 else 0x1000;stop=off+0x2ab8;size=((stop+15)&~15) if v==4 else (((0x4228 if ext else stop)+4095)&~4095);raw=bytearray(size);struct.pack_into('<II',raw,0,v,0x150 if v==4 else 0x154);raw[8:23]=b'Global\\Private\0';struct.pack_into('<II',raw,0x108,0x2ab8,off);struct.pack_into('<16I',raw,0x110,*range(16));struct.pack_into('<4I',raw,off,state,10,0,999)
 if v==5:
  struct.pack_into('<I',raw,0x150,2 if ext else 0)
  if ext:struct.pack_into('<II',raw,0x154,1,0x228);struct.pack_into('<I',raw,0x1d8,0x4000);struct.pack_into('<I',raw,0x4000,1)
 return bytes(raw),[f'{b:02x}{b:08x}.idx' for b in range(16)]
class Tests(unittest.TestCase):
 def test_v5_extension(self):
  raw,n=fixture();r=inspect_copy(raw,n);self.assertEqual(r['matched_buckets'],16);self.assertFalse(r['live_generation_proven']);self.assertFalse(r['installation_ready'])
 def test_v4(self):
  raw,n=fixture(4,False);self.assertEqual(inspect_copy(raw,n)['protocol'],4)
 def test_v5_no_extension(self):
  raw,n=fixture(ext=False);self.assertEqual(inspect_copy(raw,n)['extension_observations'],[])
 def test_redaction(self):
  raw,n=fixture();text=json.dumps(inspect_copy(raw,n));self.assertNotIn('Private',text);self.assertNotIn('Global',text)
 def test_unknown_protocol(self):
  raw,n=fixture();raw=bytearray(raw);struct.pack_into('<I',raw,0,6)
  with self.assertRaises(InvalidRelease):inspect_copy(bytes(raw),n)
 def test_unknown_flags(self):
  raw,n=fixture();raw=bytearray(raw);struct.pack_into('<I',raw,0x150,8)
  with self.assertRaises(InvalidRelease):inspect_copy(bytes(raw),n)
 def test_unknown_extension_slot(self):
  raw,n=fixture();raw=bytearray(raw);struct.pack_into('<I',raw,0x154,2)
  with self.assertRaises(InvalidRelease):inspect_copy(bytes(raw),n)
 def test_extension_geometry(self):
  raw,n=fixture();raw=bytearray(raw);struct.pack_into('<I',raw,0x1d8,0x5000)
  with self.assertRaises(InvalidRelease):inspect_copy(bytes(raw),n)
 def test_truncated(self):
  raw,n=fixture()
  with self.assertRaises(InvalidRelease):inspect_copy(raw[:-100],n)
 def test_extra_bytes(self):
  raw,n=fixture()
  with self.assertRaises(InvalidRelease):inspect_copy(raw+b'x',n)
 def test_inventory_mismatch_unknown(self):
  raw,n=fixture();r=inspect_copy(raw,n[:-1]);self.assertEqual(r['matched_buckets'],15);self.assertIn('UNKNOWN',r['status']);self.assertFalse(r['requires_repair_proven'])
 def test_duplicate_inventory_rejected(self):
  raw,n=fixture()
  with self.assertRaises(InvalidRelease):inspect_copy(raw,n+[n[0]])
 def test_newer_sequence_not_automatically_selected(self):
  raw,n=fixture();r=inspect_copy(raw,n+['000000ffff.idx']);self.assertTrue(r['sequence_observations'][0]['inventory_has_newer_sequence']);self.assertEqual(r['sequence_observations'][0]['sequence_filename'],'0000000000.idx')
 def test_pending_valid_not_repaired(self):
  raw,n=fixture(state=2);r=inspect_copy(raw,n);self.assertTrue(r['primary_observation']['rollback_pending_observed']);self.assertFalse(r['apply_authorized'])
 def test_pending_bad_index(self):
  raw,n=fixture(state=2);raw=bytearray(raw);struct.pack_into('<I',raw,0x1008,10)
  with self.assertRaises(InvalidRelease):inspect_copy(bytes(raw),n)
 def test_primary_count_not_archive_count(self):
  raw,n=fixture();self.assertTrue(inspect_copy(raw,n)['primary_observation']['record_count_is_NOT_archive_count'])
 def test_unobserved_primary_state(self):
  raw,n=fixture(state=9)
  with self.assertRaises(InvalidRelease):inspect_copy(raw,n)
 def test_reset_not_damage_diagnosis(self):
  raw,n=fixture(state=0);self.assertFalse(inspect_copy(raw,n)['requires_repair_proven'])
if __name__=='__main__':unittest.main()
