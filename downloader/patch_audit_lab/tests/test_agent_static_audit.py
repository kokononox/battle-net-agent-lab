import struct
import unittest
import agent_static_audit as s
import patch_audit as a

def index_fixture(*,flags=2,version=3,spec=1,count=1):
    blob=struct.pack('<I',3)+b'\0n\0'
    block=struct.pack('<BBHII',version,16,14,count,62)+bytes([1,flags])
    record=b'\x11'*16+struct.pack('<I',100)+b'\x22'*16+struct.pack('<II',50,50)+bytes([spec])+b'\x33'*16
    block+=record*count
    hs=35;total=hs+len(blob)+len(block)
    return struct.pack('<IIIH',hs,1,total,1)+b'\0'+struct.pack('<I',2)+struct.pack('<II',1,len(blob))+struct.pack('<II',8,len(block))+blob+block

class StaticAuditTests(unittest.TestCase):
    def test_observed_layout(self):
        rows,r=s.records(index_fixture());self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['key_a'],'11'*16);self.assertEqual(rows[0]['u32_a'],100)
        self.assertEqual(rows[0]['key_b'],'22'*16);self.assertEqual(rows[0]['key_c'],'33'*16)
        self.assertEqual(r['block8']['record_bytes'],61)
    def test_multiple_rows_kept(self):self.assertEqual(len(s.records(index_fixture(count=3))[0]),3)
    def test_all_truncations_rejected(self):
        raw=index_fixture()
        for n in range(len(raw)):
            with self.subTest(n=n),self.assertRaises(a.AuditError):s.records(raw[:n])
    def test_trailing_data_rejected(self):
        with self.assertRaises(a.AuditError):s.records(index_fixture()+b'x')
    def test_wrong_declared_size(self):
        raw=bytearray(index_fixture());struct.pack_into('<I',raw,8,1)
        with self.assertRaises(a.AuditError):s.records(raw)
    def test_unknown_flags(self):
        with self.assertRaisesRegex(a.AuditError,'variant'):s.records(index_fixture(flags=1))
    def test_unknown_version(self):
        with self.assertRaisesRegex(a.AuditError,'variant'):s.records(index_fixture(version=2))
    def test_blob_bounds(self):
        with self.assertRaisesRegex(a.AuditError,'spec_offset'):s.records(index_fixture(spec=3))
    def test_unobserved_blob(self):
        raw=index_fixture().replace(b'\0n\0',b'\0z\0')
        with self.assertRaisesRegex(a.AuditError,'unobserved_index_blob'):s.records(raw)
    def test_unknown_block(self):
        raw=bytearray(index_fixture());struct.pack_into('<I',raw,27,9)
        with self.assertRaisesRegex(a.AuditError,'block_set'):s.records(raw)
    def test_duplicate_block_id(self):
        raw=bytearray(index_fixture());struct.pack_into('<I',raw,27,1)
        with self.assertRaisesRegex(a.AuditError,'block_bounds'):s.records(raw)
    def test_record_count_bounds(self):
        raw=bytearray(index_fixture());struct.pack_into('<I',raw,42+4,2)
        with self.assertRaisesRegex(a.AuditError,'record_bounds'):s.records(raw)
    def test_invalid_agent_rejected_before_pe_read(self):
        with self.assertRaisesRegex(a.AuditError,'sha256'):s.pe_evidence(b'not a binary')
    def test_unknown_index_rejected(self):
        from unittest.mock import patch
        with patch.object(s,'pe_evidence',return_value={}),self.assertRaisesRegex(a.AuditError,'ckey'):s.analyze(b'',index_fixture(),[])

if __name__=='__main__':unittest.main()
