import copy,json,os,socket,struct,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import patch_audit as a
import agent_activation_audit as audit
import shmem_readonly as obs
import source_binding as b


def control(version=4,header=None,seq=7):
    raw=bytearray(0x2c10 if version==4 else 0x4000)
    header=header if header is not None else (0x150 if version==4 else 0x154)
    struct.pack_into('<II',raw,0,version,header);raw[8:20]=b'Global\\dummy'
    struct.pack_into('<II',raw,0x108,0x2ab8,0x150 if version==4 else 0x1000)
    struct.pack_into('<16I',raw,0x110,*([seq]*16));return bytes(raw)

class ControlTests(unittest.TestCase):
    def test_version4_geometry(self):
        got=obs.inspect(control());self.assertEqual(got['payload_offset'],0x150);self.assertFalse(got['installation_ready']);self.assertFalse(got['coherent_live_snapshot_proven'])
    def test_version5_basic_geometry(self):self.assertEqual(obs.inspect(control(5))['header_bytes'],0x154)
    def test_version5_258_is_not_declared_header(self):
        # Corrected from the old test: 0x258 is a copy length, not field[4].
        with self.assertRaisesRegex(a.AuditError,'header_size'):obs.inspect(control(5,0x258))
    def test_referenced_sequence_not_max(self):
        got=obs.inspect(control(),['0000000007.idx','0000000008.idx']);row=got['sequence_observations'][0]
        self.assertTrue(row['sequence_file_present']);self.assertEqual(row['sequence'],7);self.assertEqual(row['max_inventory_sequence'],8);self.assertTrue(row['inventory_has_newer_sequence'])
    def test_missing_reference_not_replaced_by_max(self):
        row=obs.inspect(control(),['0000000008.idx'])['sequence_observations'][0];self.assertFalse(row['sequence_file_present']);self.assertEqual(row['sequence_filename'],'0000000007.idx')
    def test_no_inventory_is_unknown_not_absent(self):self.assertIsNone(obs.inspect(control())['sequence_observations'][0]['sequence_file_present'])
    def test_empty_inventory_is_absent(self):self.assertFalse(obs.inspect(control(),[])['sequence_observations'][0]['sequence_file_present'])
    def test_name_is_not_exported(self):self.assertNotIn('Global',json.dumps(obs.inspect(control())))
    def test_unknown_protocol(self):
        for v in [0,1,3,6,0xffffffff]:
            raw=bytearray(control());struct.pack_into('<I',raw,0,v)
            with self.subTest(v=v),self.assertRaises(a.AuditError):obs.inspect(bytes(raw))
    def test_unknown_header(self):
        raw=bytearray(control());struct.pack_into('<I',raw,4,0x151)
        with self.assertRaises(a.AuditError):obs.inspect(bytes(raw))
    def test_unknown_payload_size(self):
        raw=bytearray(control());struct.pack_into('<I',raw,0x108,1)
        with self.assertRaises(a.AuditError):obs.inspect(bytes(raw))
    def test_unknown_offset(self):
        raw=bytearray(control());struct.pack_into('<I',raw,0x10c,0x1000)
        with self.assertRaises(a.AuditError):obs.inspect(bytes(raw))
    def test_short_long_and_type(self):
        for raw in [b'',control()[:0x14f],control()[:0x150+0x2ab8-1],b'X'*(obs.MAX_CONTROL+1),bytearray(control())]:
            with self.subTest(n=len(raw)),self.assertRaises(a.AuditError):obs.inspect(raw)
    def test_empty_name(self):
        raw=bytearray(control());raw[8:0x108]=bytes(256)
        with self.assertRaises(a.AuditError):obs.inspect(bytes(raw))
    def test_unterminated_name(self):
        raw=bytearray(control());raw[8:0x108]=b'A'*256
        with self.assertRaises(a.AuditError):obs.inspect(bytes(raw))
    def test_special_flag_no_activation_claim(self):
        raw=bytearray(control(5));struct.pack_into('<I',raw,0x150,1);got=obs.inspect(bytes(raw));self.assertTrue(got['protocol5_low_flag_special_path']);self.assertFalse(got['sequence_is_active_for_game_proven'])
    def test_invalid_names(self):
        for names in [['../0000000007.idx'],['1000000007.idx'],['0000000007.idx']*2,[None],['shmem'],['0000000007.IDX'],['0000000007.idx']*513,'0000000007.idx']:
            with self.subTest(names=str(names)[:40]),self.assertRaises(a.AuditError):obs.inspect(control(),names)
    def test_sequence_u32_boundaries(self):
        for seq in [0,0xffffffff]:self.assertEqual(obs.inspect(control(seq=seq))['sequence_observations'][15]['sequence'],seq)
    def test_readonly_file_and_no_network(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t).resolve()/'shmem';p.write_bytes(control());before=p.read_bytes();stat=b.fp(p.stat())
            with patch.object(socket,'socket',side_effect=AssertionError('network')):got=obs.observe_file(p)
            self.assertEqual(p.read_bytes(),before);self.assertEqual(b.fp(p.stat()),stat);self.assertEqual(got['files_written'],0)
    def test_archive_path_rejected_before_read(self):
        with patch.object(b.Watch,'read',side_effect=AssertionError('read forbidden')):
            with self.assertRaises(a.AuditError):obs.observe_file('data.000')
    def test_mutation_between_reads(self):
        with patch.object(b.Watch,'read',side_effect=[control(),control(seq=8)]):
            with self.assertRaisesRegex(a.AuditError,'changed_between_reads'):obs.observe_file('shmem')
    def test_symlink_and_hardlink_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve();target=root/'source';target.write_bytes(control());p=root/'shmem';p.symlink_to(target)
            with self.assertRaises(b.BindingError):obs.observe_file(p)
            p.unlink();os.link(target,p)
            with self.assertRaises(b.BindingError):obs.observe_file(p)

class StaticAuditTests(unittest.TestCase):
    def fake(self):
        image={}
        for _,(va,h) in audit.ANCHORS.items():image[va]=bytes.fromhex(h)
        for _,(va,target) in audit.CALLS.items():image[va]=b'\xe8'+struct.pack('<i',target-va-5)
        imports={}
        for _,(va,iat,name) in audit.IAT_CALLS.items():image[va]=b'\xff\x15'+iat.to_bytes(4,'little');imports[iat]={'name':name,'dll':'kernel32.dll'}
        image[0x9be600]=b'.idx\0'
        class Fake:
            def read(self,va,n):return image[va][:n]
            def relcall(self,va):return va+5+int.from_bytes(image[va][1:],'little',signed=True)
            def imports(self):return imports
        return Fake(),image,imports
    def test_anchor_verifier_synthetic(self):
        pe,_,_=self.fake();got=audit.verify(pe);self.assertEqual(len(got['anchors']),len(audit.ANCHORS))
    def test_bad_byte_anchor_rejected(self):
        pe,image,_=self.fake();va=next(iter(audit.ANCHORS.values()))[0];image[va]=b'\0'*len(image[va])
        with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_bad_call_target_rejected(self):
        pe,image,_=self.fake();va=next(iter(audit.CALLS.values()))[0];image[va]=b'\xe8\0\0\0\0'
        with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_bad_import_name_rejected(self):
        pe,_,imports=self.fake();imports[0x8fb48c]['name']='DifferentAPI'
        with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_unpinned_binary_rejected(self):
        with self.assertRaisesRegex(a.AuditError,'pinned_agent'):audit.analyze(b'not the Agent')
    def test_pe_short_and_non_pe_rejected(self):
        for raw in [b'',b'X'*1024]:
            with self.assertRaises(a.AuditError):audit.PE(raw)
    def test_va_unbacked(self):
        pe=audit.PE.__new__(audit.PE);pe.raw=b'abc';pe.sections=[(0x1000,0,3)]
        with self.assertRaises(a.AuditError):pe.read(0x2000,1)
        self.assertEqual(pe.read(0x1000,3),b'abc')
    def test_relcall_opcode_rejected(self):
        pe=audit.PE.__new__(audit.PE);pe.raw=bytes(5);pe.sections=[(0x1000,0,5)]
        with self.assertRaises(a.AuditError):pe.relcall(0x1000)

if __name__=='__main__':unittest.main()
