import json,socket,struct,unittest
from unittest.mock import patch
import agent_binding_extension_audit as audit
import agent_activation_audit as base
import patch_audit as a
import shmem_readonly as obs
from test_activation_readonly import control


def extended(size=0x5000,bitmap=1,state=1):
    raw=bytearray(control(5));raw.extend(bytes(size-len(raw)))
    struct.pack_into('<III',raw,0x150,2,bitmap,0x228)
    struct.pack_into('<I',raw,0x1d8,0x4000)
    if len(raw)>=0x4004:struct.pack_into('<I',raw,0x4000,state)
    return raw

class ExtensionTests(unittest.TestCase):
    def test_declared_154_vs_copy_258(self):
        got=obs.inspect(bytes(extended()));self.assertEqual(got['declared_header_field'],0x154);self.assertEqual(got['constructor_copy_bytes'],0x258);self.assertEqual(got['constructor_expected_file_bytes'],0x5000)
    def test_slot_geometry_and_no_activation_claim(self):
        got=obs.inspect(bytes(extended()));row=got['extension_observations'][0]
        self.assertEqual((row['slot'],row['offset'],row['size']),(0,0x4000,0x228));self.assertFalse(row['semantics_complete']);self.assertFalse(got['installation_ready']);self.assertFalse(got['name_source_binding_proven'])
    def test_base_v5_copy_length(self):
        got=obs.inspect(control(5));self.assertEqual(got['constructor_copy_bytes'],0x154);self.assertIsNone(got['extension_bitmap']);self.assertEqual(got['extension_observations'],[])
    def test_no_requested_slot_with_flag2(self):
        got=obs.inspect(bytes(extended(bitmap=0)));self.assertEqual(got['constructor_copy_bytes'],0x258);self.assertEqual(got['extension_observations'],[]);self.assertFalse(got['observed_file_size_matches_constructor'])
    def test_unknown_slots_rejected(self):
        for bitmap in (2,3,0x80000000):
            with self.assertRaisesRegex(a.AuditError,'extension_slot'):obs.inspect(bytes(extended(bitmap=bitmap)))
    def test_bad_extension_size(self):
        raw=extended();struct.pack_into('<I',raw,0x158,0x229)
        with self.assertRaisesRegex(a.AuditError,'extension_size'):obs.inspect(bytes(raw))
    def test_overlap_misalignment_and_huge_offset(self):
        for off in (0,0x150,0x1000,0x3ab8,0x4001,0xffffffff):
            raw=extended();struct.pack_into('<I',raw,0x1d8,off)
            with self.assertRaisesRegex(a.AuditError,'extension_offset'):obs.inspect(bytes(raw))
    def test_extension_truncated(self):
        with self.assertRaisesRegex(a.AuditError,'extension_truncated'):obs.inspect(bytes(extended()[:0x4227]))
        got=obs.inspect(bytes(extended()[:0x4228]));self.assertFalse(got['observed_file_size_matches_constructor'])
    def test_known_and_unknown_diagnostic_state(self):
        for state in (0,1,2,3,0xffffffff):self.assertEqual(obs.inspect(bytes(extended(state=state)))['extension_observations'][0]['diagnostic_state_is_recognized'],state in (1,2))
    def test_extension_and_name_content_not_exported(self):
        raw=extended();raw[0x4040:0x4051]=b'private-extension';raw[8:0x108]=b'Global\\private-name\0'.ljust(256,b'\0')
        got=json.dumps(obs.inspect(bytes(raw)));self.assertNotIn('private-',got);self.assertNotIn('Global',got)
    def test_unknown_flags_rejected(self):
        for flags in (4,6,0xffffffff):
            raw=extended();struct.pack_into('<I',raw,0x150,flags)
            with self.assertRaisesRegex(a.AuditError,'v5_flags'):obs.inspect(bytes(raw))
    def test_constructor_prefix_required(self):
        raw=bytearray(control());raw[8:15]=b'localxx'
        with self.assertRaisesRegex(a.AuditError,'name_prefix'):obs.inspect(bytes(raw))
    def test_flag3_and_no_network(self):
        raw=extended();struct.pack_into('<I',raw,0x150,3)
        with patch.object(socket,'socket',side_effect=AssertionError('network')):got=obs.inspect(bytes(raw))
        self.assertTrue(got['protocol5_low_flag_special_path']);self.assertFalse(got['coherent_live_snapshot_proven'])

class BindingAuditTests(unittest.TestCase):
    def fake(self):
        image={};imports={}
        def put(va,data):
            for i,v in enumerate(data):
                if va+i in image:self.assertEqual(image[va+i],v)
                image[va+i]=v
        for va,h in audit.ANCHORS.values():put(va,bytes.fromhex(h))
        for va,target in audit.CALLS.values():put(va,b'\xe8'+struct.pack('<i',target-va-5))
        for va,op,target in audit.BRANCHES.values():
            op=bytes.fromhex(op);w=4 if len(op)==2 else 1;put(va,op+(target-va-len(op)-w).to_bytes(w,'little',signed=True))
        for va,iat,name in audit.IAT_CALLS.values():put(va,b'\xff\x15'+iat.to_bytes(4,'little'));imports[iat]={'dll':'KERNEL32.dll','name':name}
        class Fake:
            def read(self,va,n):return bytes(image[va+i] for i in range(n))
            def relcall(self,va):return va+5+int.from_bytes(self.read(va+1,4),'little',signed=True)
            def imports(self):return imports
        return Fake(),image,imports
    def test_receipts_generated(self):
        pe,_,_=self.fake();got=audit.verify(pe);self.assertEqual(len(got['anchors']),32);self.assertEqual(len(got['direct_calls']),9);self.assertEqual(len(got['conditional_or_jump_edges']),7);self.assertEqual(len(got['import_calls']),2)
    def test_all_anchor_mutations(self):
        for name,(va,h) in audit.ANCHORS.items():
            with self.subTest(anchor=name):
                pe,image,_=self.fake();image[va]^=1
                with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_all_call_mutations(self):
        for name,(va,target) in audit.CALLS.items():
            with self.subTest(call=name):
                pe,image,_=self.fake();image[va+1]^=1
                with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_all_branch_mutations(self):
        for name,(va,op,target) in audit.BRANCHES.items():
            with self.subTest(branch=name):
                pe,image,_=self.fake();image[va+len(bytes.fromhex(op))]^=1
                with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_import_identity_mutations(self):
        for va,iat,name in audit.IAT_CALLS.values():
            pe,_,imports=self.fake();imports[iat]['name']='wrong'
            with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_import_instruction_mutations(self):
        for va,iat,name in audit.IAT_CALLS.values():
            pe,image,_=self.fake();image[va+2]^=1
            with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_unpinned_before_parse(self):
        with patch.object(base,'PE',side_effect=AssertionError('PE')):
            with self.assertRaisesRegex(a.AuditError,'pinned_agent'):audit.analyze(b'not pinned')
if __name__=='__main__':unittest.main()
