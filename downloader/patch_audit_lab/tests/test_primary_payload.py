import json,struct,unittest,socket
from unittest.mock import patch
import patch_audit as a
import shmem_primary_readonly as primary
import shmem_readonly as obs
import agent_primary_payload_audit as audit
from test_activation_readonly import control

def payload(state=1,pairs=(),index=0,saved_a=0,saved_b=0):
    raw=bytearray(primary.SIZE);struct.pack_into('<4I',raw,0,state,len(pairs),index,0xdeadbeef)
    struct.pack_into('<QQ',raw,0x10,saved_b,saved_a)
    for i,(va,vb) in enumerate(pairs):
        raw[primary.ARRAY_A+i*5:primary.ARRAY_A+(i+1)*5]=va.to_bytes(5,'big')
        raw[primary.ARRAY_B+i*5:primary.ARRAY_B+(i+1)*5]=vb.to_bytes(5,'big')
    return bytes(raw)

class PrimaryTests(unittest.TestCase):
    def test_geometry_capacity_and_tail(self):
        self.assertEqual(primary.ARRAY_A+primary.CAPACITY*5,primary.ARRAY_B)
        self.assertEqual(primary.ARRAY_B+primary.CAPACITY*5,primary.SIZE-4)
        got=primary.inspect(payload(pairs=[(1,2)]*1090));self.assertEqual(got['record_count'],1090)
    def test_empty_states(self):
        for state in (0,1):self.assertFalse(primary.inspect(payload(state))['installation_ready'])
    def test_exact_bytes_size(self):
        for raw in (bytearray(primary.SIZE),None,b'',bytes(primary.SIZE-1),bytes(primary.SIZE+1)):
            with self.assertRaisesRegex(a.AuditError,'exact_size'):primary.inspect(raw)
    def test_unknown_state(self):
        for state in (3,4,0xffffffff):
            with self.assertRaisesRegex(a.AuditError,'unobserved_state'):primary.inspect(payload(state))
    def test_capacity_overflow(self):
        raw=bytearray(payload());struct.pack_into('<I',raw,4,1091)
        with self.assertRaisesRegex(a.AuditError,'capacity'):primary.inspect(bytes(raw))
    def test_pending_index_bounds(self):
        for count,index in ((0,0),(1,1),(1,0xffffffff)):
            with self.assertRaisesRegex(a.AuditError,'index_outside'):primary.inspect(payload(2,[(0,0)]*count,index))
    def test_inactive_index_and_saved_not_used(self):
        got=primary.inspect(payload(1,[(0,0)],0xffffffff,2**64-1,2**64-1));self.assertFalse(got['rollback_index_checked'])
    def test_pending_projection_endian_and_pair_order(self):
        # Asymmetric >32-bit values catch little-endian, array or save swaps.
        va,vb=0x123456789a,0xfedcba9876
        for saved_a,saved_b,expected in ((va,vb,0),(va,0,1),(0,vb,1),(vb,va,2)):
            with self.subTest(expected=expected):self.assertEqual(primary.inspect(payload(2,[(va,vb)],0,saved_a,saved_b))['rollback_projection_changed_fields'],expected)
    def test_pending_last_slot_and_max40(self):
        raw=payload(2,[(0,0)]*1089+[(2**40-1,0)],1089,2**40-1,0)
        self.assertEqual(primary.inspect(raw)['rollback_projection_changed_fields'],0)
    def test_saved_value_policy_is_not_truncation(self):
        for va,vb in ((2**40,0),(0,2**40),(2**64-1,0)):
            with self.assertRaisesRegex(a.AuditError,'observer_policy'):primary.inspect(payload(2,[(0,0)],0,va,vb))
    def test_does_not_modify_input_or_export_entries(self):
        raw=payload(2,[(0x123456789a,0xfedcba9876)],0,12,34);before=raw
        got=primary.inspect(raw);text=json.dumps(got)
        self.assertEqual(raw,before);self.assertNotIn(str(0x123456789a),text);self.assertFalse(got['raw_entries_exported']);self.assertFalse(got['rollback_performed'])
    def test_opaque_word_and_tail_not_constraints(self):
        raw=bytearray(payload());raw[-4:]=b'priv';got=primary.inspect(bytes(raw));self.assertFalse(got['tail_padding_interpreted']);self.assertFalse(got['opaque_header_word_interpreted'])
    def test_control_versions_integrate_primary(self):
        for v,off in ((4,0x150),(5,0x1000)):
            raw=bytearray(control(v));raw[off:off+primary.SIZE]=payload(2,[(4,5)],0,3,5)
            got=obs.inspect(bytes(raw));self.assertEqual(got['format'],'shmem-bounded-observation-3');self.assertTrue(got['primary_payload_observation']['rollback_pending']);self.assertFalse(got['payload_layout_decoded']);self.assertFalse(got['installation_ready'])
    def test_control_unknown_primary_fail_closed(self):
        raw=bytearray(control());struct.pack_into('<I',raw,0x150,9)
        with self.assertRaisesRegex(a.AuditError,'unobserved_state'):obs.inspect(bytes(raw))
    def test_no_network(self):
        with patch.object(socket,'socket',side_effect=AssertionError('network')):self.assertEqual(primary.inspect(payload())['network_requests'],0)

class PrimaryAuditTests(unittest.TestCase):
    def fake(self):
        image={};imports={}
        def put(va,data):
            for i,value in enumerate(data):
                if va+i in image:self.assertEqual(image[va+i],value)
                image[va+i]=value
        for va,h in audit.ANCHORS.values():put(va,bytes.fromhex(h))
        for va,target in audit.CALLS.values():put(va,b'\xe8'+struct.pack('<i',target-va-5))
        for va,op,target in audit.BRANCHES.values():
            opcode=bytes.fromhex(op);put(va,opcode+(target-va-2).to_bytes(1,'little',signed=True))
        for va,iat,name in audit.IAT_CALLS.values():
            put(va,b'\xff\x15'+iat.to_bytes(4,'little'));imports[iat]={'dll':'KERNEL32.dll','name':name}
        class Fake:
            def read(self,va,n):return bytes(image[va+i] for i in range(n))
            def relcall(self,va):return va+5+int.from_bytes(self.read(va+1,4),'little',signed=True)
            def imports(self):return imports
        return Fake(),image
    def test_receipts(self):
        pe,_=self.fake();got=audit.verify(pe);self.assertEqual(len(got['anchors']),27);self.assertEqual(len(got['direct_calls']),24)
    def test_anchor_mutations(self):
        for name,(va,_) in audit.ANCHORS.items():
            with self.subTest(anchor=name):
                pe,image=self.fake();image[va]^=1
                with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_call_mutations(self):
        for name,(va,_) in audit.CALLS.items():
            with self.subTest(call=name):
                pe,image=self.fake();image[va+1]^=1
                with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_non_pinned_rejected(self):
        for raw in (b'bad',bytearray(b'bad')):
            with self.assertRaises(a.AuditError):audit.analyze(raw)

    def test_branch_mutations(self):
        for name,(va,_,_) in audit.BRANCHES.items():
            with self.subTest(branch=name):
                pe,image=self.fake();image[va+1]^=1
                with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_import_mutations(self):
        for va,iat,name in audit.IAT_CALLS.values():
            pe,_=self.fake();pe.imports()[iat]['name']='wrong'
            with self.assertRaisesRegex(a.AuditError,'iat_symbol'):audit.verify(pe)
    def test_import_opcode_mutations(self):
        for va,iat,name in audit.IAT_CALLS.values():
            pe,image=self.fake();image[va]^=1
            with self.assertRaisesRegex(a.AuditError,'iat_opcode'):audit.verify(pe)
