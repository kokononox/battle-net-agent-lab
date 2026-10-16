import copy,json,struct,unittest
from unittest.mock import patch
import agent_activation_audit as base
import agent_publication_audit as audit
import patch_audit as a

class PublicationTests(unittest.TestCase):
    def fake(self):
        image={};imports={}
        def put(va,data):
            for i,v in enumerate(data):
                if va+i in image:self.assertEqual(image[va+i],v)
                image[va+i]=v
        for va,h in audit.ANCHORS.values():put(va,bytes.fromhex(h))
        for va,target in audit.CALLS.values():put(va,b'\xe8'+struct.pack('<i',target-va-5))
        for va,op,target in audit.BRANCHES.values():
            op=bytes.fromhex(op);width=4 if len(op)==2 else 1
            put(va,op+(target-va-len(op)-width).to_bytes(width,'little',signed=True))
        for va,iat,name in audit.IAT_CALLS.values():
            put(va,b'\xff\x15'+iat.to_bytes(4,'little'));imports[iat]={'dll':'KERNEL32.dll','name':name}
        class Fake:
            def read(self,va,n):return bytes(image[va+i] for i in range(n))
            def relcall(self,va):
                data=self.read(va,5);a.require(data[0]==0xe8,'activation_relcall_opcode')
                return va+5+int.from_bytes(data[1:],'little',signed=True)
            def imports(self):return imports
        return Fake(),image,imports
    def test_all_receipts_pass_generated_image(self):
        pe,_,_=self.fake();got=audit.verify(pe)
        self.assertEqual(len(got['anchors']),32);self.assertEqual(len(got['direct_calls']),17)
        self.assertEqual(len(got['conditional_or_jump_edges']),13);self.assertEqual(len(got['import_calls']),6)
    def test_every_anchor_mutation_rejected(self):
        for name,(va,h) in audit.ANCHORS.items():
            with self.subTest(anchor=name):
                pe,image,_=self.fake();image[va]^=1
                with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_every_direct_target_mutation_rejected(self):
        for name,(va,target) in audit.CALLS.items():
            with self.subTest(call=name):
                pe,image,_=self.fake();image[va+1]^=1
                with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_every_branch_target_mutation_rejected(self):
        for name,(va,op,target) in audit.BRANCHES.items():
            with self.subTest(branch=name):
                pe,image,_=self.fake();image[va+len(bytes.fromhex(op))]^=1
                with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_every_branch_opcode_mutation_rejected(self):
        for name,(va,op,target) in audit.BRANCHES.items():
            with self.subTest(branch=name):
                pe,image,_=self.fake();image[va]^=1
                with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_every_import_identity_mutation_rejected(self):
        for name,(va,iat,symbol) in audit.IAT_CALLS.items():
            for changed in ['name','dll']:
                with self.subTest(api=name,field=changed):
                    pe,_,imports=self.fake();imports[iat][changed]='wrong'
                    with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_every_import_instruction_mutation_rejected(self):
        for name,(va,iat,symbol) in audit.IAT_CALLS.items():
            with self.subTest(api=name):
                pe,image,_=self.fake();image[va+2]^=1
                with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_unpinned_binary_rejected_before_pe(self):
        with patch.object(base,'PE',side_effect=AssertionError('PE must not parse')):
            with self.assertRaisesRegex(a.AuditError,'pinned_agent'):audit.analyze(b'untrusted')
    def test_size_and_mutable_type_rejected(self):
        for raw in [bytearray(b'abc'),b'X'*(8*1024**2+1),None]:
            with self.assertRaises(a.AuditError):audit.analyze(raw)
    def test_signed_edges_and_bad_config(self):
        pe,_,_=self.fake()
        for va,op,target in audit.BRANCHES.values():self.assertEqual(audit.branch_target(pe,va,op),target)
        with self.assertRaisesRegex(a.AuditError,'opcode_config'):audit.branch_target(pe,0,'90')
if __name__=='__main__':unittest.main()
