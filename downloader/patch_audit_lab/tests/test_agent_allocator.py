import struct,unittest
import patch_audit as a
import agent_allocator_model as m
import agent_storage_paths_audit as audit
import synthetic_casc_format as fmt

class AllocatorTests(unittest.TestCase):
    def test_boundary_reserve_and_retry(self):
        raw=m.make([(m.SEGMENT,0)]);one=m.allocate(raw,188);self.assertEqual(one['code'],16);self.assertEqual(one['payload'],raw)
        two=m.reserve_prefix(raw,0);self.assertEqual(two['code'],0);three=m.allocate(two['payload'],188)
        self.assertEqual((three['code'],three['address'],three['size']),(0,480,188));self.assertEqual(m.records(three['payload']),[(m.SEGMENT-668,668)])
    def test_first_fit_is_list_order(self):
        raw=m.make([(20,600),(50,100),(30,700)]);got=m.allocate(raw,25);self.assertEqual(got['address'],100);self.assertEqual(got['index'],1);self.assertEqual(m.records(got['payload']),[(20,600),(25,125),(30,700)])
    def test_exact_fit_keeps_zero_length_record(self):
        got=m.allocate(m.make([(188,480)]),188);self.assertEqual(got['code'],0);self.assertEqual(m.records(got['payload']),[(0,668)])
    def test_no_fit_is_unchanged(self):
        raw=m.make([(187,480)]);got=m.allocate(raw,188);self.assertEqual(got['code'],14);self.assertEqual(got['payload'],raw)
    def test_zero_request(self):
        raw=m.make([(10,10)]);got=m.allocate(raw,0);self.assertEqual((got['code'],got['address'],got['size']),(0,0,0));self.assertEqual(got['payload'],raw)
    def test_boundary_threshold(self):
        self.assertEqual(m.allocate(m.make([(479,0)]),1)['code'],0);self.assertEqual(m.allocate(m.make([(480,0)]),1)['code'],16)
    def test_nonzero_archives_and_address_above32(self):
        for archive in (1,3,4,1023):
            base=archive*m.SEGMENT;raw=m.make([(m.SEGMENT,base)]);self.assertEqual(m.allocate(raw,188)['code'],16)
            got=m.allocate(m.reserve_prefix(raw,archive)['payload'],188);self.assertEqual(got['address'],base+480)
    def test_prefix_no_containing_range(self):
        raw=m.make([(100,480)]);got=m.reserve_prefix(raw,0);self.assertEqual(got['code'],14);self.assertEqual(got['payload'],raw)
    def test_model_policy_rejects_overlap_and_crossing(self):
        for rows in ([(10,10),(10,15)],[(20,m.SEGMENT-10)],[(m.SEGMENT+1,0)],[(2,2**40-1)],[(True,10)]):
            with self.assertRaises(a.AuditError):m.make(rows)
    def test_request_policy(self):
        raw=m.make([])
        for size in (-1,2**32,1.5,True):
            with self.assertRaises(a.AuditError):m.allocate(raw,size)
        for archive in (-1,1024,True):
            with self.assertRaises(a.AuditError):m.reserve_prefix(raw,archive)
    def test_reset_not_allocatable(self):
        raw=bytearray(m.make([]));struct.pack_into('<I',raw,0,0);self.assertEqual(m.allocate(bytes(raw),1)['code'],14)
    def test_six_snapshot_cut_points(self):
        raw=m.make([(500,480)]);frames=m.update_frames(raw,0,312,668);self.assertEqual(len(frames),6)
        for phase,snapshot in frames:
            with self.subTest(phase=phase):
                recovered=m.recover(snapshot);self.assertEqual(m.records(recovered),[(312,668)] if phase=='committed_one' else [(500,480)]);self.assertEqual(m.recover(recovered),recovered)
    def test_allocate_recovers_state_two_first(self):
        raw=m.make([(500,480)]);dirty=m.update_frames(raw,0,312,668)[4][1];got=m.allocate(dirty,188);self.assertEqual(got['address'],480)
    def test_saved_pair_order(self):
        raw=m.make([(1000,(4<<30)+480)]);saved=m.update_frames(raw,0,900,(4<<30)+580)[1][1];saved_b,saved_a=struct.unpack_from('<QQ',saved,0x10);self.assertEqual((saved_a,saved_b),(1000,(4<<30)+480))
    def test_update_bad_index_state_range(self):
        raw=m.make([(100,480)])
        for index,x,y in ((-1,1,1),(1,1,1),(0,-1,1),(0,1,2**40)):
            with self.assertRaises(a.AuditError):m.update_frames(raw,index,x,y)
        with self.assertRaises(a.AuditError):m.update_frames(m.update_frames(raw,0,90,490)[2][1],0,80,500)

class StorageAuditTests(unittest.TestCase):
    def fake(self):
        image={}
        def put(va,data):
            for i,value in enumerate(data):
                if va+i in image:self.assertEqual(image[va+i],value)
                image[va+i]=value
        for va,h in audit.ANCHORS.values():put(va,bytes.fromhex(h))
        for va,target in audit.CALLS.values():put(va,b'\xe8'+struct.pack('<i',target-va-5))
        for va,op,target in audit.BRANCHES.values():
            opcode=bytes.fromhex(op);w=4 if len(opcode)==2 else 1;put(va,opcode+(target-va-len(opcode)-w).to_bytes(w,'little',signed=True))
        put(0x9bd650,struct.pack('<16I',*fmt.TABLE))
        class Fake:
            def read(self,va,n):return bytes(image[va+i] for i in range(n))
            def relcall(self,va):return va+5+int.from_bytes(self.read(va+1,4),'little',signed=True)
        return Fake(),image
    def test_receipts(self):
        pe,_=self.fake();got=audit.verify(pe);self.assertEqual(len(got['anchors']),25);self.assertEqual(len(got['direct_calls']),12);self.assertEqual(len(got['branch_edges']),6);self.assertTrue(got['checksum_table']['exact_match'])
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
    def test_branch_mutations(self):
        for name,(va,op,_) in audit.BRANCHES.items():
            with self.subTest(branch=name):
                pe,image=self.fake();image[va+len(bytes.fromhex(op))]^=1
                with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_each_table_word_mutation(self):
        for i in range(16):
            with self.subTest(word=i):
                pe,image=self.fake();image[0x9bd650+4*i]^=1
                with self.assertRaises(a.AuditError):audit.verify(pe)
    def test_unpinned_rejected(self):
        with self.assertRaises(a.AuditError):audit.analyze(b'wrong')
