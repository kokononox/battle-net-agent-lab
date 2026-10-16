import ctypes,json,os,random,socket,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import synthetic_casc_format as f
import synthetic_casc_store as s
import encoding_target as e
import patch_audit as a
import source_binding as b

NATIVE=Path(os.environ.get('SYNTHETIC_NATIVE_DIR', str(Path(__file__).resolve().parents[1]/'research'/'synthetic-casc-storage'/'native')))

class FormatTests(unittest.TestCase):
    def encoded(self,data=b'hello'*20):
        raw=e.encode(data,'b:*=z');hs=int.from_bytes(raw[4:8],'big');return data,raw,a.md5(raw[:hs])
    def test_span_roundtrip(self):
        data,raw,key=self.encoded();span=f.make_span(raw,key,len(data),3,19)
        self.assertEqual(f.read_span(span,key,len(data),a.md5(data),3,19)[0],data)
    def test_span_embedded_size_includes_30(self):
        data,raw,key=self.encoded();span=f.make_span(raw,key,len(data),0,0)
        self.assertEqual(int.from_bytes(span[16:20],'little'),len(raw)+30)
    def test_record_byte_reverse_full_key(self):
        data,raw,key=self.encoded();self.assertEqual(f.make_span(raw,key,len(data),0,0)[:16],bytes.fromhex(key)[::-1])
    def test_checksum_b_archive_lowbits_and_offset(self):
        data,raw,key=self.encoded()
        for aid in (0,1,2,3,4,1023):
            for offset in (0,1,15,16,17,1024):
                span=f.make_span(raw,key,len(data),aid,offset)
                self.assertEqual(f.read_span(span,key,len(data),a.md5(data),aid,offset)[0],data)
    def test_record_bad_header_rejected(self):
        data,raw,key=self.encoded();span=f.make_span(raw,key,len(data),0,0)
        for at in (0,16,20,22,26,40):
            bad=bytearray(span);bad[at]^=1
            with self.subTest(at=at),self.assertRaises((f.FormatError,a.AuditError)):f.read_span(bytes(bad),key,len(data),a.md5(data),0,0)
    def test_wrong_decoded_ckey_rejected(self):
        data,raw,key=self.encoded();span=f.make_span(raw,key,len(data),0,0)
        with self.assertRaises(f.FormatError):f.read_span(span,key,len(data),'0'*32,0,0)
    def test_offset_wrong_checksum_rejected(self):
        data,raw,key=self.encoded();span=f.make_span(raw,key,len(data),0,10)
        with self.assertRaises(f.FormatError):f.read_span(span,key,len(data),a.md5(data),0,11)
    def test_locations_full_bit_boundaries(self):
        for archive in (0,1,3,4,255,1023):
            for offset in (0,1,(1<<30)-1):self.assertEqual(f.unlocation(f.location(archive,offset)),(archive,offset))
    def test_bad_location_bounds(self):
        for args in [(-1,0),(1024,0),(0,-1),(0,1<<30),(True,0),(0,False)]:
            with self.subTest(args=args),self.assertRaises(f.FormatError):f.location(*args)
    def test_index_sorted_roundtrip(self):
        key='11'*16;rows=[{'ekey':key,'archive':5,'offset':10,'span':188}]
        raw=f.make_index(rows,f.bucket(key));self.assertEqual(f.read_index(raw,f.bucket(key))[0],{'prefix':key[:18],'archive':5,'offset':10,'span':188})
    def test_index_size_is_little_endian(self):
        key='11'*16;raw=f.make_index([{'ekey':key,'archive':0,'offset':0,'span':188}],f.bucket(key))
        self.assertEqual(raw[-4:],(188).to_bytes(4,'little'))
    def test_wrong_bucket_rejected(self):
        key='11'*16
        with self.assertRaises(f.FormatError):f.make_index([{'ekey':key,'archive':0,'offset':0,'span':188}],(f.bucket(key)+1)%16)
    def test_prefix_collision_fails_closed(self):
        key='11'*16;other=key[:18]+'22'*7
        rows=[{'ekey':v,'archive':0,'offset':i*188,'span':188} for i,v in enumerate((key,other))]
        with self.assertRaisesRegex(f.FormatError,'prefix_collision'):f.make_index(rows,f.bucket(key))
    def test_index_header_and_entry_corruption(self):
        key='11'*16;raw=f.make_index([{'ekey':key,'archive':0,'offset':0,'span':188}],f.bucket(key))
        for at in (0,4,8,24,32,36,41,55):
            bad=bytearray(raw);bad[at]^=1
            with self.subTest(at=at),self.assertRaises(f.FormatError):f.read_index(bytes(bad),f.bucket(key))
    def test_index_truncation_and_tail_rejected(self):
        key='11'*16;raw=f.make_index([{'ekey':key,'archive':0,'offset':0,'span':188}],f.bucket(key))
        for bad in (raw[:-1],raw+b'\0'):
            with self.assertRaises(f.FormatError):f.read_index(bad,f.bucket(key))
    @unittest.skipUnless((NATIVE/'liblookup3-reference.so').exists(),'native Jenkins oracle not built')
    def test_210_native_jenkins_vectors(self):
        lib=ctypes.CDLL(str(NATIVE/'liblookup3-reference.so'));fn=lib.hashlittle2;fn.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_uint32),ctypes.POINTER(ctypes.c_uint32)]
        rng=random.Random(719)
        for n in list(range(65))+[127,128,255,1024,4096]:
            data=rng.randbytes(n)
            for seed in (0,0x3D6BE971,0xffffffff):
                pc=ctypes.c_uint32(seed);pb=ctypes.c_uint32(seed^0xa5a5a5a5);buf=ctypes.create_string_buffer(data);fn(buf,n,ctypes.byref(pc),ctypes.byref(pb))
                self.assertEqual(f.hashlittle2(data,seed,seed^0xa5a5a5a5),(pc.value,pb.value))
    @unittest.skipUnless((NATIVE/'index_oracle').exists(),'native CascLib oracle not built')
    def test_actual_casclib_capture_functions_accept_and_reject(self):
        # Distinct 9-byte prefixes with matching bucket; exercise chained checksum.
        keys=['11'*16,'22'*16,'33'*16,'001100000000000000'+'44'*7,'110000000000000000'+'55'*7,'000011000000000000'+'66'*7]
        bybucket={}
        for i,key in enumerate(keys):bybucket.setdefault(f.bucket(key),[]).append({'ekey':key,'archive':3,'offset':i*188,'span':188})
        with tempfile.TemporaryDirectory() as d:
            for bucket,rows in bybucket.items():
                p=Path(d)/'sample.idx';raw=f.make_index(rows,bucket);p.write_bytes(raw)
                got=subprocess.run([str(NATIVE/'index_oracle'),str(p),str(bucket)],capture_output=True,text=True)
                self.assertEqual(got.returncode,0,got.stdout+got.stderr);self.assertTrue(json.loads(got.stdout)['accepted']);self.assertEqual(json.loads(got.stdout)['entries'],len(rows))
                for at in (4,36,41):
                    bad=bytearray(raw);bad[at]^=1;p.write_bytes(bad)
                    got=subprocess.run([str(NATIVE/'index_oracle'),str(p),str(bucket)],capture_output=True,text=True)
                    self.assertNotEqual(got.returncode,0)

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.store=s.Store.create(self.root/'fixture',archive_limit=512)
    def tearDown(self):self.temp.cleanup()
    def seed(self):return self.store.add([(b'old object'*20,'b:*=z')])
    def test_empty_fixture(self):self.assertEqual(self.store.view(),{})
    def test_new_root_only(self):
        before=set(self.root.iterdir())
        with self.assertRaises(f.FormatError):s.Store.create(self.store.root)
        self.assertEqual(before,set(self.root.iterdir()))
    def test_game_ancestor_rejected(self):
        game=self.root/'game';game.mkdir();(game/'.build.info').write_text('protected')
        with self.assertRaises(f.FormatError):s.Store.create(game/'new')
        self.assertFalse((game/'new').exists())
    def test_no_marker_root_rejected_no_writes(self):
        other=self.root/'other';other.mkdir();(other/'personal').write_text('keep')
        with self.assertRaises(Exception):s.Store(other)
        self.assertEqual(list(other.iterdir()),[other/'personal'])
    def test_symlink_ancestor_rejected(self):
        real=self.root/'real';real.mkdir();link=self.root/'link';link.symlink_to(real,target_is_directory=True)
        with self.assertRaises(b.BindingError):s.Store.create(link/'fixture')
    def test_single_add_and_reopen(self):
        self.seed();values=s.Store(self.store.root).view();self.assertEqual(list(values.values()),[b'old object'*20])
    def test_append_preserves_old_generation(self):
        old=self.seed();folder=self.store.root/'generations'/old['generation'];before={p.name:p.read_bytes() for p in folder.iterdir()}
        self.store.add([(b'new object'*20,'z')]);self.assertEqual(len(self.store.view()),2)
        self.assertEqual(before,{p.name:p.read_bytes() for p in folder.iterdir()})
    def test_rollover_two_archives(self):
        self.store.add([(b'A'*250,'n'),(b'B'*250,'n')]);ptr=self.store.pointer();m,_,_=self.store.generation(ptr)
        self.assertEqual(len(m['archives']),2)
    def test_oversize_rejected_keeps_active(self):
        old=self.store.pointer()
        with self.assertRaises(f.FormatError):self.store.add([(b'X'*600,'n')])
        self.assertEqual(self.store.pointer(),old);self.assertEqual(self.store.view(),{})
    def test_duplicate_rejected_keeps_active(self):
        self.seed();old=self.store.pointer()
        with self.assertRaises(f.FormatError):self.store.add([(b'old object'*20,'b:*=z')])
        self.assertEqual(self.store.pointer(),old)
    def test_payload_path_is_not_accepted(self):
        with self.assertRaises(f.FormatError):self.store.add([(str(self.root/'personal'),'z')])
    def test_no_network(self):
        with patch.object(socket,'socket',side_effect=AssertionError('network forbidden')):self.seed();self.assertEqual(len(self.store.view()),1)
    def test_lock_conflict(self):
        with self.store.lock():
            with self.assertRaisesRegex(f.FormatError,'busy'):self.store.view()
    def test_separate_process_lock_conflict_and_release(self):
        code='import sys; from synthetic_casc_store import Store; Store(sys.argv[1]).add([(b"child object","z")])'
        env={**os.environ,'PYTHONPATH':str(Path(s.__file__).resolve().parent)}
        with self.store.lock():
            result=subprocess.run([sys.executable,'-B','-c',code,str(self.store.root)],env=env,capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0);self.assertIn('synthetic_store_busy',result.stderr)
        self.assertEqual(self.store.view(),{})
        result=subprocess.run([sys.executable,'-B','-c',code,str(self.store.root)],env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(list(self.store.view().values()),[b'child object'])
    def test_index_corruption_detected(self):
        self.seed();ptr=self.store.pointer();folder=self.store.root/'generations'/ptr['generation'];p=next(folder.glob('*.idx'));raw=p.read_bytes();p.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
        with self.assertRaises(f.FormatError):self.store.view()
    def test_archive_corruption_detected(self):
        self.seed();ptr=self.store.pointer();p=self.store.root/'generations'/ptr['generation']/'data.000';raw=p.read_bytes();p.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
        with self.assertRaises(f.FormatError):self.store.view()
    def test_manifest_corruption_detected(self):
        self.seed();ptr=self.store.pointer();p=self.store.root/'generations'/ptr['generation']/'manifest.json';p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaises(f.FormatError):self.store.view()
    def test_hardlinked_archive_rejected(self):
        self.seed();p=self.store.root/'generations'/self.store.pointer()['generation']/'data.000';os.link(p,self.root/'extra-link')
        with self.assertRaises(b.BindingError):self.store.view()
    def test_symlink_generation_rejected(self):
        ptr=self.store.pointer();folder=self.store.root/'generations'/ptr['generation'];other=self.root/'moved';folder.rename(other);folder.symlink_to(other,target_is_directory=True)
        with self.assertRaises(b.BindingError):self.store.view()
    def test_unexpected_generation_file_rejected(self):
        folder=self.store.root/'generations'/self.store.pointer()['generation'];(folder/'personal').write_text('keep')
        with self.assertRaises(f.FormatError):self.store.view()
    def fail_at(self,phase):
        def failure(p):
            if p==phase:raise RuntimeError('injected simulated interruption')
        return failure
    def test_each_exception_failure_point_old_or_committed(self):
        # Nine separate stores; never reuse a broken transaction to hide a failure.
        for i,phase in enumerate(s.PHASES):
            store=s.Store.create(self.root/f'case-{i}');store.add([(b'old','z')]);old=store.pointer();old_values=store.view()
            with self.subTest(phase=phase):
                with self.assertRaises(RuntimeError):store.add([(b'new','z')],self.fail_at(phase))
                reopened=s.Store(store.root);reopened.recover();values=reopened.view()
                if phase=='committed_recorded':self.assertEqual(len(values),2)
                else:self.assertEqual(values,old_values);self.assertEqual(reopened.pointer(),old)
                self.assertEqual(reopened.recover(),reopened.recover())
    def test_abrupt_process_exit_at_all_nine_phases(self):
        for i,phase in enumerate(s.PHASES):
            store=s.Store.create(self.root/f'crash-{i}');store.add([(b'old','z')]);old=store.pointer();before=store.view()
            code='import os,sys; from synthetic_casc_store import Store; Store(sys.argv[1]).add([(b"new","z")],lambda p: os._exit(91) if p==sys.argv[2] else None)'
            result=subprocess.run([sys.executable,'-B','-c',code,str(store.root),phase],env={**os.environ,'PYTHONPATH':str(Path(s.__file__).resolve().parent)},capture_output=True,text=True)
            with self.subTest(phase=phase):
                self.assertEqual(result.returncode,91,result.stderr);fresh=s.Store(store.root);fresh.recover();values=fresh.view()
                if phase=='committed_recorded':self.assertEqual(len(values),2)
                else:self.assertEqual(values,before);self.assertEqual(fresh.pointer(),old)
    def test_unrelated_pointer_preserved_on_recovery(self):
        self.seed();old=self.store.pointer()
        with self.assertRaises(RuntimeError):self.store.add([(b'new','z')],self.fail_at('prepared'))
        unrelated=dict(old);unrelated['manifest_sha256']='0'*64;s.atomic(self.store.root/'active.json',s.raw_json(unrelated));before=(self.store.root/'active.json').read_bytes()
        with self.assertRaisesRegex(f.FormatError,'unrelated_pointer'):self.store.recover()
        self.assertEqual((self.store.root/'active.json').read_bytes(),before)
    def test_bad_rollback_generation_blocks_pointer_changes(self):
        old=self.seed()
        with self.assertRaises(RuntimeError):self.store.add([(b'new','z')],self.fail_at('pointer_replaced'))
        p=self.store.root/'generations'/old['generation']/'data.000';p.write_bytes(b'damaged')
        before=(self.store.root/'active.json').read_bytes()
        with self.assertRaises(f.FormatError):self.store.recover()
        self.assertEqual((self.store.root/'active.json').read_bytes(),before)
    def test_bad_new_generation_can_rollback_without_clobbering_it(self):
        self.seed();old=self.store.pointer()
        with self.assertRaises(RuntimeError):self.store.add([(b'new','z')],self.fail_at('pointer_replaced'))
        new=self.store.pointer();p=self.store.root/'generations'/new['generation']/'data.000';p.write_bytes(b'damaged')
        self.store.recover();self.assertEqual(self.store.pointer(),old);self.assertEqual(p.read_bytes(),b'damaged')
    def test_later_commits_not_undone_by_historical_journals(self):
        self.seed();self.store.add([(b'new1','z')]);self.store.add([(b'new2','z')]);latest=self.store.pointer()
        self.store.recover();self.assertEqual(self.store.pointer(),latest);self.assertEqual(len(self.store.view()),3)
    def test_invalid_journal_path_rejected(self):
        self.seed()
        with self.assertRaises(RuntimeError):self.store.add([(b'new','z')],self.fail_at('prepared'))
        journal=next(p for p in (self.store.root/'transactions').glob('*/journal.json') if s.obj(p)['state']=='prepared')
        j=s.obj(journal);j['old']['generation']='../../outside';s.atomic(journal,s.raw_json(j));before=(self.store.root/'active.json').read_bytes()
        with self.assertRaises(f.FormatError):self.store.recover()
        self.assertEqual((self.store.root/'active.json').read_bytes(),before)
