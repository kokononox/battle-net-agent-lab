import json,os,struct,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import patch_audit as a
import encoding_target as enc
import synthetic_casc_format as fmt
import retail_storage_poc as poc
import source_binding as b

FIXTURE=Path(os.environ.get('RETAIL_POC_FIXTURE','/nonexistent-retail-fixture'))
NATIVE=Path(os.environ.get('RETAIL_POC_NATIVE','/nonexistent-retail-oracle'))

class PocSafetyTests(unittest.TestCase):
    def test_refuses_existing_before_source_reads(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t);(p/'keep.txt').write_text('keep')
            with self.assertRaisesRegex(a.AuditError,'requires_new'):poc.run(Path('/nonexistent'),p)
            self.assertEqual((p/'keep.txt').read_text(),'keep')
    def test_game_ancestor_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t);(p/'.build.info').write_text('preserve')
            with self.assertRaisesRegex(fmt.FormatError,'game_path_rejected'):poc.safe_new(p/'child')
    def test_root_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);(root/'real').mkdir();(root/'link').symlink_to(root/'real',target_is_directory=True)
            with self.assertRaises(a.AuditError):poc.safe_new(root/'link')
    def test_bad_encoded_declined_before_create(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)/'new'
            with self.assertRaisesRegex(a.AuditError,'encoded_identity'):poc.materialize(root,b'bad',b'bad')
            self.assertFalse(root.exists())

@unittest.skipUnless((FIXTURE/'target.decoded').is_file() and NATIVE.is_file(),'original Retail fixture and built native oracle required')
class RealRetailPocTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.watch=b.Watch()
        for name in sorted(poc.portable_run.FIXED|{'PORTABLE-MANIFEST.json'}):cls.watch.file(FIXTURE/name)
        cls.decoded=cls.watch.read(FIXTURE/'target.decoded');cls.encoded=enc.encode(cls.decoded,'b:{256K*=z}');cls.pkg=Path(__file__).resolve().parents[1]
        assert a.sha256(cls.encoded)==poc.ENCODED_SHA
    @classmethod
    def tearDownClass(cls):cls.watch.check()
    def new(self,parent,name='generated'):
        root=Path(parent)/name;poc.materialize(root,self.encoded,self.decoded);return root
    def call_native(self,index,data,ek=poc.EK,ck=poc.CK,archive=0):
        return subprocess.run([str(NATIVE),str(index),str(data),ek,ck,str(archive)],capture_output=True,text=True,timeout=15)
    def test_real_sample_materialization_native_and_no_network(self):
        with tempfile.TemporaryDirectory() as t,patch('socket.socket',side_effect=AssertionError('network')):
            root=self.new(t);got=poc.verify(root);native=poc.native_verify(root,NATIVE)
            self.assertEqual(got['data_bytes'],668);self.assertFalse(got['installation_ready']);self.assertTrue(native['decoded_ckey_verified'])
    def test_output_existing_refused_unchanged(self):
        with tempfile.TemporaryDirectory() as t:
            root=self.new(t);before={p.name:a.sha256(p.read_bytes()) for p in root.iterdir()}
            with self.assertRaisesRegex(a.AuditError,'requires_new'):poc.materialize(root,self.encoded,self.decoded)
            self.assertEqual(before,{p.name:a.sha256(p.read_bytes()) for p in root.iterdir()})
    def test_incomplete_and_extra_file_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root=self.new(t);(root/'unrecognized').write_text('x')
            with self.assertRaisesRegex(a.AuditError,'layout'):poc.verify(root)
    def test_receipt_metadata_cannot_override_fixed_identity(self):
        with tempfile.TemporaryDirectory() as t:
            root=self.new(t);p=root/'RECEIPT.json';receipt=json.loads(p.read_text());receipt['installation_ready']=True;p.write_bytes(poc.canonical(receipt))
            with self.assertRaisesRegex(a.AuditError,'receipt_identity'):poc.verify(root)
    def test_shmem_semantic_tamper_rejected_even_if_receipt_rehashed(self):
        with tempfile.TemporaryDirectory() as t:
            root=self.new(t);p=root/'shmem';raw=bytearray(p.read_bytes());struct.pack_into('<I',raw,0x110+fmt.bucket(poc.EK)*4,2);p.write_bytes(raw)
            q=root/'RECEIPT.json';receipt=json.loads(q.read_text());receipt['files']['shmem']={'size':len(raw),'sha256':a.sha256(bytes(raw))};q.write_bytes(poc.canonical(receipt))
            with self.assertRaisesRegex(a.AuditError,'poc_sequence'):poc.verify(root)
    def test_64_native_position_vectors(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            for archive in (0,3,4,1023):
                for shift in range(16):
                    with self.subTest(archive=archive,shift=shift):
                        offset=480+shift;span=fmt.make_span(self.encoded,poc.EK,len(self.decoded),archive,offset)
                        data=root/f'data.{archive:03d}';index=root/poc.expected_index();data.write_bytes(bytes(offset)+span);index.write_bytes(fmt.make_index([{'ekey':poc.EK,'archive':archive,'offset':offset,'span':len(span)}],fmt.bucket(poc.EK)))
                        proc=self.call_native(index,data,archive=archive);self.assertEqual(proc.returncode,0,proc.stdout+proc.stderr)
    def test_native_corruption_rejection(self):
        with tempfile.TemporaryDirectory() as t:
            root=self.new(t);data=root/'data.000';idx=root/poc.expected_index();original=data.read_bytes()
            for at in (480,496,502,506,510,550,667):
                with self.subTest(byte=at):
                    raw=bytearray(original);raw[at]^=1;data.write_bytes(raw);proc=self.call_native(idx,data);self.assertNotEqual(proc.returncode,0)
            data.write_bytes(original[:-1]);self.assertNotEqual(self.call_native(idx,data).returncode,0)
            data.write_bytes(original);raw=bytearray(idx.read_bytes());raw[-1]^=1;idx.write_bytes(raw);self.assertNotEqual(self.call_native(idx,data).returncode,0)
    def test_prefix_is_not_full_identity(self):
        with tempfile.TemporaryDirectory() as t:
            root=self.new(t);ek=poc.EK[:18]+'00'*7;proc=self.call_native(root/poc.expected_index(),root/'data.000',ek=ek);self.assertNotEqual(proc.returncode,0);self.assertIn('span_full_ekey',proc.stdout)
    def test_wrong_ckey_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root=self.new(t);proc=self.call_native(root/poc.expected_index(),root/'data.000',ck='00'*16);self.assertNotEqual(proc.returncode,0);self.assertIn('decoded_ckey',proc.stdout)
    def test_process_exit_matrix_no_fake_activation(self):
        with tempfile.TemporaryDirectory() as t:
            base=Path(t);input_path=base/'input.decoded';input_path.write_bytes(self.decoded)
            for phase in poc.PHASES:
                with self.subTest(phase=phase):
                    root=base/phase
                    code="import sys;from pathlib import Path;import retail_storage_poc as p;import encoding_target as e;d=Path(sys.argv[2]).read_bytes();p.materialize(Path(sys.argv[1]),e.encode(d,'b:{256K*=z}'),d,sys.argv[3])"
                    proc=subprocess.run([sys.executable,'-B','-c',code,str(root),str(input_path),phase],cwd=self.pkg,capture_output=True,text=True,timeout=15)
                    self.assertEqual(proc.returncode,91,proc.stderr)
                    if phase=='receipt_written':self.assertEqual(poc.verify(root)['status'],'real_retail_sample_stored_and_read_back');self.assertTrue(poc.native_verify(root,NATIVE)['accepted'])
                    else:
                        with self.assertRaisesRegex(a.AuditError,'layout'):poc.verify(root)
                    self.assertTrue((root/'data.000').is_file());self.assertFalse((root/'.build.info').exists());self.assertFalse((root/'active.json').exists())
