import json,os,struct,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import patch_audit as a
import synthetic_casc_format as f
import archive_prefix_poc as p
import agent_archive_prefix_audit as audit
import retail_storage_poc as old
import encoding_target as enc

SEED=bytes.fromhex('00112233445566778899aabbccddeeff')
FIX=Path(os.environ.get('RETAIL_POC_FIXTURE','/missing'))
NATIVE=Path(os.environ.get('PREFIX_NATIVE_DIR','/missing'))
class PrefixModelTests(unittest.TestCase):
    def test_sixteen_keys_preserve_tail(self):
        ks=p.keys(SEED,0,1024);self.assertEqual(len(set(ks)),16)
        for slot,k in enumerate(ks):self.assertEqual(k[3:],SEED[3:]);self.assertEqual((f.bucket(k.hex())+1)&15,slot)
    def test_capacity_threshold_preserves_or_overwrites_byte2(self):
        self.assertTrue(all(k[2]==0x22 for k in p.keys(SEED,255,256)))
        self.assertTrue(all(k[2]==0 for k in p.keys(SEED,255,257)))
        self.assertTrue(all(k[2]==1 and k[1]==0 for k in p.keys(SEED,256,257)))
    def test_archive_1023_high_byte(self):
        self.assertTrue(all(k[1:3]==b'\xff\x03' for k in p.keys(SEED,1023,1024)))
    def test_seed_width(self):
        for s in (b'',bytes(15),bytes(17),'x',bytearray(16)):
            with self.assertRaises(a.AuditError):p.keys(s,0,1024)
    def test_archive_capacity_bounds(self):
        for ar,cap in ((-1,1),(1,1),(1024,1024),(0,0),(0,1025),(True,1),(0,True)):
            with self.assertRaises(a.AuditError):p.keys(SEED,ar,cap)
    def test_many_archive_vectors(self):
        for cap in (1,256,257,1024):
            for ar in sorted({0,cap-1}):
                for seed in (bytes(16),bytes([255])*16,SEED):
                    self.assertTrue(p.read_prefix(p.prefix(seed,ar,cap),seed,ar,cap))
    def test_checksum_b_depends_on_linear_address(self):
        raw=p.prefix(SEED,0,1024)
        with self.assertRaises(a.AuditError):p.read_prefix(raw,SEED,4,1024)
    def test_checksum_a_tamper(self):
        raw=bytearray(p.prefix(SEED,0,1024));raw[22]^=1
        with self.assertRaises(a.AuditError):p.read_prefix(bytes(raw),SEED,0,1024)
    def test_checksum_b_tamper(self):
        raw=bytearray(p.prefix(SEED,0,1024));raw[26]^=1
        with self.assertRaises(a.AuditError):p.read_prefix(bytes(raw),SEED,0,1024)
    def test_flag_size_and_slot_order(self):
        orig=p.prefix(SEED,0,1024)
        for at in (0,16,20,21,479):
            raw=bytearray(orig);raw[at]^=1
            with self.assertRaises(a.AuditError):p.read_prefix(bytes(raw),SEED,0,1024)
        with self.assertRaises(a.AuditError):p.read_prefix(orig[30:60]+orig[:30]+orig[60:],SEED,0,1024)
    def test_prefix_exact_length(self):
        for raw in (bytes(479),bytes(481)):
            with self.assertRaises(a.AuditError):p.read_prefix(raw,SEED,0,1024)
    def test_reserved_bucket_is_mode_one_not_ordinary(self):
        k=p.keys(SEED,0,1024)[0].hex();self.assertEqual(f.bucket(k),15)
        self.assertEqual(len(p.index([(k,0,30)],0)),58)
        with self.assertRaises(a.AuditError):p.index([(k,0,30)],15)
    def test_static_anchors_and_calls_fail_closed(self):
        class PE:
            def read(self,va,n):return next(bytes.fromhex(h)[:n] for v,h in audit.ANCHORS.values() if v==va)
            def relcall(self,va):return next(t for v,t in audit.CALLS.values() if v==va)
        self.assertEqual(len(audit.verify(PE())['anchors']),len(audit.ANCHORS))
        class Bad(PE):
            def read(self,va,n):return bytes(n)
        with self.assertRaises(a.AuditError):audit.verify(Bad())
    def test_static_wrong_agent_identity(self):
        with self.assertRaises(a.AuditError):audit.analyze(b'not-the-agent')

@unittest.skipUnless((FIX/'target.decoded').is_file() and (NATIVE/'prefix_oracle').is_file(),'Retail fixture and prefix native build required')
class PrefixFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w=old.b.Watch();cls.dec=cls.w.read(FIX/'target.decoded');cls.enc=enc.encode(cls.dec,'b:{256K*=z}')
    @classmethod
    def tearDownClass(cls):cls.w.check()
    def setup_fixture(self,t,seed=SEED):
        baseline=Path(t)/'baseline';root=Path(t)/'prefix';old.materialize(baseline,self.enc,self.dec);p.build(baseline,root,seed);return root,baseline
    def call(self,root,seed=SEED):return subprocess.run([str(NATIVE/'prefix_oracle'),str(root),seed.hex(),'1024'],capture_output=True,text=True,timeout=15)
    def object_call(self,root,ck=old.CK):return subprocess.run([str(NATIVE/'real_object_oracle'),str(root/old.expected_index()),str(root/'data.000'),old.EK,ck],capture_output=True,text=True,timeout=15)
    def test_complete_prefix_fixture_native(self):
        with tempfile.TemporaryDirectory() as t,patch('socket.socket',side_effect=AssertionError('network')):
            r,base=self.setup_fixture(t);self.assertFalse(p.verify(r)['archive_prefix_placeholder']);self.assertEqual(self.call(r).returncode,0);self.assertEqual(self.object_call(r).returncode,0);self.assertTrue(old.verify(base)['archive_prefix_placeholder'])
    def test_all_reserved_header_bytes_native_tamper(self):
        with tempfile.TemporaryDirectory() as t:
            r,_=self.setup_fixture(t);file=r/'data.000';orig=file.read_bytes()
            for at in range(480):
                raw=bytearray(orig);raw[at]^=1;file.write_bytes(raw);self.assertNotEqual(self.call(r).returncode,0,at)
    def test_all_index_files_native_tamper(self):
        with tempfile.TemporaryDirectory() as t:
            r,_=self.setup_fixture(t)
            for file in sorted(r.glob('*.idx')):
                orig=file.read_bytes();raw=bytearray(orig);raw[-1]^=1;file.write_bytes(raw);self.assertNotEqual(self.call(r).returncode,0,file.name);file.write_bytes(orig)
    def test_native_wrong_seed(self):
        with tempfile.TemporaryDirectory() as t:
            r,_=self.setup_fixture(t);self.assertNotEqual(self.call(r,bytes(16)).returncode,0)
    def test_native_seed_positive_vectors(self):
        for seed in (bytes(16),bytes([255])*16,bytes(range(16))):
            with tempfile.TemporaryDirectory() as t:
                r,_=self.setup_fixture(t,seed);self.assertEqual(self.call(r,seed).returncode,0);self.assertEqual(self.object_call(r).returncode,0)
    def test_payload_tamper_detected_by_object_oracle(self):
        with tempfile.TemporaryDirectory() as t:
            r,_=self.setup_fixture(t);file=r/'data.000';raw=bytearray(file.read_bytes());raw[-1]^=1;file.write_bytes(raw);self.assertNotEqual(self.object_call(r).returncode,0)
    def test_native_wrong_decoded_ckey(self):
        with tempfile.TemporaryDirectory() as t:
            r,_=self.setup_fixture(t);self.assertNotEqual(self.object_call(r,'0'*32).returncode,0)
    def test_output_existing_refused(self):
        with tempfile.TemporaryDirectory() as t:
            r,base=self.setup_fixture(t);before=(r/'data.000').read_bytes()
            with self.assertRaises(a.AuditError):p.build(base,r,SEED)
            self.assertEqual((r/'data.000').read_bytes(),before)
    def test_game_ancestor_refused(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t)/'.build.info').write_text('keep')
            with self.assertRaises(f.FormatError):p.build(Path('/missing'),Path(t)/'new',SEED)
    def test_baseline_tamper_refused_before_create(self):
        with tempfile.TemporaryDirectory() as t:
            r,base=self.setup_fixture(t);(base/'data.000').write_bytes(b'bad');out=Path(t)/'another'
            with self.assertRaises(a.AuditError):p.build(base,out,SEED)
            self.assertFalse(out.exists())
    def test_symlink_output_refused(self):
        with tempfile.TemporaryDirectory() as t:
            r,base=self.setup_fixture(t);link=Path(t)/'link';link.symlink_to(r,target_is_directory=True)
            with self.assertRaises(a.AuditError):p.build(base,link,SEED)
    def test_incomplete_and_extra_layout(self):
        with tempfile.TemporaryDirectory() as t:
            r,_=self.setup_fixture(t);(r/'extra').write_text('x')
            with self.assertRaises(a.AuditError):p.verify(r)
            (r/'extra').unlink();(r/'RECEIPT.json').unlink()
            with self.assertRaises((a.AuditError,OSError)):p.verify(r)
    def test_rehashed_receipt_cannot_override_semantics(self):
        with tempfile.TemporaryDirectory() as t:
            r,_=self.setup_fixture(t);file=r/'shmem';raw=bytearray(file.read_bytes());struct.pack_into('<I',raw,0x110,2);file.write_bytes(raw);q=r/'RECEIPT.json';receipt=json.loads(q.read_text());receipt['files']['shmem']={'size':len(raw),'sha256':a.sha256(bytes(raw))};q.write_text(json.dumps(receipt))
            with self.assertRaises(a.AuditError):p.verify(r)
    def test_index_truncation_native(self):
        with tempfile.TemporaryDirectory() as t:
            r,_=self.setup_fixture(t);file=r/old.expected_index();file.write_bytes(file.read_bytes()[:-1]);self.assertNotEqual(self.call(r).returncode,0);self.assertNotEqual(self.object_call(r).returncode,0)
    def test_marker_cannot_claim_install_ready(self):
        with tempfile.TemporaryDirectory() as t:
            r,_=self.setup_fixture(t);file=r/p.MARKER;m=json.loads(file.read_text());m['installation_ready']=True;file.write_text(json.dumps(m))
            with self.assertRaises(a.AuditError):p.verify(r)
if __name__=='__main__':unittest.main()
