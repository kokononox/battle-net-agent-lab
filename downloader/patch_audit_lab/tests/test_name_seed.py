import hashlib,json,os,random,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import patch_audit as a
import name_seed_model as m
import archive_prefix_poc as prefix
import agent_name_seed_audit as audit
import retail_storage_poc as old
import encoding_target as enc

ORACLE=Path(os.environ.get('NAME_SEED_ORACLE','/missing'))
FIX=Path(os.environ.get('RETAIL_POC_FIXTURE','/missing'))
NATIVE=Path(os.environ.get('PREFIX_NATIVE_DIR','/missing'))
class NameSeedModelTests(unittest.TestCase):
    def test_drive_case_only(self):self.assertEqual(m.lexical(r'C:\Games\WoW\Data'),'c:/Games/WoW/Data')
    def test_dot_segments_and_trailing_slash(self):self.assertEqual(m.lexical('C:/A//B/./C/../'),'c:/A/B/')
    def test_unc_leading_pair(self):self.assertEqual(m.lexical('\\\\SERVER\\Share\\A\\..\\'),'//SERVER/Share/')
    def test_raw_normalizer_does_not_protect_drive_root(self):self.assertEqual(m.lexical('C:/../x'),'x')
    def test_wrapper_rejects_drive_escape(self):
        with self.assertRaises(a.AuditError):m.prepare('C:/../x')
    def test_unc_escape_rejected(self):
        with self.assertRaises(a.AuditError):m.prepare('//SERVER/Share/../Other')
    def test_relative_requires_explicit_cwd(self):
        with self.assertRaises(a.AuditError):m.prepare('Data')
        self.assertEqual(m.prepare('A/../Data',r'C:\Games\WoW')[1],'c:/Games/WoW/Data')
    def test_absolute_cwd_ambiguity(self):
        with self.assertRaises(a.AuditError):m.prepare('C:/Data','C:/Other')
    def test_unsupported_windows_forms(self):
        for s in ('C:Data','/Data',r'\Data',r'\\?\C:\Data',r'\\.\C:\Data','C:/Data:stream','C:/A*'):
            with self.subTest(s=s),self.assertRaises(a.AuditError):m.prepare(s)
    def test_path_input_bounds_and_types(self):
        for s in ('', 'C:/'+('a'*773),'C:/D\0ata','C:/D\nata','C:/بازی',b'C:/Data',None):
            with self.subTest(s=s),self.assertRaises(a.AuditError):m.lexical(s)
    def test_computer_input_bounds(self):
        for name in ('','X'*16,'LAB\0PC','کامپیوتر','A/B','A\\B',None):
            with self.subTest(name=name),self.assertRaises(a.AuditError):m.derive(name,'c:/Data')
    def test_hash_is_concat_no_delimiter_or_nul(self):
        self.assertEqual(m.derive('LAB-PC','c:/Data'),hashlib.md5(b'LAB-PCc:/Data').digest())
        self.assertNotEqual(m.derive('LAB-PC','c:/Data'),hashlib.md5(b'LAB-PC\0c:/Data\0').digest())
    def test_host_case_preserved(self):self.assertNotEqual(m.derive('LAB-PC','c:/Data'),m.derive('lab-pc','c:/Data'))
    def test_path_case_preserved(self):self.assertNotEqual(m.model('LAB-PC','C:/Data')['seed'],m.model('LAB-PC','C:/data')['seed'])
    def test_drive_letter_case_equivalent(self):self.assertEqual(m.model('LAB-PC','C:/Data')['seed'],m.model('LAB-PC','c:/Data')['seed'])
    def test_no_environment_inference(self):
        with patch('os.getcwd',side_effect=AssertionError('host cwd')),patch('socket.gethostname',side_effect=AssertionError('host computer')),patch('socket.socket',side_effect=AssertionError('network')):
            self.assertFalse(m.model('LAB-PC','Data','C:/Game')['actual_user_installation_binding_proven'])
    def test_static_wrong_identity(self):
        with self.assertRaises(a.AuditError):audit.analyze(b'bad')
    def test_static_verifier_fail_closed(self):
        class PE:
            def read(self,va,n):
                if va==0x86d019:return b'\xff\x15'+(0x8fb55c).to_bytes(4,'little')
                return next(bytes.fromhex(h)[:n] for v,h in audit.ANCHORS.values() if v==va)
            def relcall(self,va):return next(t for v,t in audit.CALLS.values() if v==va)
            def imports(self):return {0x8fb55c:{'dll':'KERNEL32.dll','name':'GetComputerNameW'}}
        self.assertEqual(len(audit.verify(PE())['anchors']),17)
        class Bad(PE):
            def imports(self):return {0x8fb55c:{'dll':'KERNEL32.dll','name':'GetComputerNameA'}}
        with self.assertRaises(a.AuditError):audit.verify(Bad())

@unittest.skipUnless(ORACLE.is_file(),'built Linux i386 pure-fragment oracle required')
class NameSeedFragmentTests(unittest.TestCase):
    def test_known_vector_complete_chain(self):
        got=m.compare(ORACLE,'LAB-PC',r'C:\Games\World of Warcraft\Data');self.assertEqual(got['seed'],'13c12f1aaed0ac3d869b3fc98e77f84d');self.assertTrue(got['fragment_comparison']['matched'])
    def test_250_deterministic_raw_lexical_vectors(self):
        rng=random.Random(9824)
        for _ in range(250):
            raw=rng.choice(['C:/','//server/share/','/',''])+rng.choice(['/','\\']).join(rng.choice(['A','b','..','.','','WoW','Data']) for _ in range(rng.randrange(1,10)))
            raw=raw or '.';v=m.oracle(ORACLE,'LAB-PC',raw);self.assertEqual(v['canonical_path'],m.lexical(raw));seed=m.derive('LAB-PC',m.lexical(raw));self.assertEqual(v['seed'],seed.hex());self.assertEqual(v['reserved_keys'],[k.hex() for k in prefix.keys(seed,0,1024)])
    def test_md5_block_padding_boundaries(self):
        for total in (54,55,56,57,63,64,65,119,120,127,128,129,255,512,778):
            raw='C:/'+('x'*(total-6));v=m.oracle(ORACLE,'LAB',raw);self.assertEqual(v['seed'],m.derive('LAB',m.lexical(raw)).hex())
    def test_maximum_supported_raw_path(self):self.assertTrue(m.compare(ORACLE,'X'*15,'C:/'+('a'*772))['fragment_comparison']['matched'])
    def test_raw_empty_normalization(self):self.assertEqual(m.oracle(ORACLE,'LAB-PC','/a/..')['canonical_path'],'')
    def test_relative_join_policy_then_fragment(self):self.assertTrue(m.compare(ORACLE,'LAB-PC','A/../Data','C:/Games/WoW')['fragment_comparison']['matched'])
    def test_unc_complete_chain(self):self.assertTrue(m.compare(ORACLE,'LAB-PC',r'\\Server\Share\A\..\Data')['fragment_comparison']['matched'])
    def test_native_rejects_overlong_host(self):
        p=subprocess.run([str(ORACLE),'X'*16,'C:/Data'],capture_output=True,timeout=5);self.assertEqual(p.returncode,90);self.assertFalse(p.stdout)
    def test_native_rejects_non_ascii_and_empty(self):
        for host,path in [('LAB','C:/بازی'),('','C:/Data'),('LAB','')]:
            p=subprocess.run([str(ORACLE),host,path],capture_output=True,timeout=5);self.assertEqual(p.returncode,90)
    def test_windows_flags_remain_false(self):
        v=m.compare(ORACLE,'LAB-PC','C:/Data');self.assertFalse(v['installation_ready']);self.assertFalse(v['windows_agent_process_executed']);self.assertTrue(v['fragment_comparison']['isolated_agent_pure_fragments_executed'])

@unittest.skipUnless(ORACLE.is_file() and (FIX/'target.decoded').is_file() and (NATIVE/'prefix_oracle').is_file(),'Retail fixture and both oracles required')
class NameSeedRealRetailTests(unittest.TestCase):
    def test_derived_seed_to_real_retail_readback(self):
        w=old.b.Watch();decoded=w.read(FIX/'target.decoded');encoded=enc.encode(decoded,'b:{256K*=z}')
        with tempfile.TemporaryDirectory() as t,patch('socket.socket',side_effect=AssertionError('network')):
            root=Path(t);base=root/'baseline';out=root/'derived-prefix';old.materialize(base,encoded,decoded)
            got=m.compare(ORACLE,'LAB-PC',r'C:\Games\World of Warcraft\Data');p=prefix.build(base,out,bytes.fromhex(got['seed']));self.assertFalse(p['archive_prefix_placeholder']);self.assertTrue(prefix.native(out,NATIVE/'prefix_oracle')['accepted'])
            native=subprocess.run([str(NATIVE/'real_object_oracle'),str(out/old.expected_index()),str(out/'data.000'),old.EK,old.CK],capture_output=True,text=True,timeout=15);self.assertEqual(native.returncode,0,native.stdout);self.assertTrue(json.loads(native.stdout)['decoded_ckey_verified']);old.verify(base)
        w.check()
if __name__=='__main__':unittest.main()
