"""Real pinned sample; isolated research stores only. Set fixture/native env vars."""
import json,os,subprocess,sys,tempfile,unittest,shutil
from pathlib import Path
import retail_update_cycle as c
import name_seed_model as names
import patch_audit as a

FIXTURE=os.environ.get('RETAIL_POC_FIXTURE')
NATIVE=os.environ.get('CYCLE_NATIVE_DIR')
@unittest.skipUnless(FIXTURE and NATIVE,'explicit real sample and native tools required')
class Cycle(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name);self.root=self.base/'store';self.native=Path(NATIVE)
        self.source=(Path(FIXTURE)/'source.blte').read_bytes();self.patch=(Path(FIXTURE)/'sample.zbsdiff').read_bytes()
        self.origin={'format':'cycle-portable-input-proof-1','original_fixture_manifest_verified':True,'source_full_ekey_verified':True,'patch_hash_verified':True,'target_ckey':c.old.CK}
        self.named=names.model('LAB-PC',r'C:\Games\World of Warcraft\Data')
        c.create(self.root,self.source,self.patch,self.named,self.origin)
        self.initial=(self.root/'data.000').read_bytes()
    def snapshot(self,root=None):
        return {p.name:(a.sha256(p.read_bytes()),p.stat().st_mtime_ns,p.stat().st_ino) for p in (root or self.root).iterdir()}
    def native_status(self):return c.native_status(self.root,self.native/'cycle_oracle',self.native/'real_object_oracle')
    def advance(self,bind=None):return c.advance(self.root,bind=bind or (lambda p:c.native_bind(self.native/'real_object_oracle',p)))
    def crash(self,phase):
        run=subprocess.run([sys.executable,'-B',str(Path(c.__file__)),'advance','--root',str(self.root),'--native-object-oracle',str(self.native/'real_object_oracle'),'--test-exit-after',phase],capture_output=True,timeout=10)
        self.assertEqual(run.returncode,91,run.stderr.decode())
    def rejected_unchanged(self):
        before=self.snapshot()
        with self.assertRaises(Exception):self.advance()
        self.assertEqual(before,self.snapshot())
    def test_initial_native_source_only(self):
        s=self.native_status();self.assertFalse(s['selection']['target_visible']);self.assertTrue(s['source']['decoded_ckey_verified']);self.assertIsNone(s['target'])
    def test_real_update_preserves_source(self):
        self.assertTrue(self.advance()['target_published']);self.assertEqual((self.root/'data.000').read_bytes()[:668],self.initial);self.assertTrue(self.native_status()['target']['decoded_ckey_verified'])
    def test_idempotent_without_file_changes(self):
        self.advance();before=self.snapshot();self.assertTrue(self.advance()['idempotent_noop']);self.assertEqual(before,self.snapshot())
    def test_status_readonly(self):
        before=self.snapshot();c.status(self.root);self.native_status();self.assertEqual(before,self.snapshot())
    def test_binding_failure_keeps_header_old(self):
        with self.assertRaisesRegex(Exception,'cycle_index_bind_failed'):self.advance(lambda p:False)
        self.assertFalse(self.native_status()['selection']['target_visible']);self.assertEqual(c.status(self.root)['pending_unpublished_tail_bytes'],188);self.advance()
    def test_native_binding_failure_keeps_header_old(self):
        with self.assertRaises(Exception):self.advance(lambda p:c.native_bind(self.native/'cycle_oracle',p))
        self.assertFalse(self.native_status()['selection']['target_visible'])
    def test_orphan_higher_index_not_selected(self):
        (self.root/c.idx(2,2)).write_bytes(c.tables(bytes.fromhex(self.named['seed']),True)[2])
        self.assertFalse(self.native_status()['selection']['target_visible']);self.rejected_unchanged()
    def test_index_noreplace_preserves_destination(self):
        x=self.base/'x';y=self.base/'y';x.write_bytes(b'x');y.write_bytes(b'y')
        with self.assertRaises(Exception):c.publish_index_noreplace(x,y)
        self.assertEqual(x.read_bytes(),b'x');self.assertEqual(y.read_bytes(),b'y')
    def test_cross_workspace_journal_rejected(self):
        other=self.base/'other';c.create(other,self.source,self.patch,self.named,self.origin);self.crash('prepared');(other/c.JOURNAL).write_bytes((self.root/c.JOURNAL).read_bytes())
        with self.assertRaisesRegex(Exception,'cycle_journal_binding'):c.advance(other)
    def test_lock_busy(self):
        with c.locked(self.root):
            run=subprocess.run([sys.executable,'-B',str(Path(c.__file__)),'status','--root',str(self.root)],capture_output=True,timeout=5)
            self.assertNotEqual(run.returncode,0);self.assertIn(b'cycle_busy',run.stderr)
        self.assertFalse(c.status(self.root)['target_published'])
    def test_existing_root_refused(self):
        before=self.snapshot()
        with self.assertRaises(Exception):c.create(self.root,self.source,self.patch,self.named,self.origin)
        self.assertEqual(before,self.snapshot())
    def test_symlink_root_refused(self):
        link=self.base/'link';link.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(Exception):c.status(link)
    def test_hardlinked_data_refused(self):
        os.link(self.root/'data.000',self.base/'linked-data');self.rejected_unchanged()
    def test_unknown_file_refused(self):
        (self.root/'unexpected').write_bytes(b'x');self.rejected_unchanged()
    def test_wrong_partial_append_refused(self):
        self.crash('target_half_appended');f=self.root/'data.000';raw=bytearray(f.read_bytes());raw[-1]^=1;f.write_bytes(raw);self.rejected_unchanged()
    def test_unjournaled_append_refused(self):
        self.crash('target_data_synced');(self.root/c.JOURNAL).unlink();self.rejected_unchanged()
    def test_wrong_journal_refused(self):
        self.crash('prepared');f=self.root/c.JOURNAL;j=json.loads(f.read_bytes());j['target_encoded_sha256']='0'*64;f.write_text(json.dumps(j));self.rejected_unchanged()
    def test_old_source_index_preserved(self):
        f=self.root/c.idx(5,1);before=f.read_bytes();self.advance();self.assertEqual(before,f.read_bytes())
    def test_wrong_index_refused_before_publish(self):
        self.crash('index_named');f=self.root/c.idx(2,2);raw=bytearray(f.read_bytes());raw[-1]^=1;f.write_bytes(raw);self.rejected_unchanged()
    def test_missing_selected_index_refused(self):
        self.advance();(self.root/c.idx(2,2)).unlink();self.rejected_unchanged()
    def test_wrong_sequence_refused(self):
        f=self.root/'shmem';raw=bytearray(f.read_bytes());raw[0x118]=3;f.write_bytes(raw);self.rejected_unchanged()
    def test_published_partial_refused(self):
        self.crash('prepared');(self.root/'shmem').write_bytes(c.control(True));self.rejected_unchanged()
    def test_source_corruption_refused(self):
        f=self.root/'data.000';raw=bytearray(f.read_bytes());raw[600]^=1;f.write_bytes(raw);self.rejected_unchanged()
    def test_prefix_corruption_refused(self):
        f=self.root/'data.000';raw=bytearray(f.read_bytes());raw[30]^=1;f.write_bytes(raw);self.rejected_unchanged()
    def test_patch_corruption_refused(self):
        f=self.root/'PATCH.zbsdiff';raw=bytearray(f.read_bytes());raw[-1]^=1;f.write_bytes(raw);self.rejected_unchanged()
    def test_index_temporary_corruption_refused(self):
        self.crash('index_temp_synced');(self.root/c.INDEX_TMP).write_bytes(b'bad');self.rejected_unchanged()
    def test_control_temporary_corruption_refused(self):
        self.crash('control_temp_synced');(self.root/c.CONTROL_TMP).write_bytes(b'bad');self.rejected_unchanged()
    def test_receipts_never_claim_install_ready(self):
        for r in (c.status(self.root),self.advance(),self.native_status()):self.assertIs(r['installation_ready'],False)

def crash_case(phase):
    def run(self):
        self.crash(phase);published=phase in ('control_published','committed');s=self.native_status();self.assertEqual(s['selection']['target_visible'],published)
        self.assertEqual(c.status(self.root)['target_published'],published);self.advance();self.assertTrue(self.native_status()['target']['decoded_ckey_verified'])
        self.assertEqual((self.root/'data.000').read_bytes()[:668],self.initial);before=self.snapshot();self.assertTrue(self.advance()['idempotent_noop']);self.assertEqual(before,self.snapshot())
    return run
for phase in c.PHASES:setattr(Cycle,'test_crash_resume_'+phase,crash_case(phase))
