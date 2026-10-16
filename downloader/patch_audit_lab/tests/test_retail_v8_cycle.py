import hashlib,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import retail_v8_cycle as c
import retail_update_cycle as oldcycle
import agent_bind_contract as bind
import patch_audit as a
ORACLE=Path(os.environ.get('BIND_CONTRACT_ORACLE','/missing'));PRIOR=Path(os.environ.get('V8_PRIOR_CYCLE','/missing'))
def hashes(root):return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()}
@unittest.skipUnless(ORACLE.is_file() and PRIOR.is_dir(),'original bind oracle and completed owned V7 cycle required')
class V8Cycle(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory();cls.base=Path(cls.temp.name);cls.template=cls.base/'template';c.create(PRIOR,cls.template,ORACLE)
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def setUp(self):self.temp2=tempfile.TemporaryDirectory();self.root=Path(self.temp2.name)/'v8';shutil.copytree(self.template,self.root)
 def tearDown(self):self.temp2.cleanup()
 def advance(self):return c.advance(self.root,ORACLE)
 def test_initial_source_only(self):self.assertEqual(c.status(self.root,ORACLE)['visible_objects'],1)
 def test_no_legacy_marker_masquerade(self):self.assertFalse((self.root/oldcycle.MARKER).exists())
 def test_every_index_is_v8(self):
  for i in range(16):self.assertEqual(int.from_bytes((self.root/oldcycle.idx(i,1)).read_bytes()[8:10],'little'),8)
 def test_real_cycle(self):
  result=self.advance();self.assertTrue(result['target_published']);self.assertTrue(result['mandatory_native_gate']);self.assertEqual(result['visible_objects'],2)
 def test_source_and_prefix_unchanged(self):
  before=(self.root/'data.000').read_bytes();self.advance();self.assertEqual((self.root/'data.000').read_bytes()[:668],before)
 def test_initial_indexes_never_replaced(self):
  before={n:h for n,h in hashes(self.root).items() if n.endswith('.idx')};self.advance();after=hashes(self.root);self.assertTrue(all(after[n]==h for n,h in before.items()))
 def test_only_target_sequence_changed(self):
  before=(self.root/'shmem').read_bytes();self.advance();after=(self.root/'shmem').read_bytes();at=4*c.fmt.bucket(c.TARGET);seq0=before[0x110:0x150];seq1=after[0x110:0x150];self.assertEqual(seq0[:at]+seq0[at+4:],seq1[:at]+seq1[at+4:]);self.assertEqual(int.from_bytes(seq1[at:at+4],'little'),2);self.assertEqual(after,oldcycle.control(True))
 def test_idempotent_rebind_no_write(self):
  self.advance();before=hashes(self.root);result=self.advance();self.assertTrue(result['idempotent_noop']);self.assertEqual(before,hashes(self.root));self.assertTrue(result['original_agent_inner_bind_verified'])
 def test_all_nine_hard_exit_resume_boundaries(self):
  for name in c.PHASES:
   with self.subTest(name=name):
    root=Path(self.temp2.name)/name;shutil.copytree(self.template,root);p=subprocess.run([sys.executable,'-B',str(Path(c.__file__)),'advance','--root',str(root),'--oracle',str(ORACLE),'--test-exit-after',name],capture_output=True,timeout=20);self.assertEqual(p.returncode,91,p.stderr.decode());result=c.advance(root,ORACLE);self.assertTrue(result['target_published']);self.assertEqual((root/'data.000').stat().st_size,856);self.assertTrue(c.advance(root,ORACLE)['idempotent_noop'])
 def test_actual_mapping_failure_at_candidate_blocks_publish_then_resume(self):
  actual=bind.compare;header=(self.root/'shmem').read_bytes()
  def failing(binary,raw,bucket,**kw):return actual(binary,raw,bucket,map_error=73,**kw) if bytes.fromhex(c.TARGET) in raw else actual(binary,raw,bucket,**kw)
  with patch.object(bind,'compare',side_effect=failing),self.assertRaises(a.AuditError):self.advance()
  self.assertEqual((self.root/'shmem').read_bytes(),header);self.assertEqual(json.loads((self.root/c.JOURNAL).read_text())['state'],'prepared');self.assertTrue((self.root/oldcycle.idx(c.fmt.bucket(c.TARGET),2)).exists());self.assertTrue(self.advance()['target_published'])
 def test_missing_oracle_no_write(self):
  before=hashes(self.root)
  with self.assertRaises((ValueError,OSError)):c.advance(self.root,Path(self.temp2.name)/'missing')
  self.assertEqual(before,hashes(self.root))
 def test_bad_oracle_no_write(self):
  fake=Path(self.temp2.name)/'fail';fake.write_text('#!/bin/sh\nexit 1\n');fake.chmod(0o700);before=hashes(self.root)
  with self.assertRaises(a.AuditError):c.advance(self.root,fake)
  self.assertEqual(before,hashes(self.root))
 def test_mutated_source_rejected(self):
  p=self.root/'data.000';r=bytearray(p.read_bytes());r[-1]^=1;p.write_bytes(r)
  with self.assertRaises((a.AuditError,ValueError)):self.advance()
 def test_mutated_index_rejected(self):
  p=self.root/oldcycle.idx(0,1);r=bytearray(p.read_bytes());r[50]^=1;p.write_bytes(r)
  with self.assertRaises(a.AuditError):self.advance()
 def test_unexpected_generation_not_selected(self):
  (self.root/'0200000099.idx').write_bytes((self.root/oldcycle.idx(2,1)).read_bytes())
  with self.assertRaises(a.AuditError):self.advance()
 def test_unknown_files_rejected(self):
  (self.root/'unexpected').write_text('x')
  with self.assertRaises(a.AuditError):self.advance()
 def test_foreign_journal_rejected(self):
  self.advance();p=self.root/c.MARKER;r=json.loads(p.read_text());r['workspace_id']='00000000-0000-0000-0000-000000000000';p.write_text(json.dumps(r))
  with self.assertRaises(a.AuditError):self.advance()
 def test_symlink_data_rejected(self):
  p=self.root/'data.000';r=p.read_bytes();p.unlink();other=Path(self.temp2.name)/'data';other.write_bytes(r);p.symlink_to(other)
  with self.assertRaises(ValueError):self.advance()
 def test_existing_output_refused(self):
  with self.assertRaises((a.AuditError,ValueError)):c.create(PRIOR,self.root,ORACLE)
 def test_original_owned_store_readonly(self):
  before=hashes(PRIOR);out=Path(self.temp2.name)/'other';c.create(PRIOR,out,ORACLE);c.advance(out,ORACLE);self.assertEqual(before,hashes(PRIOR))

 def test_modified_oracle_binary_refused_before_write(self):
  folder=Path(self.temp2.name)/'native';folder.mkdir();fake=folder/'bind_contract_oracle';blob=bytearray(ORACLE.read_bytes());blob[-1]^=1;fake.write_bytes(blob);fake.chmod(0o700);shutil.copyfile(ORACLE.parent/'BUILD-RECEIPT.json',folder/'BUILD-RECEIPT.json');before=hashes(self.root)
  with self.assertRaises(a.AuditError):c.advance(self.root,fake)
  self.assertEqual(before,hashes(self.root))
 def test_unpinned_build_receipt_refused_before_write(self):
  folder=Path(self.temp2.name)/'native';folder.mkdir();fake=folder/'bind_contract_oracle';shutil.copyfile(ORACLE,fake);fake.chmod(0o700);receipt=json.loads((ORACLE.parent/'BUILD-RECEIPT.json').read_text());receipt['agent_sha256']='0'*64;(folder/'BUILD-RECEIPT.json').write_text(json.dumps(receipt));before=hashes(self.root)
  with self.assertRaises(a.AuditError):c.advance(self.root,fake)
  self.assertEqual(before,hashes(self.root))
