import json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import retail_lookup_cycle as c
import retail_v8_cycle as base
import retail_update_cycle as old
import agent_lookup_merge as m
import agent_bind_contract as b
import patch_audit as a
BIND=Path(os.environ.get('BIND_CONTRACT_ORACLE','/missing'));LOOKUP=Path(os.environ.get('LOOKUP_MERGE_ORACLE','/missing'));PRIOR=Path(os.environ.get('V8_PRIOR_CYCLE','/missing'))
def hashes(root):return {p.name:a.sha256(p.read_bytes()) for p in root.iterdir() if p.is_file()}
@unittest.skipUnless(BIND.is_file() and LOOKUP.is_file() and PRIOR.is_dir(),'original bind/lookup oracles and completed owned V7 cycle required')
class LookupCycle(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.temp=tempfile.TemporaryDirectory();cls.template=Path(cls.temp.name)/'template';c.create(PRIOR,cls.template,BIND,LOOKUP)
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def setUp(self):self.temp2=tempfile.TemporaryDirectory();self.root=Path(self.temp2.name)/'store';shutil.copytree(self.template,self.root)
 def tearDown(self):self.temp2.cleanup()
 def advance(self):return c.advance(self.root,BIND,LOOKUP)
 def test_source_initial(self):self.assertEqual(c.status(self.root,BIND,LOOKUP)['lookup_gate_objects'][0]['returned_offset'],480)
 def test_target_completed(self):self.assertEqual(self.advance()['lookup_gate_objects'][1]['returned_offset'],668)
 def test_lookup_gate_runs_before_candidate_and_after(self):
  with patch.object(c,'gate',wraps=c.gate) as spy:self.advance();self.assertEqual([x.args[3] for x in spy.call_args_list],[False,True,False])
 def test_idempotent_rechecks_no_write(self):
  self.advance();before=hashes(self.root)
  with patch.object(c,'gate',wraps=c.gate) as spy:r=self.advance();self.assertTrue(r['idempotent_noop']);self.assertEqual(spy.call_count,1)
  self.assertEqual(before,hashes(self.root))
 def test_all_nine_hard_exits_resume(self):
  for phase in base.PHASES:
   with self.subTest(phase=phase):
    root=Path(self.temp2.name)/phase;shutil.copytree(self.template,root);p=subprocess.run([sys.executable,'-B',str(Path(c.__file__)),'advance','--root',str(root),'--bind-oracle',str(BIND),'--lookup-oracle',str(LOOKUP),'--test-exit-after',phase],capture_output=True,timeout=25);self.assertEqual(p.returncode,91,p.stderr.decode());r=c.advance(root,BIND,LOOKUP);self.assertTrue(r['target_published']);self.assertTrue(r['mandatory_original_lookup_merge_range_gate'])
 def test_real_lookup_gap_status_blocks_publish_then_resume(self):
  original=m.compare;target=base.TARGET;seen=[]
  def hole(oracle,raw,bucket,query,*args,**kw):
   if query==target:
    raw=m.build_index([b.record(target,668,188)],[(b.record(target,700,20),7)],bucket);out=original(oracle,raw,bucket,query,*args,**kw);seen.append(out['lookup']['status']);return out
   return original(oracle,raw,bucket,query,*args,**kw)
  with patch.object(m,'compare',side_effect=hole),self.assertRaises(a.AuditError):self.advance()
  self.assertEqual(seen,[3]);self.assertEqual((self.root/'shmem').read_bytes(),old.control(False));self.assertEqual(json.loads((self.root/base.JOURNAL).read_text())['state'],'prepared');self.assertTrue(self.advance()['target_published'])
 def test_missing_lookup_oracle_no_write(self):
  before=hashes(self.root)
  with self.assertRaises((ValueError,OSError)):c.advance(self.root,BIND,Path(self.temp2.name)/'missing')
  self.assertEqual(before,hashes(self.root))
 def test_mutated_lookup_oracle_no_write(self):
  folder=Path(self.temp2.name)/'native';folder.mkdir();oracle=folder/'lookup_merge_oracle';r=bytearray(LOOKUP.read_bytes());r[-1]^=1;oracle.write_bytes(r);oracle.chmod(0o700);shutil.copyfile(LOOKUP.parent/'BUILD-RECEIPT.json',folder/'BUILD-RECEIPT.json');before=hashes(self.root)
  with self.assertRaises(a.AuditError):c.advance(self.root,BIND,oracle)
  self.assertEqual(before,hashes(self.root))
 def test_prefix_source_immutable(self):
  before=(self.root/'data.000').read_bytes();self.advance();self.assertEqual((self.root/'data.000').read_bytes()[:668],before)
 def test_original_store_untouched(self):
  before=hashes(PRIOR);self.advance();self.assertEqual(before,hashes(PRIOR))
