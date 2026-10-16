import json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import retail_span_cycle as c
import retail_v8_cycle as base
import retail_update_cycle as old
import agent_span_reader as span
import patch_audit as a
BIND=Path(os.environ.get('BIND_CONTRACT_ORACLE','/missing'));LOOKUP=Path(os.environ.get('LOOKUP_MERGE_ORACLE','/missing'));SPAN=Path(os.environ.get('SPAN_READER_ORACLE','/missing'));PRIOR=Path(os.environ.get('V8_PRIOR_CYCLE','/missing'))
def hashes(root):return {p.name:a.sha256(p.read_bytes()) for p in root.iterdir() if p.is_file()}
@unittest.skipUnless(BIND.is_file() and LOOKUP.is_file() and SPAN.is_file() and PRIOR.is_dir(),'three original oracles and prior owned cycle required')
class SpanCycle(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.temp=tempfile.TemporaryDirectory();cls.template=Path(cls.temp.name)/'template';c.create(PRIOR,cls.template,BIND,LOOKUP,SPAN)
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def setUp(self):self.temp2=tempfile.TemporaryDirectory();self.root=Path(self.temp2.name)/'store';shutil.copytree(self.template,self.root)
 def tearDown(self):self.temp2.cleanup()
 def advance(self):return c.advance(self.root,BIND,LOOKUP,SPAN)
 def test_original_source_header_gate(self):self.assertEqual(c.status(self.root,BIND,LOOKUP,SPAN)['span_gate_objects'][0]['payload_offset'],510)
 def test_original_target_header_gate(self):self.assertEqual(self.advance()['span_gate_objects'][1]['payload_offset'],698)
 def test_mandatory_before_after_and_noop(self):
  with patch.object(c,'gate',wraps=c.gate) as spy:self.advance();self.assertEqual([x.args[4] for x in spy.call_args_list],[False,True,False])
  before=hashes(self.root)
  with patch.object(c,'gate',wraps=c.gate) as spy:r=self.advance();self.assertTrue(r['idempotent_noop']);self.assertEqual(spy.call_count,1)
  self.assertEqual(before,hashes(self.root))
 def test_nine_hard_exits_resume(self):
  for phase in base.PHASES:
   with self.subTest(phase=phase):
    root=Path(self.temp2.name)/phase;shutil.copytree(self.template,root);p=subprocess.run([sys.executable,'-B',str(Path(c.__file__)),'advance','--root',str(root),'--bind-oracle',str(BIND),'--lookup-oracle',str(LOOKUP),'--span-oracle',str(SPAN),'--test-exit-after',phase],capture_output=True,timeout=25);self.assertEqual(p.returncode,91,p.stderr.decode());r=c.advance(root,BIND,LOOKUP,SPAN);self.assertTrue(r['target_published']);self.assertTrue(r['mandatory_original_span_header_and_address_gate'])
 def test_original_bad_header_at_input_boundary_blocks_publication(self):
  original=span.compare;seen=[]
  def corrupt(oracle,h,address,*args,**kw):
   if address==668:
    h=bytearray(h);h[26]^=1;result=original(oracle,bytes(h),address,*args,**kw);seen.append(result['valid']);return result
   return original(oracle,h,address,*args,**kw)
  with patch.object(span,'compare',side_effect=corrupt),self.assertRaisesRegex(a.AuditError,'span_reader_original_header_rejected'):self.advance()
  self.assertEqual(seen,[False]);self.assertEqual((self.root/'shmem').read_bytes(),old.control(False));self.assertEqual(json.loads((self.root/base.JOURNAL).read_text())['state'],'prepared');self.assertTrue(self.advance()['target_published'])
 def test_missing_oracle_no_write(self):
  before=hashes(self.root)
  with self.assertRaises((ValueError,OSError)):c.advance(self.root,BIND,LOOKUP,Path(self.temp2.name)/'missing')
  self.assertEqual(before,hashes(self.root))
 def test_prior_original_unchanged(self):
  before=hashes(PRIOR);self.advance();self.assertEqual(before,hashes(PRIOR))
 def test_source_and_prefix_unchanged(self):
  initial=(self.root/'data.000').read_bytes();self.advance();self.assertEqual((self.root/'data.000').read_bytes()[:668],initial)
