import json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from bootstrap_readiness import blank,fold,validate,load
class Tests(unittest.TestCase):
 def test_blank(self):validate(blank('a'*40,'123'))
 def test_no_raw(self):
  b=dict(status='agent_process_observed',samples=[dict(processes=[dict(name='agent.exe',path='PRIVATE',uuid='PRIVATE')])],gui_observations=[],language_step=dict(status='continued'))
  r=fold(b,'a'*40,'123');self.assertNotIn('PRIVATE',json.dumps(r));self.assertEqual(r['observed_names'],['agent.exe'])
 def test_unknown_field_refused(self):
  r=blank('a'*40,'123');r['path']='private';self.assertRaises(ValueError,validate,r)
 def test_duplicate_refused(self):self.assertRaises(ValueError,load,b'{"x":1,"x":2}')
 def test_bool_count_refused(self):
  r=blank('a'*40,'123');r['sample_count']=True;self.assertRaises(ValueError,validate,r)
 def test_install_refused(self):
  r=blank('a'*40,'123');r['install_action_requested']=True;self.assertRaises(ValueError,validate,r)
 def test_gui_bound(self):
  r=blank('a'*40,'123');r['gui_snapshot_count']=4;self.assertRaises(ValueError,validate,r)
