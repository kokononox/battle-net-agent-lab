import ast,copy,json,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE));sys.path.append(str(HERE.parent/'prelogin-registry-stack'))
from report import blank,fold,validate,gui,load
from run_control import authorized,root_state,BRANCH
class Tests(unittest.TestCase):
 def test_blank(self):validate(blank('a'*40,'123'))
 def test_private_gui_removed(self):
  g=dict(observer_session_id=123,process_sessions=[dict(pid=456,session_id=123),dict(pid=987,session_id=234),dict(pid=654,session_id=None)],windows=[dict(visible=True,text='PRIVATE',hwnd=789)],window_station_visible=True,input_desktop_accessible=True)
  r=gui(g);self.assertEqual((r['same_session_processes'],r['different_session_processes'],r['unknown_session_processes']),(1,1,1));s=json.dumps(r);self.assertNotIn('PRIVATE',s);self.assertNotIn('456',s);self.assertNotIn('123',s);self.assertEqual(r['visible_owned_windows'],1)
 def test_station_unknown(self):self.assertIsNone(gui({})['window_station_visible'])
 def test_no_type_coercion_station(self):self.assertIsNone(gui(dict(window_station_visible=1))['window_station_visible'])
 def test_unlaunched_cannot_sample(self):
  r=blank('a'*40,'123');r['root_samples']['running']=1;self.assertRaises(ValueError,validate,r)
 def test_launch_requires_pin(self):
  r=blank('a'*40,'123');r['target_launched']=True;self.assertRaises(ValueError,validate,r)
 def test_derived_report(self):
  r=blank('a'*40,'123');r['target_launched']=True;r['bootstrap_pin_match']=True;r['root_samples']['running']=2;r['root_state_before_cleanup']='running';fold(dict(status='bootstrapper_observed_agent_not_observed',samples=[],gui_observations=[],language_step={}),r)
 def test_readiness_identity_bound(self):
  r=blank('a'*40,'123');r['readiness']['run_id']='456';self.assertRaises(ValueError,validate,r)
 def test_raw_field_rejected(self):
  r=blank('a'*40,'123');r['path']='PRIVATE';self.assertRaises(ValueError,validate,r)
 def test_raw_gui_field_rejected(self):
  r=blank('a'*40,'123');g=gui({});g['pid']=123;r['desktop_observations']=[g];self.assertRaises(ValueError,validate,r)
 def test_bad_count_rejected(self):
  r=blank('a'*40,'123');r['root_samples']['unknown']=True;self.assertRaises(ValueError,validate,r)
 def test_snapshot_cap(self):
  r=blank('a'*40,'123');r['desktop_observations']=[gui({})]*4;self.assertRaises(ValueError,validate,r)
 def test_root_cap(self):
  r=blank('a'*40,'123');r['root_samples'].update(running=128,unknown=1);self.assertRaises(ValueError,validate,r)
 def test_injection_not_claimable(self):
  r=blank('a'*40,'123');r['limits']['injection_requested']=True;self.assertRaises(ValueError,validate,r)
 def test_causality_not_claimable(self):
  r=blank('a'*40,'123');r['limits']['observer_causality_proven']=True;self.assertRaises(ValueError,validate,r)
 def test_duplicate_json(self):self.assertRaises(ValueError,load,b'{"schema":1,"schema":2}')
 def test_roundtrip(self):r=blank('a'*40,'123');self.assertEqual(load(json.dumps(r).encode()),r)
 def test_gate(self):
  e=dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_NAME='push',GITHUB_REF=BRANCH,BNET_BOOTSTRAP_CONTROL='approved-bootstrap-control-b2');self.assertTrue(authorized(e,'win32'))
  for k in e:
   x=e.copy();x[k]='wrong';self.assertFalse(authorized(x,'win32'),k)
  self.assertFalse(authorized(e,'linux'))
 def test_root_states(self):
  class P:
   def __init__(self,v):self.v=v
   def poll(self):return self.v
  for v,w in [(None,'running'),(0,'exited_zero'),(1,'exited_nonzero'),(-1,'exited_nonzero')]:self.assertEqual(root_state(P(v)),w)
 def test_root_failure(self):
  class P:
   def poll(self):raise OSError()
  self.assertEqual(root_state(P()),'unknown')
 def test_no_frida_import(self):
  t=ast.parse((HERE/'run_control.py').read_text())
  for n in ast.walk(t):
   if isinstance(n,ast.Import):self.assertTrue(all(a.name!='frida' for a in n.names))
   if isinstance(n,ast.ImportFrom):self.assertNotEqual(n.module,'frida')
