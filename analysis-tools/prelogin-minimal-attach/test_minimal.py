import ast,copy,json,sys,unittest
from pathlib import Path
H=Path(__file__).resolve().parent
sys.path.insert(0,str(H));sys.path.append(str(H.parent/'prelogin-registry-stack'))
from attach_session import Session,SOURCE,blank as ab
from report import blank,validate,load,valid_attach,gui
from run_minimal import authorized,BRANCH
class Cancel:
 def __enter__(self):return self
 def __exit__(self,*a):pass
 def cancel(self):pass
class Frida:Cancellable=Cancel
class Script:
 def __init__(self,reply):self.callback=None;self.reply=reply
 def on(self,name,callback):assert name=='message';self.callback=callback
 def load(self):
  for msg,data in self.reply:self.callback(msg,data)
class Remote:
 def __init__(self,reply):self.script=Script(reply);self.detached=False;self.source=None
 def create_script(self,source):self.source=source;return self.script
 def detach(self):self.detached=True
class Device:
 def __init__(self,reply):self.remote=Remote(reply);self.attaches=[]
 def attach(self,pid):self.attaches.append(pid);return self.remote

def message(bits=32):return {'type':'send','payload':{'kind':'ready','pointer_bits':bits}},None
def ready(bits=32):
 r=ab();r.update(status='ready',attach_returned=True,image_verified_before_and_after=True,ready=True,pointer_bits=bits,bitness_confirmed=True);return r
def good():
 r=blank('a'*40,'123');r['native_gate']=[dict(architecture=a,passed=True,exit_code=0,attach=ready(b),error_kind=None) for a,b in [('x64',64),('x86',32)]];r.update(bootstrap_pin_match=True,target_launched=True,status='observation_complete',target_attach=ready());r['readiness']['status']='agent_process_observed';return r
class Tests(unittest.TestCase):
 def test_blank(self):validate(blank('a'*40,'123'))
 def test_good(self):validate(good())
 def test_attach_and_double_identity(self):
  d=Device([message()]);s=Session(Frida,d);calls=[];r=s.start(123,lambda:calls.append('verified'),32)
  self.assertEqual(r,ready());self.assertEqual(calls,['verified','verified']);self.assertEqual(d.attaches,[123]);self.assertEqual(d.remote.source,SOURCE);s.close();self.assertTrue(d.remote.detached)
 def test_no_attach_before_identity(self):
  d=Device([message()]);s=Session(Frida,d)
  def bad():raise RuntimeError('private')
  r=s.start(123,bad,32);self.assertEqual(r['status'],'failed');self.assertEqual(d.attaches,[]);self.assertNotIn('private',json.dumps(r))
 def test_no_ready_claim_on_wrong_bitness(self):
  d=Device([message(64)]);s=Session(Frida,d);r=s.start(123,lambda:None,32);self.assertEqual(r['status'],'failed');self.assertFalse(r['bitness_confirmed'])
 def test_recheck_failure(self):
  d=Device([message()]);s=Session(Frida,d);calls=[]
  def verify():
   calls.append(1)
   if len(calls)>1:raise RuntimeError('private')
  r=s.start(123,verify,32);self.assertEqual(r['status'],'failed');self.assertFalse(r['image_verified_before_and_after'])
 def test_duplicate_message_is_error(self):
  d=Device([message(),message()]);s=Session(Frida,d);r=s.start(123,lambda:None,32);self.assertEqual(r['status'],'failed');self.assertEqual(r['message_errors'],1)
 def test_raw_data_rejected(self):
  s=Session(Frida,Device([]));m,_=message();s.message(m,b'PRIVATE');self.assertEqual(s.record['message_errors'],1);self.assertNotIn('PRIVATE',json.dumps(s.record))
 def test_extra_message_field_rejected(self):
  s=Session(Frida,Device([]));m,_=message();m['payload']['path']='PRIVATE';s.message(m,None);self.assertEqual(s.record['message_errors'],1)
 def test_script_error_rejected(self):
  s=Session(Frida,Device([]));s.message({'type':'error','description':'PRIVATE'},None);self.assertEqual(s.record['message_errors'],1);self.assertNotIn('PRIVATE',json.dumps(s.record))
 def test_bool_bits_rejected(self):
  s=Session(Frida,Device([]));m,_=message();m['payload']['pointer_bits']=True;s.message(m,None);self.assertFalse(s.record['ready'])
 def test_error_cap(self):
  s=Session(Frida,Device([]))
  for _ in range(200):s.message({},None)
  self.assertEqual(s.record['message_errors'],128)
 def test_fixed_script_has_no_hooks(self):self.assertEqual(SOURCE,"send({kind:'ready',pointer_bits:Process.pointerSize*8});")
 def test_not_started_must_be_blank(self):
  a=ab();a['ready']=True;self.assertRaises(ValueError,valid_attach,a)
 def test_ready_cannot_have_errors(self):
  a=ready();a['message_errors']=1;self.assertRaises(ValueError,valid_attach,a)
 def test_ready_requires_identity(self):
  a=ready();a['image_verified_before_and_after']=False;self.assertRaises(ValueError,valid_attach,a)
 def test_raw_report_field(self):
  r=good();r['uuid']='PRIVATE';self.assertRaises(ValueError,validate,r)
 def test_raw_attach_field(self):
  r=good();r['target_attach']['pid']=123;self.assertRaises(ValueError,validate,r)
 def test_native_gate_before_target(self):
  r=good();r['native_gate']=[];self.assertRaises(ValueError,validate,r)
 def test_native_claim_requires_matching_bits(self):
  r=good();r['native_gate'][0]['attach']['pointer_bits']=32;self.assertRaises(ValueError,validate,r)
 def test_missing_native_arch(self):
  r=good();r['native_gate'].pop();self.assertRaises(ValueError,validate,r)
 def test_duplicate_native_arch(self):
  r=good();r['native_gate'][0]=copy.deepcopy(r['native_gate'][1]);self.assertRaises(ValueError,validate,r)
 def test_pin_before_launch(self):
  r=good();r['bootstrap_pin_match']=False;self.assertRaises(ValueError,validate,r)
 def test_no_attach_without_launch(self):
  r=blank('a'*40,'123');r['target_attach']=ready();self.assertRaises(ValueError,validate,r)
 def test_target_bitness(self):
  r=good();r['target_attach']=ready(64);self.assertRaises(ValueError,validate,r)
 def test_raw_gui_removed(self):
  r=gui(dict(observer_session_id=123,process_sessions=[dict(pid=777,session_id=123)],windows=[dict(visible=True,text='PRIVATE')]))
  self.assertEqual(r['same_session_processes'],1);self.assertNotIn('PRIVATE',json.dumps(r));self.assertNotIn('777',json.dumps(r))
 def test_readiness_source_bound(self):
  r=good();r['readiness']['source_commit']='b'*40;self.assertRaises(ValueError,validate,r)
 def test_limits_cannot_be_relaxed(self):
  for k in ('registry_hook_requested','network_hook_requested','child_gating_requested','suspended_spawn_requested','process_birth_coverage','observer_causality_proven'):
   r=good();r['limits'][k]=True;self.assertRaises(ValueError,validate,r)
 def test_true_limits_not_numeric(self):
  r=good();r['limits']['ordinary_popen_launch']=1;self.assertRaises(ValueError,validate,r)
 def test_complete_requires_observation(self):
  r=good();r['readiness']['status']='not_observed';self.assertRaises(ValueError,validate,r)
 def test_duplicate_json(self):self.assertRaises(ValueError,load,b'{"schema":1,"schema":2}')
 def test_roundtrip(self):r=good();self.assertEqual(load(json.dumps(r).encode()),r)
 def test_guard(self):
  e=dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_NAME='push',GITHUB_REF=BRANCH,BNET_MINIMAL_ATTACH='approved-minimal-attach-b3');self.assertTrue(authorized(e,'win32'))
  for k in e:
   other=e.copy();other[k]='wrong';self.assertFalse(authorized(other,'win32'))
  self.assertFalse(authorized(e,'linux'))
 def test_no_spawn_or_child_gating_calls(self):
  for name in ['attach_session.py','run_minimal.py','native_gate.py']:
   tree=ast.parse((H/name).read_text())
   for node in ast.walk(tree):
    if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute):self.assertNotIn(node.func.attr,['spawn','enable_child_gating'])
