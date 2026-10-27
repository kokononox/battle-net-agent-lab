import ast,copy,json,sys,unittest
from pathlib import Path
H=Path(__file__).resolve().parent
sys.path.insert(0,str(H));sys.path.append(str(H.parent/'prelogin-registry-stack'))
from attach_session import Session,SOURCE,blank as ab
from registry_events import APIS
from report import blank,validate,load,valid_attach,gui,CHECKS,registry_blank,PIN
from run_registry_only import authorized,BRANCH
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
 r=ab();r.update(status='ready',attach_returned=True,image_verified_before_and_after=True,ready=True,pointer_bits=bits,bitness_confirmed=True,registry_ready=True);return r
def good():
 r=blank('a'*40,'123');r['native_gate']=[dict(architecture=a,passed=True,exit_code=0,attach=ready(b),error_kind=None,probe_checks={k:True for k in CHECKS},registry_errors=0,registry_limits=0) for a,b in [('x64',64),('x86',32)]];r.update(bootstrap_pin_match=True,target_launched=True,status='observation_complete',target_attach=ready());r['readiness']['status']='agent_process_observed';r['baseline_before_target']=dict(status='absent',value_present=False,valid_uuid=False);return r
def new_session(d):return Session(Frida,d,H/'dummy.exe','a'*64)
def reg_reply(bits=32):
 return [({'type':'send','payload':dict(kind='reg_installed',api=a)},None) for a in sorted(APIS)]+[({'type':'send','payload':dict(kind='reg_ready',pointer_bits=bits)},None)]
def value_event():return dict(kind='reg_value',api='RegQueryValueExW',operation='read',label='target',status=0,value_type=1,caller_rva=123,stack_status='captured',verified_image_stack_rvas=[123],image_scope='verified',process_main_matches_verified_image=False)
class Tests(unittest.TestCase):
 def test_blank(self):validate(blank('a'*40,'123'))
 def test_good(self):validate(good())
 def test_attach_and_double_identity(self):
  d=Device(reg_reply()+[message()]);s=new_session(d);calls=[];r=s.start(123,lambda:calls.append('verified'),32)
  self.assertEqual(r,ready());self.assertEqual(calls,['verified','verified']);self.assertEqual(d.attaches,[123]);self.assertTrue(d.remote.source.endswith(SOURCE));self.assertIn('registryTrace',d.remote.source);self.assertNotIn('wire_hook',d.remote.source);s.close();self.assertTrue(d.remote.detached)
 def test_no_attach_before_identity(self):
  d=Device(reg_reply()+[message()]);s=new_session(d)
  def bad():raise RuntimeError('private')
  r=s.start(123,bad,32);self.assertEqual(r['status'],'failed');self.assertEqual(d.attaches,[]);self.assertNotIn('private',json.dumps(r))
 def test_no_ready_claim_on_wrong_bitness(self):
  d=Device(reg_reply(64)+[message(64)]);s=new_session(d);r=s.start(123,lambda:None,32);self.assertEqual(r['status'],'failed');self.assertFalse(r['bitness_confirmed'])
 def test_recheck_failure(self):
  d=Device(reg_reply()+[message()]);s=new_session(d);calls=[]
  def verify():
   calls.append(1)
   if len(calls)>1:raise RuntimeError('private')
  r=s.start(123,verify,32);self.assertEqual(r['status'],'failed');self.assertFalse(r['image_verified_before_and_after'])
 def test_duplicate_message_is_error(self):
  d=Device(reg_reply()+[message(),message()]);s=new_session(d);r=s.start(123,lambda:None,32);self.assertEqual(r['status'],'failed');self.assertEqual(r['message_errors'],1)
 def test_raw_data_rejected(self):
  s=new_session(Device([]));m,_=message();s.message(m,b'PRIVATE');self.assertEqual(s.record['message_errors'],1);self.assertNotIn('PRIVATE',json.dumps(s.record))
 def test_extra_message_field_rejected(self):
  s=new_session(Device([]));m,_=message();m['payload']['path']='PRIVATE';s.message(m,None);self.assertEqual(s.record['message_errors'],1)
 def test_script_error_rejected(self):
  s=new_session(Device([]));s.message({'type':'error','description':'PRIVATE'},None);self.assertEqual(s.record['message_errors'],1);self.assertNotIn('PRIVATE',json.dumps(s.record))
 def test_bool_bits_rejected(self):
  s=new_session(Device([]));m,_=message();m['payload']['pointer_bits']=True;s.message(m,None);self.assertFalse(s.record['ready'])
 def test_error_cap(self):
  s=new_session(Device([]))
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
  for k in ('network_hook_requested','child_gating_requested','suspended_spawn_requested','process_birth_coverage','observer_causality_proven'):
   r=good();r['limits'][k]=True;self.assertRaises(ValueError,validate,r)
 def test_true_limits_not_numeric(self):
  r=good();r['limits']['ordinary_popen_launch']=1;self.assertRaises(ValueError,validate,r)
 def test_complete_requires_observation(self):
  r=good();r['readiness']['status']='not_observed';self.assertRaises(ValueError,validate,r)
 def test_duplicate_json(self):self.assertRaises(ValueError,load,b'{"schema":1,"schema":2}')
 def test_roundtrip(self):r=good();self.assertEqual(load(json.dumps(r).encode()),r)
 def test_guard(self):
  e=dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_NAME='push',GITHUB_REF=BRANCH,BNET_REGISTRY_ONLY='approved-registry-only-b4');self.assertTrue(authorized(e,'win32'))
  for k in e:
   other=e.copy();other[k]='wrong';self.assertFalse(authorized(other,'win32'))
  self.assertFalse(authorized(e,'linux'))
 def test_no_spawn_or_child_gating_calls(self):
  for name in ['attach_session.py','run_registry_only.py','native_gate.py']:
   tree=ast.parse((H/name).read_text())
   for node in ast.walk(tree):
    if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute):self.assertNotIn(node.func.attr,['spawn','enable_child_gating'])
class RegistryTests(unittest.TestCase):
 def test_native_probe_checks_required(self):
  r=good();r['native_gate'][0]['probe_checks']['read_a']=False;self.assertRaises(ValueError,validate,r)
 def test_native_registry_errors_fail_gate(self):
  r=good();r['native_gate'][0]['registry_errors']=1;self.assertRaises(ValueError,validate,r)
 def test_registry_before_launch_baseline(self):
  r=good();r['baseline_before_target']=None;self.assertRaises(ValueError,validate,r)
 def test_error_baseline_refuses_launch(self):
  r=good();r['baseline_before_target']=dict(status='error',value_present=False,valid_uuid=False);self.assertRaises(ValueError,validate,r)
 def test_no_registry_ready_claim_without_hook_ready(self):
  a=ready();a['registry_ready']=False;self.assertRaises(ValueError,valid_attach,a)
 def test_registry_only_flag_required(self):
  r=good();r['limits']['registry_hook_requested']=False;self.assertRaises(ValueError,validate,r)
 def test_no_wire_comparison_allowed(self):
  r=good();r['registry']['wire_comparison_performed']=True;self.assertRaises(ValueError,validate,r)
 def test_no_uuid_or_hash_export(self):
  s=new_session(Device([]));s.row=dict(pid=123,sha256=PIN)
  s.message({'type':'send','payload':value_event()},b'abcdefab-abcd-4abc-abcd-abcdefabcdef\0')
  r=s.summary();j=json.dumps(r);self.assertNotIn('abcdefab',j);self.assertNotIn('equals_wire_host_id',j);self.assertTrue(r['records'][0]['valid_uuid']);self.assertFalse(r['wire_comparison_performed'])
 def test_good_public_registry_record(self):
  s=new_session(Device([]));s.row=dict(pid=123,sha256=PIN);s.message({'type':'send','payload':value_event()},b'abcdefab-abcd-4abc-abcd-abcdefabcdef\0')
  r=good();r['registry']=s.summary();validate(r)
 def test_no_other_process_digest_allowed(self):
  s=new_session(Device([]));s.row=dict(pid=123,sha256='a'*64);s.message({'type':'send','payload':value_event()},None)
  r=good();r['registry']=s.summary();self.assertRaises(ValueError,validate,r)
 def test_raw_registry_record_refused(self):
  s=new_session(Device([]));s.row=dict(pid=123,sha256=PIN);s.message({'type':'send','payload':value_event()},None)
  r=good();r['registry']=s.summary();r['registry']['records'][0]['uuid']='PRIVATE';self.assertRaises(ValueError,validate,r)
 def test_registry_error_extra_field_rejected(self):
  s=new_session(Device([]));s.row=dict(pid=123,sha256=PIN);s.message({'type':'send','payload':dict(kind='reg_error',path='PRIVATE')},None);self.assertEqual(s.registry.errors,1)
 def test_registry_message_type_rejected(self):
  s=new_session(Device([]));s.row=dict(pid=123,sha256=PIN);s.message({'type':'error','payload':dict(kind='reg_ready',pointer_bits=32)},None);self.assertEqual(s.registry.errors,1)
 def test_registry_ready_bool_rejected(self):
  s=new_session(Device([]));s.row=dict(pid=123,sha256=PIN);s.message({'type':'send','payload':dict(kind='reg_ready',pointer_bits=True)},None);self.assertEqual(s.registry.errors,1)
 def test_registry_duplicate_ready_rejected(self):
  s=new_session(Device([]));s.row=dict(pid=123,sha256=PIN)
  for _ in range(2):s.message({'type':'send','payload':dict(kind='reg_ready',pointer_bits=32)},None)
  self.assertEqual(s.registry.errors,1)
 def test_registry_ready_bitness_mismatch(self):
  s=new_session(Device(reg_reply(64)+[message(32)]));r=s.start(123,lambda:None,32);self.assertEqual(r['status'],'failed')
 def test_wire_equality_field_rejected(self):
  s=new_session(Device([]));s.row=dict(pid=123,sha256=PIN);s.message({'type':'send','payload':value_event()},None)
  r=good();r['registry']=s.summary();r['registry']['records'][0]['equals_wire_host_id']=False;self.assertRaises(ValueError,validate,r)
 def test_registry_unlaunched_is_empty(self):
  r=blank('a'*40,'123');r['registry']['ready_processes']=1;self.assertRaises(ValueError,validate,r)
