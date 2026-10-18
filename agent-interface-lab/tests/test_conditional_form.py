import copy,hashlib,json,os,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import agent_diagnostics as d
import classic_install as c
import probe
from test_classic_install import report,form

class ConditionalFormTests(unittest.TestCase):
 def details(self):
  r=d.blank_transition();r.update(status='inspected_read_only',path_relation='different_within_agent_root',initial_relative_path='Agent.1234/Agent.exe',observed_relative_path='Agent.1234/temp_'+('a'*32)+'.exe',observed_signature_accepted=True,observed_sha256='b'*64,matches_initial_sha256=True,snapshot_stable=True,original_listener_still_owned=True)
  return r
 def test_all_metadata_conditions_required(self):
  good=self.details();self.assertTrue(d.eligible_temp_transition(good,'b'*64))
  changes=[('observed_signature_accepted',False),('observed_sha256','c'*64),('matches_initial_sha256',False),('snapshot_stable',False),('original_listener_still_owned',False),('observed_relative_path','Agent.9999/temp_'+('a'*32)+'.exe'),('observed_relative_path','Agent.1234/other.exe'),('status','inspection_failed')]
  for key,value in changes:
   r=copy.deepcopy(good);r[key]=value;self.assertFalse(d.eligible_temp_transition(r,'b'*64),key)
 def run_fixture(self,signature_ok=True,hash_ok=True,socket_ok=True):
  with tempfile.TemporaryDirectory()as tmp:
   folder=Path(tmp)/'Battle.net'/'Agent'/'Agent.1234';folder.mkdir(parents=True)
   pinned=folder/'Agent.exe';pinned.write_bytes(b'MZ-fixture');observed=folder/('temp_'+('a'*32)+'.exe');observed.write_bytes(b'MZ-fixture'if hash_ok else b'MZ-other-bytes')
   env=dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1',AGENT_INTERFACE_ONCE=probe.APPROVAL,GITHUB_SHA='a'*40,GITHUB_RUN_ID='123',RUNNER_TEMP=tmp,ProgramData=tmp,SystemRoot=tmp)
   phase=[False];states=[];details=[]
   lab=SimpleNamespace(clean_environment=lambda e:e,snapshot=lambda e:{'processes':[]},observe=lambda *a,**kw:{'status':'agent_process_observed','language_step':{'status':'continued','outcome_uncertain':False},'safety':{'account_login_attempted':False,'game_download_requested':False},'cleanup_attempted':True},is_reparse=lambda p:False,signature=lambda path,env:{'accepted_for_execution':signature_ok if path==observed else True},stop_observed=lambda *a:None)
   proc=SimpleNamespace(pid=123,poll=lambda:None)
   def image(pid):self.assertEqual(pid,123);return observed if phase[0]else pinned
   def rows(pid):self.assertEqual(pid,123);return [('127.0.0.1',1235 if phase[0]and not socket_ok else 1234)]
   def handshake(port,r):r.update(http_requests_attempted=1,http_status=200,response_bytes=2,response_json_object=True,authorization_token_present=True,status='handshake_token_observed');return 'synthetic-token'
   def observer(token,port,verify):phase[0]=True;self.assertEqual(port,1234);verify()
   with patch.dict(os.environ,env),patch.dict(sys.modules,observe_agent=lab),patch.object(probe.sys,'platform','win32'),patch.object(probe.subprocess,'Popen',return_value=proc),patch.object(probe.subprocess,'run'),patch.object(probe,'process_image',side_effect=image),patch.object(probe,'listener_rows',side_effect=rows),patch.object(probe,'request_agent',side_effect=handshake):
    result=probe.run(Path(tmp)/'out',after_handshake=observer,identity_observer=lambda state,stage:states.append(state),identity_details_observer=details.append,allow_verified_temp_image=True)
   return result,states,details
 def test_opt_in_allows_only_same_signed_image_same_listener(self):
  result,states,details=self.run_fixture();self.assertEqual(result['status'],'handshake_token_observed');self.assertEqual(states.count('verified_temp_image'),2);self.assertEqual(len(details),2)
 def test_bad_signature_hash_or_listener_refused(self):
  for kw in [dict(signature_ok=False),dict(hash_ok=False),dict(socket_ok=False)]:
   result,states,details=self.run_fixture(**kw);self.assertEqual(result['status'],'identity_changed');self.assertNotIn('verified_temp_image',states)
 def test_counter_is_not_identity_failure(self):
  r=report();r.update(protocol_diagnostic_only=True,conditional_temp_identity_enabled=True)
  c.record_identity(r,'verified_temp_image','observer');self.assertEqual(r['temp_image_verifications'],1);self.assertIsNone(r['identity_failure_state']);c.validate(r)
 def actual_form(self):
  f=form();f['form'].update(eula={'error':0,'eula':False},finalized=False,shortcut='private-shortcut',tome_path={'error':0});return f
 def test_all_error_codes_recorded_no_acceptance(self):
  r=report();r['protocol_diagnostic_only']=True;f=self.actual_form();f['error']=6
  for name,code in [('authentication',7),('min_spec',3),('game_dir',2),('eula',4),('tome_path',5)]:f['form'][name]['error']=code
  c.diagnose_form(f,r)
  self.assertEqual(r['status'],'form_diagnostic_complete');self.assertTrue(r['diagnostic_form_schema_valid']);self.assertEqual(r['auth_error_code'],7);self.assertEqual(r['min_spec_error_code'],3);self.assertEqual(r['game_dir_error_code'],2);self.assertEqual(r['eula_error_code'],4);self.assertEqual(r['tome_path_error_code'],5);self.assertEqual(r['initialization_agent_error_code'],6)
  self.assertEqual(set(r['diagnostic_form_blockers']),{'authentication_error','minimum_spec_error','game_dir_error','eula_error','tome_path_error','agent_error','eula_review_pending'})
  self.assertFalse(r['initialization_response_accepted']);self.assertFalse(r['finalization_attempted']);self.assertFalse(r['legal_terms_accepted']);self.assertNotIn('private-shortcut',json.dumps(r))
 def test_zero_error_eula_presence_is_review_not_requirement_proof(self):
  r=report();c.diagnose_form(self.actual_form(),r)
  self.assertEqual(r['diagnostic_form_blockers'],['eula_review_pending']);self.assertEqual(r['eula_error_code'],0);self.assertTrue(r['diagnostic_form_schema_valid']);self.assertFalse(r['legal_terms_accepted'])
 def test_bad_extra_shapes_and_unknowns_refused(self):
  for name,value in [('finalized','true'),('shortcut',{}),('shortcut','x'*2049),('tome_path',{'error':False}),('tome_path',{'error':0,'extra':'private'}),('new_unknown',True)]:
   r=report();f=self.actual_form();f['form'][name]=value;c.diagnose_form(f,r)
   self.assertEqual(r['status'],'initialization_form_unknown',name);self.assertFalse(r['diagnostic_form_schema_valid']);self.assertFalse(r['finalization_attempted'])
 def test_bool_or_missing_error_refused_but_other_codes_collected(self):
  r=report();f=self.actual_form();f['form']['authentication']['error']=True;f['form']['game_dir']['error']=123
  c.diagnose_form(f,r);self.assertFalse(r['diagnostic_form_schema_valid']);self.assertEqual(r['game_dir_error_code'],123);self.assertIsNone(r['auth_error_code'])
 def test_mode_cannot_escape_diagnostic_scope(self):
  r=report();r['conditional_temp_identity_enabled']=True
  with self.assertRaises(ValueError):c.validate(r)
  r=report();r['protocol_diagnostic_only']=True;r['conditional_temp_identity_enabled']=True;r['temp_image_verifications']=1
  with self.assertRaises(ValueError):c.validate(r)
if __name__=='__main__':unittest.main()
