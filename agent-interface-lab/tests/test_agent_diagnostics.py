import copy,hashlib,json,os,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import agent_diagnostics as d
import classic_install as c
import probe
from test_classic_install import report,form
from test_probe import Response,Connection

class AgentDiagnosticsTests(unittest.TestCase):
 def test_form_exports_names_and_types_never_values(self):
  form={'account_country':{'type':'secret-string','value':'private-value','nested':{'password':'secret'}},'eula':{'url':'https://secret.invalid/private-token','accepted':False}}
  r=d.summarize_form(form);text=json.dumps(r)
  self.assertEqual(r['field_count'],2);self.assertEqual(r['fields'][0]['name'],'account_country')
  for value in ('secret-string','private-value','password','https://secret.invalid','private-token'):self.assertNotIn(value,text)
  self.assertEqual(r['fields'][0]['members'][2],dict(name='nested',type='object'))
 def test_bad_names_redacted(self):
  r=d.summarize_form({'https://private.invalid/token':{'Email@example.com':'secret'},'A'*200:'secret'})
  self.assertIsNone(r['fields'][0]['name']);self.assertIsNone(r['fields'][0]['members'][0]['name']);self.assertIsNone(r['fields'][1]['name']);d.validate_form(r)
 def test_form_caps_and_boolean_type(self):
  self.assertEqual(d.summarize_form({str(i):{}for i in range(33)})['status'],'refused')
  r=d.summarize_form({'large':{str(i):'secret'for i in range(40)},'flag':True})
  self.assertEqual(r['fields'][0]['member_count'],33);self.assertEqual(r['fields'][0]['members'],[]);self.assertEqual(r['fields'][1]['type'],'boolean')
 def test_shape_schema_rejects_value_injection(self):
  r=d.summarize_form({'safe':{'value':'secret'}});r['fields'][0]['members'][0]['value']='secret'
  with self.assertRaises(ValueError):d.validate_form(r)
 def fixture(self,tmp):
  root=Path(tmp)/'Agent';folder=root/'Agent.1234';folder.mkdir(parents=True)
  pinned=folder/'Agent.exe';pinned.write_bytes(b'MZ-synthetic-signed-fixture')
  observed=folder/'Agent.exe.old';pinned.rename(observed)
  proc=SimpleNamespace(pid=123,poll=lambda:None);hash=hashlib.sha256(observed.read_bytes()).hexdigest()
  return root,pinned,observed,proc,hash
 def inspect(self,root,pinned,observed,proc,hash,**kwargs):
  return d.inspect_transition(proc,pinned,(1234,'loopback'),root,hash,kwargs.get('process_image',lambda pid:observed),kwargs.get('listener_rows',lambda pid:[('127.0.0.1',1234)]),kwargs.get('is_reparse',lambda path:False),kwargs.get('signature',lambda path,env:{'accepted_for_execution':True}),{})
 def test_renamed_binary_read_only_signature_and_hash(self):
  with tempfile.TemporaryDirectory()as tmp:
   root,pinned,observed,proc,hash=self.fixture(tmp)
   r=self.inspect(root,pinned,observed,proc,hash)
   self.assertEqual(r['status'],'inspected_read_only');self.assertEqual(r['path_relation'],'different_within_agent_root');self.assertTrue(r['observed_signature_accepted']);self.assertTrue(r['matches_initial_sha256']);self.assertFalse(r['pinned_path_exists']);self.assertTrue(r['original_listener_still_owned']);self.assertEqual(r['observed_relative_path'],'Agent.1234/Agent.exe.old');self.assertNotIn(tmp,json.dumps(r));self.assertTrue(observed.exists());self.assertFalse(pinned.exists())
 def test_bounded_renamed_agent_suffix_is_diagnostic_not_trusted(self):
  with tempfile.TemporaryDirectory()as tmp:
   root,pinned,observed,proc,hash=self.fixture(tmp)
   renamed=observed.with_name('Agent.exe.delete.1234.5678');observed.rename(renamed)
   r=self.inspect(root,pinned,renamed,proc,hash)
   self.assertEqual(r['status'],'inspected_read_only');self.assertEqual(r['observed_relative_path'],'Agent.1234/Agent.exe.delete.1234.5678');self.assertTrue(r['matches_initial_sha256'])
 def test_path_label_cannot_traverse_or_export_full_path(self):
  for value in ('../Agent.exe','./Agent.exe','Agent.1/../Agent.exe','C:/private/Agent.exe','Agent.1/secret?token.exe'):
   r=d.blank_transition();r['observed_relative_path']=value
   with self.assertRaises(ValueError,msg=value):d.validate_transition(r)
 def test_outside_path_never_opened_or_signed(self):
  with tempfile.TemporaryDirectory()as tmp:
   root,pinned,observed,proc,hash=self.fixture(tmp)
   def forbidden(*args):raise AssertionError('unexpected_inspection')
   r=self.inspect(root,pinned,Path(tmp)/'private'/ 'Agent.exe',proc,hash,signature=forbidden,is_reparse=forbidden)
   self.assertEqual(r['status'],'outside_scope');self.assertIsNone(r['observed_relative_path']);self.assertIsNone(r['observed_sha256']);self.assertNotIn('private',json.dumps(r))
 def test_reparse_refused_before_signature(self):
  with tempfile.TemporaryDirectory()as tmp:
   root,pinned,observed,proc,hash=self.fixture(tmp)
   def forbidden(*args):raise AssertionError('unexpected_signature')
   r=self.inspect(root,pinned,observed,proc,hash,is_reparse=lambda path:path==root,signature=forbidden)
   self.assertEqual(r['status'],'path_refused');self.assertIsNone(r['observed_sha256'])
 def test_changed_bytes_and_bad_signature_are_not_trusted(self):
  with tempfile.TemporaryDirectory()as tmp:
   root,pinned,observed,proc,hash=self.fixture(tmp);observed.write_bytes(b'MZ-different-data')
   r=self.inspect(root,pinned,observed,proc,hash,signature=lambda *args:{'accepted_for_execution':False})
   self.assertFalse(r['matches_initial_sha256']);self.assertFalse(r['observed_signature_accepted']);self.assertNotIn('accepted_for_execution',r)
 def test_live_image_change_during_diagnostic_is_not_stable(self):
  with tempfile.TemporaryDirectory()as tmp:
   root,pinned,observed,proc,hash=self.fixture(tmp);paths=iter([observed,pinned])
   r=self.inspect(root,pinned,observed,proc,hash,process_image=lambda pid:next(paths))
   self.assertEqual(r['status'],'snapshot_unstable');self.assertFalse(r['snapshot_stable'])
 def test_oversize_file_refused(self):
  with tempfile.TemporaryDirectory()as tmp:
   root,pinned,observed,proc,hash=self.fixture(tmp)
   with patch.object(d,'MAX_BINARY',5):r=self.inspect(root,pinned,observed,proc,hash)
   self.assertEqual(r['status'],'path_refused');self.assertEqual(r['observed_bytes_hashed'],0)
 def test_transition_schema_no_raw_path_or_false_success(self):
  r=d.blank_transition();d.validate_transition(r)
  for key,value in [('raw_path','private'),('observed_relative_path','C:/private/Agent.exe'),('observed_sha256','wrong'),('status','inspected_read_only')]:
   bad=copy.deepcopy(r);bad[key]=value
   with self.assertRaises(ValueError,msg=key):d.validate_transition(bad)
 def test_valid_transition_signature_never_adopts_new_image(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp)/'Battle.net'/'Agent';folder=root/'Agent.1234';folder.mkdir(parents=True);(folder/'Agent.exe').write_bytes(b'MZ-fixture')
   env=dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1',AGENT_INTERFACE_ONCE=probe.APPROVAL,GITHUB_SHA='a'*40,GITHUB_RUN_ID='123',RUNNER_TEMP=tmp,ProgramData=tmp,SystemRoot=tmp)
   lab=SimpleNamespace(clean_environment=lambda e:e,snapshot=lambda e:{'processes':[]},observe=lambda *a,**kw:{'status':'agent_process_observed','language_step':{'status':'continued','outcome_uncertain':False},'safety':{'account_login_attempted':False,'game_download_requested':False},'cleanup_attempted':True},is_reparse=lambda p:False,signature=lambda *a:{'accepted_for_execution':True},stop_observed=lambda *a:None)
   proc=SimpleNamespace(pid=123,poll=lambda:None);seen=[]
   details=d.blank_transition();details.update(status='inspected_read_only',path_relation='different_within_agent_root',observed_sha256='a'*64,observed_signature_accepted=True,snapshot_stable=True)
   def handshake(port,r):
    r.update(http_requests_attempted=1,http_status=200,response_bytes=2,response_json_object=True,authorization_token_present=True,status='handshake_token_observed');return 'synthetic-token'
   def observer(token,port,verify):verify()
   with patch.dict(os.environ,env),patch.dict(sys.modules,observe_agent=lab),patch.object(probe.sys,'platform','win32'),patch.object(probe.subprocess,'Popen',return_value=proc),patch.object(probe.subprocess,'run'),patch.object(probe,'process_image',return_value=folder/'Agent.exe'),patch.object(probe,'listener_rows',return_value=[('127.0.0.1',1234)]),patch.object(probe,'request_agent',side_effect=handshake),patch.object(probe,'identity_state',side_effect=['verified','image_changed']),patch.object(d,'inspect_transition',return_value=details):
    result=probe.run(Path(tmp)/'out',after_handshake=observer,identity_details_observer=seen.append)
   self.assertEqual(result['status'],'identity_changed');self.assertEqual(len(seen),1);self.assertTrue(seen[0]['observed_signature_accepted'])
 def test_metadata_preserved_when_identity_fails_no_finalization(self):
  f=form();f['form'].update(account_country={'value':'private-country'},eula={'accepted':False})
  r=report();r['protocol_diagnostic_only']=True;checks=iter([True,False]);conn=Connection(Response(json.dumps(f).encode(),status=201))
  s=c.Session(1234,'synthetic-token',lambda:next(checks),r,lambda *args,**kw:conn)
  with self.assertRaisesRegex(probe.Stop,'identity_changed'):s.request('POST','/install',{})
  names=[x['name']for x in r['form_structure']['fields']]
  self.assertIn('account_country',names);self.assertIn('eula',names);self.assertNotIn('private-country',json.dumps(r));self.assertFalse(r['initialization_response_accepted']);self.assertFalse(r['finalization_attempted'])
if __name__=='__main__':unittest.main()
