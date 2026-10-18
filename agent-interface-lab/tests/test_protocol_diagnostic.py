import copy,json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import classic_install as c
import probe as p
from test_classic_install import report,form
from test_probe import Response,Connection

class ProtocolDiagnosticTests(unittest.TestCase):
 def session(self,response,r=None,verify=lambda:True):
  r=report()if r is None else r;conn=Connection(response)
  return c.Session(1234,'synthetic-private-token',verify,r,lambda *a,**kw:conn),r,conn
 def test_201_valid_json_only_on_initial_post(self):
  s,r,conn=self.session(Response(json.dumps(form()).encode(),status=201))
  data=s.request('POST','/install',c.initialized_payload());c.inspect_form(data,r)
  self.assertEqual(r['initialization_http_status'],201);self.assertTrue(r['initialization_json_object']);self.assertTrue(r['initialization_form_present']);self.assertEqual(r['initialization_form_field_count'],3)
  self.assertTrue(r['initialization_response_accepted']);self.assertTrue(conn.closed)
 def test_201_not_accepted_for_game_get(self):
  s,r,conn=self.session(Response(b'{}',status=201))
  with self.assertRaisesRegex(p.Stop,'response_refused'):s.request('GET','/game')
  self.assertFalse(r['initialization_json_object'])
 def test_201_not_accepted_for_finalization(self):
  s,r,conn=self.session(Response(b'{}',status=201));s.init=True;r['initialization_response_accepted']=True
  with self.assertRaisesRegex(p.Stop,'response_refused'):s.request('POST','/install/'+c.PRODUCT,{})
 def test_201_does_not_skip_json_limits(self):
  for response in [Response(b'not-json',status=201),Response(b'{"error":0,"error":1}',status=201),Response(b'[]',status=201),Response(b'x'*65537,status=201),Response(b'{}',{'Content-Encoding':'gzip'},201)]:
   s,r,conn=self.session(response)
   with self.assertRaises(p.Stop):s.request('POST','/install',{})
   self.assertFalse(r['initialization_response_accepted']);self.assertEqual(len(conn.calls),1)
   with self.assertRaises(p.Stop):s.request('POST','/install',{})
   self.assertEqual(len(conn.calls),1)
 def test_201_unknown_form_no_finalization(self):
  f=form();f['form']['private-field']={'value':'private-data'}
  s,r,conn=self.session(Response(json.dumps(f).encode(),status=201));data=s.request('POST','/install',{})
  with self.assertRaises(p.Stop):c.inspect_form(data,r)
  self.assertTrue(r['unknown_form_fields'])
  for secret in ('private-field','private-data','synthetic-private-token'):self.assertNotIn(secret,json.dumps(r))
 def test_201_does_not_bypass_auth_or_eula(self):
  for f,stop in [(dict(error=0,form={**form()['form'],'eula':{}}),'legal_consent_required'),(dict(error=0,form={**form()['form'],'authentication':{'error':5}}),'authentication_required')]:
   s,r,conn=self.session(Response(json.dumps(f).encode(),status=201));data=s.request('POST','/install',{})
   with self.assertRaisesRegex(p.Stop,stop):c.inspect_form(data,r)
   self.assertFalse(r['finalization_attempted'])
 def test_201_metadata_is_not_acceptance_after_identity_failure(self):
  checks=iter([True,False]);s,r,conn=self.session(Response(json.dumps(form()).encode(),status=201),verify=lambda:next(checks))
  with self.assertRaisesRegex(p.Stop,'identity_changed'):s.request('POST','/install',{})
  self.assertTrue(r['initialization_json_object']);self.assertFalse(r['initialization_response_accepted'])
 def test_diagnostic_mode_rejects_final_post_even_if_form_accepted(self):
  r=report();r.update(protocol_diagnostic_only=True,initialization_response_accepted=True)
  s,r,conn=self.session(Response(b'{}'),r);s.init=True
  with self.assertRaisesRegex(p.Stop,'request_refused'):s.request('POST','/install/'+c.PRODUCT,{})
  self.assertFalse(conn.calls);self.assertFalse(r['finalization_attempted'])
 def test_diagnostic_mode_stops_after_initialization(self):
  r=report();r.update(protocol_diagnostic_only=True,approval_present=True,destination_fixed_drive=True,destination_new_empty=True,identity_check_count=1,last_identity_state='verified',last_identity_stage='after_handshake')
  replies=iter([Response(b'{}'),Response(json.dumps(form()).encode(),status=201)]);calls=[]
  def factory(*args,**kw):
   conn=Connection(next(replies));calls.append(conn);return conn
  real=c.Session
  with patch.object(c,'Session',side_effect=lambda *args:real(*args,connection_factory=factory)),patch.object(c,'disk_pair',return_value=(c.MIN_FREE,c.MIN_FREE)):
   c.observe('synthetic-private-token',1234,lambda:True,r,None,None,lambda path:False)
  self.assertEqual(r['status'],'form_diagnostic_complete');self.assertEqual(r['total_local_requests'],2);self.assertFalse(r['finalization_attempted']);c.validate(r)
 def test_diagnostic_schema_rejects_mutation_and_raw_evidence(self):
  r=report();r['protocol_diagnostic_only']=True;r['finalization_attempted']=True
  with self.assertRaises(ValueError):c.validate(r)
  r=report();r['raw_identity_path']='private'
  with self.assertRaises(ValueError):c.validate(r)
 def test_first_identity_failure_is_sticky_and_has_no_private_strings(self):
  r=report();c.record_identity(r,'verified','after_handshake');c.record_identity(r,'listener_changed','observer');c.record_identity(r,'process_exited','after_observer')
  self.assertEqual(r['identity_failure_state'],'listener_changed');self.assertEqual(r['identity_failure_stage'],'observer');self.assertEqual(r['last_identity_state'],'process_exited');self.assertEqual(r['identity_check_count'],3);c.validate(r)
  with self.assertRaises(ValueError):c.record_identity(r,'raw-private-string','observer')
 def test_identity_verified(self):
  proc=SimpleNamespace(pid=123,poll=lambda:None);agent=Path('Agent.exe').resolve()
  with patch.object(p,'process_image',return_value=agent),patch.object(p,'listener_rows',return_value=[('127.0.0.1',1234)]):self.assertEqual(p.identity_state(proc,agent,(1234,'loopback')),'verified')
 def test_identity_failure_reasons(self):
  proc=SimpleNamespace(pid=123,poll=lambda:None);agent=Path('Agent.exe').resolve()
  self.assertEqual(p.identity_state(SimpleNamespace(poll=lambda:0),agent,(1234,'loopback')),'process_exited')
  with patch.object(p,'process_image',return_value=Path('other.exe')):self.assertEqual(p.identity_state(proc,agent,(1234,'loopback')),'image_changed')
  for rows,expected in [([],'listener_missing'),([('127.0.0.1',1235)],'listener_changed'),([('127.0.0.1',1),('127.0.0.1',2)],'listener_not_unique')]:
   with patch.object(p,'process_image',return_value=agent),patch.object(p,'listener_rows',return_value=rows):self.assertEqual(p.identity_state(proc,agent,(1234,'loopback')),expected)
  with patch.object(p,'process_image',side_effect=OSError('private')):self.assertEqual(p.identity_state(proc,agent,(1234,'loopback')),'inspection_failed')
if __name__=='__main__':unittest.main()
