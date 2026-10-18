import copy,http.server,json,os,socket,sys,tempfile,threading,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import classic_install as c
import probe
from test_probe import Response,Connection

def report():
 r=c.blank()
 for x in (r,r['handshake']):x.update(source_commit='a'*40,run_id='123',run_attempt='1')
 return r

def form():return {'error':0,'form':{k:{'error':0}for k in ('authentication','game_dir','min_spec')}}
class InstallTests(unittest.TestCase):
 def session(self,r=None,response=None):
  r=report()if r is None else r;conn=Connection(response or Response(b'{}'))
  return c.Session(1234,'synthetic-private-token',lambda:True,r,lambda *a,**k:conn),r,conn
 def test_blank_schema(self):c.validate(report())
 def test_no_extra_report_fields(self):
  r=report();r['raw']='secret'
  with self.assertRaises(ValueError):c.validate(r)
 def test_all_fixed_safety_flags(self):
  for k,v in report().items():
   if type(v)is bool and k not in c.MUTABLE_FLAGS:
    r=report();r[k]=not v
    with self.assertRaises(ValueError,msg=k):c.validate(r)
 def test_environment_one_shot(self):
  env=dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1',AGENT_INTERFACE_ONCE=probe.APPROVAL,CLASSIC_INSTALL_ONCE=c.APPROVAL,GITHUB_SHA='a'*40,GITHUB_RUN_ID='123')
  self.assertTrue(c.fresh_environment(env,'win32'))
  for k in env:
   bad=env.copy();bad[k]='wrong';self.assertFalse(c.fresh_environment(bad,'win32'),k)
  self.assertFalse(c.fresh_environment(env,'linux'))
 def test_routes_forbidden(self):
  for method,path in [('GET','/hardware'),('GET','/gamesession'),('POST','/update/'+c.PRODUCT),('POST','/uninstall'),('POST','/repair'),('POST','/install/wow')]:
   s,r,conn=self.session()
   with self.assertRaises(probe.Stop):s.request(method,path,{})
   self.assertFalse(conn.calls)
 def test_get_headers_and_privacy(self):
  s,r,conn=self.session();s.request('GET','/game');a,kw=conn.calls[0]
  self.assertEqual(a,('GET','/game'));self.assertEqual(kw['headers']['Authorization'],'synthetic-private-token');self.assertIsNone(kw['body']);self.assertTrue(conn.closed)
  self.assertNotIn('synthetic-private-token',json.dumps(r))
 def test_token_header_injection_rejected(self):
  with self.assertRaises(probe.Stop):c.Session(1234,'bad\r\nInjected: true',lambda:True,report())
 def test_no_mutation_retry(self):
  s,r,conn=self.session();s.request('POST','/install',c.initialized_payload())
  with self.assertRaises(probe.Stop):s.request('POST','/install',c.initialized_payload())
  self.assertEqual(len(conn.calls),1)
 def test_finalization_requires_accepted_form(self):
  s,r,conn=self.session();s.init=True
  with self.assertRaises(probe.Stop):s.request('POST','/install/'+c.PRODUCT,{})
  self.assertFalse(conn.calls)
 def test_no_update_or_fabricated_country(self):
  p=c.finalized_payload(Path('owned-target'))
  self.assertNotIn('account_country',p);self.assertNotIn('geo_ip_country',p);self.assertNotIn('eula',p)
  self.assertEqual(c.initialized_payload()['uid'],c.PRODUCT);self.assertNotEqual(c.PRODUCT,'wow')
 def test_identity_before_io(self):
  s,r,conn=self.session();s.verify=lambda:False
  with self.assertRaises(probe.Stop):s.request('GET','/game')
  self.assertEqual(r['total_local_requests'],0)
 def test_identity_after_io(self):
  s,r,conn=self.session();checks=iter([True,False]);s.verify=lambda:next(checks)
  with self.assertRaises(probe.Stop):s.request('GET','/game')
 def test_response_failure_no_redirect_retry(self):
  for response in (Response(status=302),Response(headers={'Content-Length':'65537'}),Response(b'{"error":1}'),Response(b'{"error":0,"error":1}'),Response(b'{}',{'Content-Encoding':'gzip'})):
   s,r,conn=self.session(response=response)
   with self.assertRaises(probe.Stop):s.request('GET','/game')
   self.assertEqual(len(conn.calls),1);self.assertTrue(conn.closed)
 def test_form_success(self):
  r=report();c.inspect_form(form(),r);self.assertTrue(r['initialization_response_accepted'])
 def test_missing_auth_or_minspec_refused(self):
  for k in ('authentication','min_spec','game_dir'):
   f=form();del f['form'][k]
   with self.assertRaises(probe.Stop):c.inspect_form(f,report())
 def test_each_error_refused(self):
  for k in ('authentication','min_spec','game_dir'):
   f=form();f['form'][k]['error']=3
   with self.assertRaises(probe.Stop):c.inspect_form(f,report())
 def test_unknown_form_refused(self):
  f=form();f['form']['arbitrary_required_field']={'value':'private'};r=report()
  with self.assertRaises(probe.Stop):c.inspect_form(f,r)
  self.assertTrue(r['unknown_form_fields']);self.assertNotIn('private',json.dumps(r));self.assertNotIn('arbitrary_required_field',json.dumps(r))
 def test_eula_not_accepted(self):
  f=form();f['form']['eula']={'eula':False};r=report()
  with self.assertRaisesRegex(probe.Stop,'legal_consent_required'):c.inspect_form(f,r)
  self.assertFalse(r['legal_terms_accepted']);self.assertFalse(r['initialization_response_accepted'])
 def test_disk_preflight_and_reserve(self):
  r=report()
  with patch.object(c,'disk_pair',return_value=(c.MIN_FREE,c.MIN_FREE)):c.sample_disk(None,None,r,True)
  with patch.object(c,'disk_pair',return_value=(c.RESERVE-1,c.MIN_FREE)),self.assertRaisesRegex(probe.Stop,'disk_refused'):c.sample_disk(None,None,r)
 def test_false_completion_not_qualified(self):
  r=report();r['status']='baseline_agent_complete'
  with self.assertRaises(ValueError):c.validate(r)
 def test_successful_owned_build_identity(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);p.joinpath('.build.info').write_text('Active!DEC:1|Build Key!HEX:16|Version!STRING:0\n1|'+('b'*32)+'|1.2.3.4\n')
   r=report();r.update(observed_version='1.2.3.4',observed_build_config='b'*32)
   self.assertTrue(c.build_identity(p,r,lambda p:False));self.assertTrue(r['owned_build_info_read'])
   r['observed_build_config']='c'*32;self.assertFalse(c.build_identity(p,r,lambda p:False))
 def test_build_reparse_not_read(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);p.joinpath('.build.info').write_bytes(b'private');r=report()
   self.assertFalse(c.build_identity(p,r,lambda p:True));self.assertFalse(r['owned_build_info_read'])
 def test_full_observer_synthetic_completion(self):
  r=report();r.update(approval_present=True,destination_fixed_drive=True,destination_new_empty=True,observed_version='1.2.3.4',observed_build_config='b'*32)
  replies=iter([{},form(),{}, {'installed':True,'download_complete':True}]);calls=[]
  class FakeSession:
   def __init__(self,*args):pass
   def request(self,method,path,payload=None):
    calls.append((method,path));r['total_local_requests']+=1
    if path=='/install':r['initialization_attempted']=True
    if path=='/install/'+c.PRODUCT:r['finalization_attempted']=True
    return next(replies)
  with tempfile.TemporaryDirectory()as d:
   target=Path(d);target.joinpath('.build.info').write_text('Active|Build Key|Version\n1|'+('b'*32)+'|1.2.3.4\n')
   with patch.object(c,'Session',FakeSession),patch.object(c,'disk_pair',return_value=(c.MIN_FREE,c.MIN_FREE)):
    c.observe('fixture',1234,lambda:True,r,target,target,lambda p:False)
   self.assertEqual(r['status'],'baseline_agent_complete');self.assertEqual(len(calls),4);c.validate(r)
 def test_existing_game_no_initialization(self):
  r=report()
  class FakeSession:
   def __init__(self,*a):pass
   def request(self,*a):return {'existing':{'link':'private'}}
  with patch.object(c,'Session',FakeSession),self.assertRaisesRegex(probe.Stop,'existing_products_refused'):
   c.observe('fixture',1234,lambda:True,r,None,None,lambda p:False)
  self.assertFalse(r['initialization_attempted'])
 def test_real_loopback_only_fixture(self):
  seen=[]
  class Handler(http.server.BaseHTTPRequestHandler):
   def do_GET(self):
    seen.append((self.path,self.headers.get('Authorization')));self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'{}')
   def log_message(self,*a):pass
  server=http.server.HTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
  try:
   s=c.Session(server.server_port,'fixture-secret',lambda:True,report());self.assertEqual(s.request('GET','/game'),{});self.assertEqual(seen,[('/game','fixture-secret')])
  finally:server.shutdown();server.server_close();thread.join()
if __name__=='__main__':unittest.main()
