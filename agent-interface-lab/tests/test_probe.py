import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import probe as p

def report():
    r=p.blank();r.update(source_commit='a'*40,run_id='123',run_attempt='1');return r

def ready():
    r=report();r.update(agent_signature_verified=True,agent_sha256='b'*64,
                       process_path_verified=True,listener_owner_verified=True,listener_binding='loopback')
    return r

class Response:
    status=200
    def __init__(self,body=b'{"authorization":"synthetic-secret"}',headers=None,status=200):
        self.body=body;self.headers=headers or {};self.status=status
    def getheader(self,k,default=None):return self.headers.get(k,default)
    def read(self,n):return self.body[:n]
class Connection:
    def __init__(self,response):self.response=response;self.calls=[];self.closed=False
    def request(self,*a,**kw):self.calls.append((a,kw))
    def getresponse(self):return self.response
    def close(self):self.closed=True

class PolicyTests(unittest.TestCase):
    def test_environment(self):
        env=dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',
             GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1',AGENT_INTERFACE_ONCE=p.APPROVAL,
             GITHUB_SHA='a'*40,GITHUB_RUN_ID='123')
        self.assertTrue(p.fresh_environment(env,'win32'))
        for key in env:
            bad=env.copy();bad[key]='unapproved';self.assertFalse(p.fresh_environment(bad,'win32'),key)
        self.assertFalse(p.fresh_environment(env,'linux'))
    def test_blank(self):p.validate(report())
    def test_safety_flags(self):
        r=report()
        for key,value in r.items():
            if type(value) is bool and key not in p.OBSERVED_FLAGS:
                bad=r.copy();bad[key]=not value
                with self.assertRaises(ValueError,msg=key):p.validate(bad)
    def test_schema_no_extra_text(self):
        r=report();r['raw_token']='secret'
        with self.assertRaises(ValueError):p.validate(r)
    def test_request_requires_identity(self):
        for key in ('agent_signature_verified','process_path_verified','listener_owner_verified'):
            r=ready();r[key]=False;factory=[]
            with self.assertRaises(p.Stop):p.request_agent(1234,r,lambda *a,**k:factory.append(1))
            self.assertEqual(factory,[]);self.assertEqual(r['http_requests_attempted'],0)
    def test_only_one_get_no_auth(self):
        r=ready();conn=Connection(Response());args=[]
        def factory(*a,**kw):args.append((a,kw));return conn
        p.request_agent(1234,r,factory)
        self.assertEqual(args,[(('127.0.0.1',1234),{'timeout':3})])
        a,kw=conn.calls[0];self.assertEqual(a,('GET','/agent'))
        self.assertNotIn('body',kw);self.assertNotIn('Authorization',kw['headers']);self.assertTrue(conn.closed)
        self.assertEqual(r['status'],'handshake_token_observed')
        self.assertNotIn('synthetic-secret',json.dumps(r))
        r['cleanup_attempted']=True;p.validate(r)
        with self.assertRaises(p.Stop):p.request_agent(1234,r,factory)
        self.assertEqual(len(args),1)
    def test_invalid_ports(self):
        for port in (0,-1,65536,True,'1234'):
            with self.assertRaises(p.Stop):p.request_agent(port,ready())
    def test_redirect_no_follow(self):
        for status in (301,302,307,401,403,500):
            r=ready();conn=Connection(Response(status=status))
            with self.assertRaises(p.Stop):p.request_agent(1234,r,lambda *a,**k:conn)
            self.assertEqual(len(conn.calls),1);self.assertTrue(conn.closed)
            self.assertFalse(r['authorization_token_present'])
    def test_no_retry_on_transport_error(self):
        r=ready()
        def factory(*a,**kw):raise OSError('synthetic')
        with self.assertRaises(OSError):p.request_agent(1234,r,factory)
        self.assertEqual(r['http_requests_attempted'],1)
        with self.assertRaises(p.Stop):p.request_agent(1234,r,factory)
    def test_response_rejections(self):
        cases=[Response(b'{"authorization":"a","authorization":"b"}'),Response(b'[]'),
          Response(b'bad'),Response(b'\xff'),Response(b'{"x":NaN}'),
          Response(b'x'*(p.MAX_BODY+1)),Response(headers={'Content-Length':'65537'}),
          Response(headers={'Content-Length':'-1'}),Response(headers={'Content-Encoding':'gzip'}),
          Response(headers={'Content-Length':'1'})]
        for response in cases:
            r=ready();conn=Connection(response)
            with self.assertRaises(p.Stop):p.request_agent(1234,r,lambda *a,**k:conn)
            self.assertTrue(conn.closed);self.assertFalse(r['authorization_token_present'])
    def test_valid_without_token(self):
        for body in (b'{}',b'{"authorization":null}',b'{"authorization":false}',b'{"authorization":""}'):
            r=ready();p.request_agent(1234,r,lambda *a,**k:Connection(Response(body)))
            self.assertEqual(r['status'],'handshake_without_token');r['cleanup_attempted']=True;p.validate(r)
    def test_not_account_or_update_proof(self):
        r=ready();p.request_agent(1234,r,lambda *a,**k:Connection(Response()))
        r['cleanup_attempted']=True
        for key in ('account_login_requirement_proven','game_update_without_login_proven','retail_policy_proven'):
            bad=r.copy();bad[key]=True
            with self.assertRaises(ValueError):p.validate(bad)
    def test_missing_evidence(self):
        r=ready();r.update(status='handshake_token_observed',authorization_token_present=True)
        with self.assertRaises(ValueError):p.validate(r)
    def test_listener_selection(self):
        self.assertIsNone(p.choose_listener([]))
        self.assertEqual(p.choose_listener([('127.0.0.1',1234)]),(1234,'loopback'))
        self.assertEqual(p.choose_listener([('0.0.0.0',1234)]),(1234,'wildcard'))
        for rows in ([('10.0.0.1',1234)],[('127.0.0.1',0)],[('127.0.0.1',True)],
                     [('127.0.0.1',1),('127.0.0.1',2)]):
            with self.assertRaises(p.Stop):p.choose_listener(rows)
    def test_candidate_no_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'Agent.exe').write_bytes(b'MZlauncher')
            with self.assertRaises(p.Stop):p.choose_agent(root,lambda path:False)
            folder=root/'Agent.123';folder.mkdir();(folder/'Agent.exe').write_bytes(b'MZtest')
            self.assertEqual(p.choose_agent(root,lambda path:False), (folder/'Agent.exe').resolve())
            with self.assertRaises(p.Stop):p.choose_agent(root,lambda path:path==folder)
            folder2=root/'Agent.124';folder2.mkdir();(folder2/'Agent.exe').write_bytes(b'MZtest')
            with self.assertRaises(p.Stop):p.choose_agent(root,lambda path:False)
    @unittest.skipUnless(sys.platform=='win32','native Windows fixture only')
    def test_native_listener_owner_and_image(self):
        self.assertEqual(p.process_image(os.getpid()).resolve(),Path(sys.executable).resolve())
        with socket.socket() as server:
            server.bind(('127.0.0.1',0));server.listen(1)
            rows=p.listener_rows(os.getpid())
            self.assertIn(('127.0.0.1',server.getsockname()[1]),rows)
            self.assertNotIn(('127.0.0.1',server.getsockname()[1]),p.listener_rows(0))

if __name__=='__main__':unittest.main()
