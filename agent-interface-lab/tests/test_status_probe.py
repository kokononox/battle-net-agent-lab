import copy
import http.server
import json
import os
from pathlib import Path
import socket
import sys
import threading
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import probe
import status_probe as s
from test_probe import Connection,Response

def report(ready=False):
    r=s.blank()
    for target in (r,r['handshake']):target.update(source_commit='a'*40,run_id='123',run_attempt='1')
    if ready:
        h=r['handshake'];h.update(status='handshake_token_observed',agent_signature_verified=True,
          agent_sha256='b'*64,process_path_verified=True,listener_owner_verified=True,
          listener_binding='loopback',http_requests_attempted=1,http_status=200,response_bytes=20,
          response_json_object=True,authorization_token_present=True,cleanup_attempted=True)
        r['total_http_requests_attempted']=1
    return r

def finish(r):
    r['total_http_requests_attempted']=r['handshake']['http_requests_attempted']+r['game_http_requests_attempted']
    return s.validate(r)

class StatusTests(unittest.TestCase):
    def test_blank(self):s.validate(report())
    def test_scope_requires_both_approvals(self):
        env=dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',
          GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1',AGENT_INTERFACE_ONCE=probe.APPROVAL,
          AGENT_STATUS_ONCE=s.APPROVAL,GITHUB_SHA='a'*40,GITHUB_RUN_ID='123')
        self.assertTrue(s.fresh_environment(env,'win32'))
        for key in env:
            bad=env.copy();bad[key]='wrong';self.assertFalse(s.fresh_environment(bad,'win32'),key)
    def test_empty_object_success(self):
        r=report(True);conn=Connection(Response(b'{}'));checks=[]
        def verify():checks.append(1);return True
        s.request_game(1234,'synthetic-token',r,verify,lambda *a,**k:conn)
        finish(r)
        self.assertEqual(r['status'],'game_summary_observed');self.assertEqual(r['product_entry_count'],0)
        self.assertEqual(len(checks),2);self.assertTrue(conn.closed)
        self.assertNotIn('synthetic-token',json.dumps(r))
    def test_exact_route_headers_no_mutation(self):
        r=report(True);conn=Connection(Response(b'{}'));targets=[]
        def factory(*a,**kw):targets.append((a,kw));return conn
        s.request_game(1234,'synthetic-token',r,lambda:True,factory)
        self.assertEqual(targets,[(('127.0.0.1',1234),{'timeout':3})])
        args,kwargs=conn.calls[0]
        self.assertEqual(args,('GET','/game'));self.assertNotIn('body',kwargs)
        self.assertEqual(kwargs['headers']['Authorization'],'synthetic-token')
        self.assertNotIn('Cookie',kwargs['headers'])
    def test_summary_does_not_export_names_or_links(self):
        r=report(True);body=b'{"synthetic-product":{"link":"http://127.0.0.1/private-path"}}'
        s.request_game(1234,'synthetic-token',r,lambda:True,lambda *a,**k:Connection(Response(body)))
        finish(r)
        self.assertEqual(r['product_entry_count'],1)
        for value in ('synthetic-product','private-path','synthetic-token'):self.assertNotIn(value,json.dumps(r))
    def test_error_zero_not_product(self):self.assertEqual(s.summarize(b'{"error":0}'),('error_zero_empty',0))
    def test_error_not_miscounted(self):
        with self.assertRaisesRegex(probe.Stop,'agent_error_reported'):s.summarize(b'{"error":2221}')
    def test_unknown_shape_rejected(self):
        for raw in (b'[]',b'null',b'{"x":{}}',b'{"x":{"link":5}}',b'{"error":false}',
          b'{"error":-1}',b'{"x":3}',b'{"authorization":"unexpected-secret"}',b'{"x":{"link":""}}'):
            with self.assertRaises(probe.Stop):s.summarize(raw)
    def test_duplicate_nonfinite_oversized_rejected(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"error":Infinity}',b'\xff',b'x'*(probe.MAX_BODY+1)):
            with self.assertRaises(probe.Stop):s.summarize(raw)
    def test_product_count_cap(self):
        raw=json.dumps({str(i):{'link':'x'} for i in range(257)}).encode()
        with self.assertRaises(probe.Stop):s.summarize(raw)
    def test_token_safety_no_request(self):
        for token in ('','a\r\nb','a\nb','é',None,False,'x'*8193):
            r=report(True);calls=[]
            with self.assertRaises(probe.Stop):s.request_game(1234,token,r,lambda:True,lambda *a,**k:calls.append(1))
            self.assertEqual(calls,[]);self.assertEqual(r['game_http_requests_attempted'],0)
    def test_no_token_no_request(self):
        r=report(True);r['handshake']['authorization_token_present']=False
        with self.assertRaises(probe.Stop):s.request_game(1234,'token',r,lambda:True)
    def test_owner_change_before_request(self):
        r=report(True);calls=[]
        with self.assertRaises(probe.Stop):s.request_game(1234,'token',r,lambda:False,lambda *a,**k:calls.append(1))
        self.assertEqual(calls,[])
    def test_owner_change_after_response(self):
        r=report(True);checks=iter([True,False]);conn=Connection(Response(b'{}'))
        with self.assertRaises(probe.Stop):s.request_game(1234,'token',r,lambda:next(checks),lambda *a,**k:conn)
        self.assertFalse(r['game_after_owner_verified']);self.assertIsNone(r['product_entry_count'])
        self.assertTrue(conn.closed)
    def test_no_redirect_or_auth_retry(self):
        for status in (301,302,307,401,403,404,500):
            r=report(True);conn=Connection(Response(status=status))
            with self.assertRaises(probe.Stop):s.request_game(1234,'token',r,lambda:True,lambda *a,**k:conn)
            with self.assertRaises(probe.Stop):s.request_game(1234,'token',r,lambda:True,lambda *a,**k:conn)
            self.assertEqual(len(conn.calls),1);self.assertTrue(conn.closed)
    def test_body_limits(self):
        cases=[Response(headers={'Content-Length':'65537'}),Response(headers={'Content-Encoding':'gzip'}),
          Response(b'x'*(probe.MAX_BODY+1)),Response(b'{}',headers={'Content-Length':'5'})]
        for response in cases:
            with self.assertRaises(probe.Stop):s.request_game(1234,'token',report(True),lambda:True,lambda *a,**k:Connection(response))
    def test_delivery_uncertain_counted_once(self):
        r=report(True)
        def factory(*a,**kw):raise OSError('synthetic secret')
        with self.assertRaises(OSError):s.request_game(1234,'token',r,lambda:True,factory)
        self.assertEqual(r['game_http_requests_attempted'],1)
        with self.assertRaises(probe.Stop):s.request_game(1234,'token',r,lambda:True,factory)
    def test_fixed_flags_and_no_extra_fields(self):
        r=report()
        for key,value in r.items():
            if type(value) is bool and key not in s.OBSERVED:
                bad=copy.deepcopy(r);bad[key]=not value
                with self.assertRaises(ValueError,msg=key):s.validate(bad)
        r['raw_response']='secret'
        with self.assertRaises(ValueError):s.validate(r)
    def test_success_requires_evidence_and_sum(self):
        r=report(True);s.request_game(1234,'token',r,lambda:True,lambda *a,**k:Connection(Response(b'{}')))
        finish(r)
        for key,value in [('total_http_requests_attempted',1),('game_after_owner_verified',False),('game_response_schema',None),('product_entry_count',None),('agent_error_reported',True)]:
            bad=copy.deepcopy(r);bad[key]=value
            with self.assertRaises(ValueError,msg=key):s.validate(bad)
    def test_actual_loopback_http_transport(self):
        seen=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.command,self.path,self.headers.get('Authorization'),self.headers.get('Cookie')))
                self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'{}')
            def log_message(self,*a):pass
        with http.server.HTTPServer(('127.0.0.1',0),Handler) as server:
            thread=threading.Thread(target=server.handle_request,daemon=True);thread.start()
            r=report(True);s.request_game(server.server_port,'synthetic-only',r,lambda:True)
            thread.join(timeout=3);self.assertFalse(thread.is_alive());finish(r)
        self.assertEqual(seen,[('GET','/game','synthetic-only',None)])
    def test_runner_observer_and_sanitized_receipt(self):
        import tempfile
        env=dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',
          GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1',AGENT_INTERFACE_ONCE=probe.APPROVAL,
          AGENT_STATUS_ONCE=s.APPROVAL,GITHUB_SHA='a'*40,GITHUB_RUN_ID='123')
        def fake_run(out,after_handshake,report_sink):
            report_sink.update(report(True)['handshake'])
            after_handshake('synthetic-secret',1234,lambda:True)
            return report_sink
        real_request=s.request_game
        def fixture_request(port,token,r,verify_live):
            return real_request(port,token,r,verify_live,lambda *a,**k:Connection(Response(b'{}')))
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,env),patch.object(s.sys,'platform','win32'),patch.object(probe,'run',side_effect=fake_run),patch.object(s,'request_game',side_effect=fixture_request):
            r=s.run(Path(tmp));self.assertEqual(r['status'],'game_summary_observed')
            raw=(Path(tmp)/'agent-status-to-share.json').read_text()
            self.assertNotIn('synthetic-secret',raw);s.validate(json.loads(raw))

    def test_handshake_token_return_is_not_in_report(self):
        h=report(True)['handshake'];h['http_requests_attempted']=0
        token=probe.request_agent(1234,h,lambda *a,**k:Connection(Response()))
        self.assertEqual(token,'synthetic-secret');self.assertNotIn(token,json.dumps(h))

if __name__=='__main__':unittest.main()
