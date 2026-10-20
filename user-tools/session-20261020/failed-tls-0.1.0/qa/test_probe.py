import sys,types,tempfile,unittest,json,gzip,zlib,base64,asyncio,os
from pathlib import Path
from unittest.mock import patch
sys.modules['mitmproxy']=types.SimpleNamespace(ctx=types.SimpleNamespace(master=types.SimpleNamespace(shutdown=lambda:None)))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import ingest_probe as m
class Headers(dict):
 def items(self,multi=False):return super().items()
def flow(body=b'{"cpu":"PRIVATE-CPU","event":"PRIVATE-EVENT"}',host=m.FIXTURE_HOST,sni=m.FIXTURE_HOST):
 return types.SimpleNamespace(id='test-id',request=types.SimpleNamespace(host=host,port=443,scheme='https',method='POST',path='/private?token=PRIVATE-TOKEN',raw_content=body,headers=Headers({'content-type':'application/json','authorization':'PRIVATE-AUTH'})),client_conn=types.SimpleNamespace(sni=sni),response=types.SimpleNamespace(status_code=200,stream=False))
class Tests(unittest.TestCase):
 def probe(self,d):
  with patch.dict(os.environ,{'INGEST_PROBE_RUN':str(d),'INGEST_PROBE_PHASE':'capture'}):p=m.Probe()
  p.refs={'cpu_model':['PRIVATE-CPU']};return p
 def test_target_exact(self):self.assertTrue(m.target(flow()))
 def test_another_destination_captured(self):self.assertTrue(m.target(flow(host='other.example',sni='other.example')))
 def test_sni_mismatch_not_captured(self):self.assertFalse(m.target(flow(sni='other.example')))
 def test_no_sni_not_captured(self):self.assertFalse(m.target(flow(sni=None)))
 def test_suffix_attack_not_captured(self):self.assertFalse(m.target(flow(sni=m.FIXTURE_HOST+'.evil.test')))
 def test_known_markers_and_no_values(self):
  r=m.body_summary(b'{"cpu":"PRIVATE-CPU","biosVersion":"123","random-ID-as-key":"PRIVATE-ID"}','',{'cpu_model':['PRIVATE-CPU']})
  self.assertEqual(r['hardware_literal_categories'],['cpu_model']);self.assertEqual(r['known_field_name_hints'],['bios_version','cpu']);self.assertNotIn('PRIVATE',json.dumps(r));self.assertNotIn('random-ID',json.dumps(r))
 def test_gzip(self):self.assertEqual(m.decode_body(gzip.compress(b'hello'),'gzip'),(b'hello',True,'gzip'))
 def test_deflate(self):self.assertEqual(m.decode_body(zlib.compress(b'hello'),'deflate'),(b'hello',True,'deflate'))
 def test_compressed_bomb_bounded(self):self.assertFalse(m.decode_body(gzip.compress(b'A'*(m.MAX_BODY+1)),'gzip')[1])
 def test_concat_gzip_not_complete(self):self.assertFalse(m.decode_body(gzip.compress(b'a')+gzip.compress(b'b'),'gzip')[1])
 def test_unsupported_encoding_explicit(self):self.assertEqual(m.decode_body(b'abc','br')[2],'unsupported_content_encoding')
 def test_bad_gzip(self):self.assertEqual(m.decode_body(b'bad','gzip')[2],'decompression_failed')
 def test_truncated_gzip(self):self.assertFalse(m.decode_body(gzip.compress(b'hello')[:-5],'gzip')[1])
 def test_body_cap(self):self.assertFalse(m.decode_body(b'x'*(m.MAX_BODY+1),'')[1])
 def test_empty(self):self.assertEqual(m.body_summary(b'','',{})['body_format_hint'],'empty')
 def test_form_keys(self):self.assertEqual(m.body_summary(b'cpuModel=TEST&biosVersion=VALUE','',{})['known_field_name_hints'],['bios_version','cpu_model'])
 def test_utf16_hardware(self):self.assertEqual(m.body_summary('PRIVATE-CPU'.encode('utf-16-le'),'',{'cpu_model':['PRIVATE-CPU']})['hardware_literal_categories'],['cpu_model'])
 def test_secret_values_stay_local(self):
  with tempfile.TemporaryDirectory() as d:
   p=self.probe(d);f=flow();before=f.request.raw_content;p.request(f)
   shared=(Path(d)/'ingest-content.json').read_text();private=(Path(d)/'PRIVATE-REQUESTS/request-01.json').read_text()
   self.assertNotIn('PRIVATE-',shared);self.assertIn('PRIVATE-TOKEN',private);self.assertIn('PRIVATE-CPU',private);self.assertEqual(before,f.request.raw_content)
 def test_unrelated_requests_not_saved(self):
  with tempfile.TemporaryDirectory() as d:
   p=self.probe(d);p.request(flow(host='other.test'));self.assertEqual(p.report['requests'],[]);self.assertEqual(list(Path(d).iterdir()),[])
 def test_streamed_body_explicitly_unexamined(self):
  with tempfile.TemporaryDirectory() as d:
   p=self.probe(d);p.request(flow(body=None));r=p.report['requests'][0];self.assertFalse(r['body_buffered']);self.assertEqual(r['body_decode_status'],'streamed_or_unavailable_not_examined')
 def test_request_cap(self):
  with tempfile.TemporaryDirectory() as d:
   p=self.probe(d)
   for i in range(34):f=flow(b'');f.id=str(i);p.request(f)
   self.assertEqual(len(p.report['requests']),32);self.assertIn('request_count_limit',p.report['limits_hit'])
 def test_response_status_not_body_recorded(self):
  with tempfile.TemporaryDirectory() as d:
   p=self.probe(d);f=flow();p.request(f);p.responseheaders(f);self.assertTrue(f.response.stream);self.assertEqual(p.report['requests'][0]['server_response_status'],200)
 def test_client_tls_failure_flag(self):
  with tempfile.TemporaryDirectory() as d:
   p=self.probe(d);p.tls_failed_client(types.SimpleNamespace(conn=types.SimpleNamespace(sni=m.FIXTURE_HOST)))
   self.assertTrue((Path(d)/'tls-failed.flag').exists());self.assertEqual(p.report['tls_client_failed_count'],1)
 def test_other_destination_tls_failure_also_stops(self):
  with tempfile.TemporaryDirectory() as d:
   p=self.probe(d);p.tls_failed_client(types.SimpleNamespace(conn=types.SimpleNamespace(sni='else.test')));self.assertTrue((Path(d)/'tls-failed.flag').exists())
 def test_bootstrap_no_request_capture(self):
  with tempfile.TemporaryDirectory() as d:
   p=self.probe(d);p.phase='bootstrap';p.request(flow());self.assertEqual(p.report['requests'],[])
 def test_refs_cleared_on_done(self):
  with tempfile.TemporaryDirectory() as d:
   p=self.probe(d);p.done();self.assertEqual(p.refs,{})
 def test_client_success_count(self):
  with tempfile.TemporaryDirectory() as d:
   p=self.probe(d);p.tls_established_client(types.SimpleNamespace(conn=types.SimpleNamespace(sni=m.FIXTURE_HOST)));self.assertEqual(p.report['tls_client_established_count'],1)
 def test_large_request_streamed(self):
  f=flow();f.request.headers['content-length']=str(m.MAX_BODY+1);m.Probe.requestheaders(None,f);self.assertTrue(f.request.stream)
 def test_header_hardware_match_local_only(self):
  self.assertEqual(m.body_summary(b'', '', {'cpu_model':['PRIVATE-CPU']},b'X-CPU: PRIVATE-CPU')['hardware_literal_categories'],['cpu_model'])
 def test_script_stops_on_flag(self):
  with tempfile.TemporaryDirectory() as d:
   p=self.probe(d);(Path(d)/'stop.flag').write_text('stop');asyncio.run(p.timer());self.assertEqual(p.report['status'],'observation_ended')

 def test_plaintext_http_another_destination(self):
  f=flow(host='level3.blizzard.com',sni=None);f.request.scheme='http';f.request.port=80
  self.assertTrue(m.target(f))
 def test_private_ip_content_not_saved(self):self.assertFalse(m.target(flow(host='127.0.0.1',sni='127.0.0.1')))
 def test_destination_metadata_multiple_hosts(self):
  with tempfile.TemporaryDirectory() as d:
   p=self.probe(d)
   for host,ip in [('oauth.battle.net','192.0.2.1'),('prod.depot.battle.net','192.0.2.2')]:
    server=types.SimpleNamespace(address=(host,443),peername=(ip,443),sni=host)
    p.server_connected(types.SimpleNamespace(server=server))
   self.assertEqual(len(p.report['destinations']),2)
 def test_clienthello_domain_list(self):
  with tempfile.TemporaryDirectory() as d:
   p=self.probe(d);p.tls_clienthello(types.SimpleNamespace(client_hello=types.SimpleNamespace(sni='oauth.battle.net')))
   self.assertEqual(p.report['destinations'][0]['visible_sni'],'oauth.battle.net')
 def test_unknown_raw_tcp_endpoint_not_labeled_http(self):
  with tempfile.TemporaryDirectory() as d:
   p=self.probe(d);p.tcp_start(types.SimpleNamespace(server_conn=types.SimpleNamespace(address=('37.244.29.11',3724),peername=('37.244.29.11',3724),sni=None)))
   self.assertEqual(p.report['destinations'][0]['kind'],'raw_tcp_connection_content_not_decoded');self.assertEqual(p.report['requests'],[])

if __name__=='__main__':unittest.main(verbosity=2)
