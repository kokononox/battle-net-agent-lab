"""Offline characterization, not anti-fingerprinting acceptance tests.
No remote network, OS firewall changes, actual Windows admission or real TLS session.
Admission is explicitly mocked to model an already-admitted process.
"""
import argparse, hashlib, json, ssl, sys, tempfile, types, unittest
from pathlib import Path
from unittest.mock import patch
parser=argparse.ArgumentParser()
parser.add_argument('--source',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
ROOT=args.source.resolve()
sys.path.insert(0,str(ROOT))
fake=types.ModuleType('peer_guard');fake.admit=lambda *a:None
sys.modules['peer_guard']=fake
import domain_proxy as d

class Permit:
 def revalidate(self):pass
 def close(self):pass
class Stream:
 def __init__(self,data=b''):self.data=data;self.sent=bytearray()
 def recv(self,n):v=self.data[:n];self.data=self.data[n:];return v
 def send(self,v):self.sent.extend(v);return len(v)
 def sendall(self,v):self.sent.extend(v)
 def settimeout(self,n):pass
 def close(self):pass

class Characterize(unittest.TestCase):
 observations=[]
 def http(self,request,admitted=True):
  client=Stream(request);up=Stream(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
  with tempfile.TemporaryDirectory() as temp:
   server=types.SimpleNamespace(config={'peer_policy':'mock-only','log':str(Path(temp)/'log')},transparent_http=True,destination_port=80)
   with patch.object(d,'admit',side_effect=(lambda *a:Permit()) if admitted else ValueError('peer_not_in_owned_job')),patch.object(d,'connect',return_value=up) as dial:
    d.Handler(client,('127.0.0.1',12345),server)
   return bytes(up.sent),bytes(client.sent),dial.call_count
 def test_01_post_body_passes_to_allowed_destination(self):
  body=b'{"synthetic_device_id":"AUDIT-FAKE-DEVICE-0001"}'
  wire,response,calls=self.http(b'POST /audit-only HTTP/1.1\r\nHost: level3.blizzard.com\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
  self.assertIn(body,wire);self.assertEqual(calls,1)
  self.observations.append({'id':'http_post_body','outcome':'synthetic_device_field_forwarded','anti_fingerprint_requirement':'not_enforced'})
 def test_02_get_query_and_header_pass(self):
  wire,_,_=self.http(b'GET /file?device=AUDIT-FAKE-QUERY HTTP/1.1\r\nHost: level3.blizzard.com\r\nX-Device-Id: AUDIT-FAKE-HEADER\r\nCookie: id=AUDIT-FAKE-COOKIE\r\n\r\n')
  for marker in (b'AUDIT-FAKE-QUERY',b'AUDIT-FAKE-HEADER',b'AUDIT-FAKE-COOKIE'):self.assertIn(marker,wire)
  self.observations.append({'id':'http_get_fields','outcome':'query_header_cookie_forwarded','anti_fingerprint_requirement':'not_enforced'})
 def test_03_get_path_passes(self):
  wire,_,_=self.http(b'GET /AUDIT-FAKE-DEVICE-0001/file HTTP/1.1\r\nHost: level3.blizzard.com\r\n\r\n')
  self.assertIn(b'/AUDIT-FAKE-DEVICE-0001/file',wire)
  self.observations.append({'id':'http_get_path','outcome':'synthetic_identifier_in_path_forwarded','anti_fingerprint_requirement':'not_enforced'})
 def test_04_other_host_rejected_before_dial(self):
  wire,response,calls=self.http(b'GET /file HTTP/1.1\r\nHost: example.invalid\r\n\r\n')
  self.assertEqual(calls,0);self.assertEqual(wire,b'');self.assertTrue(response.startswith(b'HTTP/1.1 403'))
  self.observations.append({'id':'unapproved_host','outcome':'blocked_before_dial','scope':'protocol_unit_only'})
 def test_05_nonadmitted_peer_rejected_before_dial(self):
  wire,response,calls=self.http(b'GET /file HTTP/1.1\r\nHost: level3.blizzard.com\r\n\r\n',False)
  self.assertEqual(calls,0);self.assertEqual(wire,b'');self.assertTrue(response.startswith(b'HTTP/1.1 403'))
  self.observations.append({'id':'nonadmitted_peer','outcome':'blocked_before_dial','scope':'mocked_admission_rejection_only'})
 def test_06_connect_relays_opaque_application_bytes(self):
  incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO()
  obj=ssl.create_default_context().wrap_bio(incoming,outgoing,server_hostname='level3.blizzard.com')
  try:obj.do_handshake()
  except ssl.SSLWantReadError:pass
  hello=outgoing.read();payload=b'AUDIT-SYNTHETIC-OPAQUE-CONTENT'
  # TLS-shaped record only: payload is not encryption and no handshake completes.
  record=b'\x17\x03\x03'+len(payload).to_bytes(2,'big')+payload
  client=Stream(b'CONNECT level3.blizzard.com:443 HTTP/1.1\r\nHost: level3.blizzard.com:443\r\n\r\n'+hello+record)
  upstream=Stream()
  with tempfile.TemporaryDirectory() as temp:
   server=types.SimpleNamespace(config={'peer_policy':'mock-only','log':str(Path(temp)/'log')},destination_port=80)
   with patch.object(d,'admit',return_value=Permit()),patch.object(d,'connect',return_value=upstream),patch.object(d.select,'select',side_effect=lambda *a:([client],[],[])):
    d.Handler(client,('127.0.0.1',12345),server)
   events=[json.loads(line) for line in Path(temp,'log').read_text().splitlines()]
  self.assertEqual(bytes(upstream.sent),hello+record)
  final=[r for r in events if r['kind']=='tls_transfer_final'][0]
  self.assertEqual(final['client_sent_bytes'],len(record))
  self.observations.append({'id':'connect_opaque_relay','outcome':'clienthello_and_opaque_record_forwarded','scope':'in_memory_protocol_no_real_tls_session','anti_fingerprint_requirement':'not_enforced'})

if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(Characterize)
 r=unittest.TextTestRunner(verbosity=2).run(suite)
 source_files=['domain_proxy.py','tls_records.py','peer_guard.py','FirewallGate.ps1','OfflineLauncher.cs']
 result={'schema':'privacy_architecture_characterization_v1','source_commit':'c579bec60c4fbcbef5694c44f27a808409a1d62e','source_directory':'analysis-tools/two-destination-g34','tests_run':r.testsRun,'failures':len(r.failures),'errors':len(r.errors),'tests_passed':r.wasSuccessful(),'acceptance_for_anti_fingerprinting':False,'no_external_network':True,'no_os_policy_changes':True,'admission_mocked':True,'no_real_tls_session':True,'synthetic_markers_only':True,'observations':Characterize.observations,'source_sha256':{f:hashlib.sha256((ROOT/f).read_bytes()).hexdigest() for f in source_files}}
 args.output.write_text(json.dumps(result,indent=2)+'\n')
 sys.exit(not r.wasSuccessful())
