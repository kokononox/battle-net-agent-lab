"""Offline contract tests, no Battle.net requests or Windows changes."""
import json
from pathlib import Path
import socket
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from unittest.mock import patch
from broker import Catalog,Denied,InMemoryTransport,OfflineBroker,Reply,digest

PAYLOAD=b'SYNTHETIC DOWNLOAD FIXTURE\n'
def encoded(value):return json.dumps(value,separators=(',',':')).encode()
def policy():
 return {'schema':'offline_download_catalog_v1','resources':[{'resource_id':'fixture','host':'level3.blizzard.com','path':'/audit-fixture/file.bin','expected_bytes':len(PAYLOAD),'sha256':digest(PAYLOAD),'review':{'status':'approved','evidence_id':'synthetic_test_fixture_only'}}]}
def load(value=None):
 raw=encoded(policy() if value is None else value)
 return Catalog.load(raw,digest(raw))

class Tests(unittest.TestCase):
 def setUp(self):
  # Any accidental socket creation fails the suite; transport is fixture-only.
  self.guard=patch.object(socket,'socket',side_effect=AssertionError('network_forbidden'))
  self.guard.start();self.addCleanup(self.guard.stop)
  self.catalog=load();self.request=b'{"resource_id":"fixture"}'
  self.plan=self.catalog.plan(self.request)
  self.transport=InMemoryTransport({(self.plan.host,self.plan.request):Reply(200,PAYLOAD)})
  self.broker=OfflineBroker(self.catalog,self.transport)
 def deny_request(self,value):
  raw=value if type(value) is bytes else encoded(value)
  with self.assertRaises(Denied):self.broker.download(raw)
  self.assertEqual(self.transport.calls,[])
 def test_fixture_download(self):
  self.assertEqual(self.broker.download(self.request),PAYLOAD)
  self.assertEqual(len(self.transport.calls),1)
 def test_wire_exact(self):
  self.assertEqual(self.plan.request,b'GET /audit-fixture/file.bin HTTP/1.1\r\nHost: level3.blizzard.com\r\nAccept: application/octet-stream\r\nAccept-Encoding: identity\r\nUser-Agent: BNet-Isolated-Downloader/0.1\r\nConnection: close\r\n\r\n')
  self.assertEqual((self.plan.scheme,self.plan.port),('https',443))
 def test_deterministic_reconstruction(self):
  self.assertEqual(self.plan,self.catalog.plan(b'{ "resource_id" : "fixture" }'))
 def test_extra_fields_blocked_before_fetch(self):
  for field in ('url','path','query','headers','cookie','body','method','host','port','device_id','machine_guid','authorization','proxy','redirect','range'):
   with self.subTest(field=field):self.deny_request({'resource_id':'fixture',field:'AUDIT-FAKE-ID'})
 def test_unknown_id_blocked(self):self.deny_request({'resource_id':'AUDIT-FAKE-ID'})
 def test_same_destination_url_blocked(self):self.deny_request({'resource_id':'fixture','url':'https://level3.blizzard.com/AUDIT-FAKE-ID'})
 def test_raw_http_and_connect_blocked(self):
  for raw in (b'GET /x HTTP/1.1\r\nHost: level3.blizzard.com\r\n\r\n',b'CONNECT level3.blizzard.com:443 HTTP/1.1\r\n\r\n'):
   with self.subTest(raw=raw):self.deny_request(raw)
 def test_bad_json_blocked(self):
  for raw in (b'',b'{',b'\xff',b'\xef\xbb\xbf{}',b'{"resource_id":NaN}',b'{}{}'):
   with self.subTest(raw=raw):self.deny_request(raw)
 def test_duplicate_json_key_blocked(self):self.deny_request(b'{"resource_id":"fixture","resource_id":"fixture"}')
 def test_request_type_size_shape_blocked(self):
  for value in ([],None,1,True,{}, {'resource_id':[]},{'resource_id':None},{'resource_id':True},b' '*257):
   with self.subTest(value=value):self.deny_request(value)
 def test_client_encoding_not_forwarded(self):
  # Escaped resource id is normalized; caller byte representation is discarded.
  self.assertEqual(self.plan,self.catalog.plan(b'{"resource_id":"fixt\\u0075re"}'))
 def test_many_injected_requests_never_fetch(self):
  for index in range(1000):
   raw=encoded({'resource_id':'fixture','x_'+str(index):'AUDIT-ID-'+str(index)})
   with self.assertRaises(Denied):self.broker.download(raw)
  self.assertEqual(self.transport.calls,[])
 def test_deny_all_shipped_policy(self):
  raw=Path(__file__).with_name('catalog.deny-all.json').read_bytes()
  catalog=Catalog.load(raw,digest(raw));transport=InMemoryTransport({})
  with self.assertRaises(Denied):OfflineBroker(catalog,transport).download(self.request)
  self.assertEqual(transport.calls,[])
 def test_policy_pin_mismatch(self):
  with self.assertRaises(Denied):Catalog.load(encoded(policy()),'0'*64)
 def test_policy_duplicate_key_blocked(self):
  raw=b'{"schema":"offline_download_catalog_v1","resources":[],"resources":[]}'
  with self.assertRaises(Denied):Catalog.load(raw,digest(raw))
 def test_unreviewed_resource_blocked(self):
  for review in ({'status':'pending','evidence_id':'test'},{'status':'approved','evidence_id':''},None,{'status':'approved','evidence_id':'test','override':True}):
   p=policy();p['resources'][0]['review']=review
   with self.subTest(review=review),self.assertRaises(Denied):load(p)
 def test_host_lookalikes_and_ip_blocked(self):
  for host in ('example.invalid','level3.blizzard.com.evil','level3.blizzard.com@evil','127.0.0.1','LEVEL3.BLIZZARD.COM','level3.blizzard.com:443'):
   p=policy();p['resources'][0]['host']=host
   with self.subTest(host=host),self.assertRaises(Denied):load(p)
 def test_noncanonical_paths_blocked(self):
  for path in ('//evil/file','/a/../b','/a/./b','/a//b','/x?device=id','/x#id','/x%3Fid','/x\r\nX-Id: z','https://level3.blizzard.com/x','/فایل','/x\\id','/x/'):
   p=policy();p['resources'][0]['path']=path
   with self.subTest(path=path),self.assertRaises(Denied):load(p)
 def test_policy_cannot_add_arbitrary_headers_or_method(self):
  for key in ('headers','method','query','body','port','scheme'):
   p=policy();p['resources'][0][key]='injected'
   with self.subTest(key=key),self.assertRaises(Denied):load(p)
 def test_duplicate_resource_blocked(self):
  p=policy();p['resources']*=2
  with self.assertRaises(Denied):load(p)
 def test_integrity_configuration_blocked(self):
  for key,value in (('expected_bytes',True),('expected_bytes',0),('expected_bytes',-1),('expected_bytes',2**40),('sha256','unknown')):
   p=policy();p['resources'][0][key]=value
   with self.subTest(key=key,value=value),self.assertRaises(Denied):load(p)
 def test_redirects_errors_not_delivered(self):
  for status in (301,302,307,308,404,500,True):
   self.transport.replies[(self.plan.host,self.plan.request)]=Reply(status,PAYLOAD)
   with self.subTest(status=status),self.assertRaises(Denied):self.broker.download(self.request)
 def test_size_mismatch_not_delivered(self):
  for body in (b'',PAYLOAD+b'x',PAYLOAD[:-1]):
   self.transport.replies[(self.plan.host,self.plan.request)]=Reply(200,body)
   with self.subTest(body=body),self.assertRaises(Denied):self.broker.download(self.request)
 def test_hash_mismatch_not_delivered(self):
  self.transport.replies[(self.plan.host,self.plan.request)]=Reply(200,b'X'*len(PAYLOAD))
  with self.assertRaises(Denied):self.broker.download(self.request)
 def test_no_fixture_no_network_fallback(self):
  self.transport.replies.clear()
  with self.assertRaises(Denied):self.broker.download(self.request)
 def test_real_transport_not_accepted(self):
  with self.assertRaises(Denied):OfflineBroker(self.catalog,object())
 def test_policy_resource_mapping_readonly(self):
  with self.assertRaises(TypeError):self.catalog.resources['bad']=self.catalog.resources['fixture']

if __name__=='__main__':unittest.main(verbosity=2)
