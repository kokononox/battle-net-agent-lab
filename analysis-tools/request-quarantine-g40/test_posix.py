"""Synthetic request quarantine tests. Never print private captures."""
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import quarantine as q

ID='SYNTHETIC-DEVICE-IDENTIFIER-0001'
COOKIE='SYNTHETIC-COOKIE-SECRET'
AUTH='SYNTHETIC-AUTH-SECRET'
BODY=b'SYNTHETIC-BODY-SECRET'
def request(target='/file?device='+ID,extras='',body=b''):
 headers='Host: level3.blizzard.com\r\n'+extras
 if body:headers+='Content-Length: '+str(len(body))+'\r\n'
 return ('GET '+target+' HTTP/1.1\r\n'+headers+'\r\n').encode('ascii')+body

class Tests(unittest.TestCase):
 def setUp(self):
  guard=patch.object(socket,'socket',side_effect=AssertionError('network_forbidden'));guard.start();self.addCleanup(guard.stop)
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name)/'private';self.root.mkdir(mode=0o700)
  self.store=q.PrivateStore(str(self.root));self.addCleanup(self.store.close)
  self.gate=q.QuarantineGate(self.store)
 def record(self,raw):
  receipt=self.gate.inspect_http(raw)
  self.assertTrue(receipt.private_stored);self.assertEqual(receipt.decision,'blocked');self.assertEqual(receipt.upstream_attempts,0)
  return receipt,self.store.read_for_local_review(receipt.capture_id)
 def test_query_and_path_retained_privately(self):
  receipt,record=self.record(request('/'+ID+'/file?device='+ID))
  self.assertIn(ID,record['path']);self.assertIn(ID,record['query'])
  self.assertFalse(record['approval_granted']);self.assertEqual(record['review_status'],'pending')
 def test_header_values_retained_privately(self):
  _,r=self.record(request(extras='X-Device-ID: '+ID+'\r\nUser-Agent: Synthetic/1\r\n'))
  self.assertTrue(any(h['value']==ID for h in r['headers']))
 def test_known_credentials_redacted(self):
  _,r=self.record(request(extras='Cookie: '+COOKIE+'\r\nAuthorization: Bearer '+AUTH+'\r\nX-Api-Key: '+AUTH+'\r\n'))
  text=json.dumps(r);self.assertNotIn(COOKIE,text);self.assertNotIn(AUTH,text)
  fields=[h for h in r['headers'] if h['redacted']]
  self.assertEqual(len(fields),3);self.assertTrue(all(h['value'] is None and h['value_bytes']>0 for h in fields))
 def test_body_not_persisted(self):
  _,r=self.record(request(body=BODY));self.assertEqual(r['body_bytes'],len(BODY));self.assertEqual(r['body_sha256'],q.sha(BODY))
  self.assertNotIn(BODY.decode(),json.dumps(r));self.assertFalse(r['raw_request_persisted'])
 def test_public_receipt_contains_no_request_details_or_hashes(self):
  receipt,record=self.record(request('/'+ID+'?id='+ID,extras='Cookie: '+COOKIE+'\r\nX-Id: '+ID+'\r\n',body=BODY))
  text=json.dumps(receipt.public())
  for marker in (ID,COOKIE,BODY.decode(),q.sha(BODY),'level3.blizzard.com','/file','query','headers','body_sha256'):self.assertNotIn(marker,text)
  self.assertEqual(set(receipt.public()),{'schema','decision','reason','capture_id','private_stored','upstream_attempts'})
 def test_files_owner_only(self):
  receipt,_=self.record(request());s=os.stat(self.root/(receipt.capture_id+'.json'))
  self.assertEqual(stat.S_IMODE(s.st_mode),0o600);self.assertEqual(s.st_uid,os.geteuid())
 def test_unsafe_directory_refused(self):
  unsafe=Path(self.temp.name)/'unsafe';unsafe.mkdir(mode=0o755)
  with self.assertRaises(q.Rejected):q.PrivateStore(str(unsafe))
 def test_symlink_directory_refused(self):
  link=Path(self.temp.name)/'alias';link.symlink_to(self.root,target_is_directory=True)
  with self.assertRaises(OSError):q.PrivateStore(str(link))
 def test_permission_drift_blocks_without_capture(self):
  self.root.chmod(0o755)
  receipt=self.gate.inspect_http(request());self.assertFalse(receipt.private_stored);self.assertEqual(receipt.decision,'blocked');self.assertEqual(list(self.root.iterdir()),[])
 def test_existing_symlink_file_blocks(self):
  (self.root/('a'*32+'.json')).symlink_to('/dev/null')
  receipt=self.gate.inspect_http(request());self.assertFalse(receipt.private_stored);self.assertEqual(receipt.decision,'blocked')
 def test_existing_hardlink_file_blocks(self):
  target=Path(self.temp.name)/'target';target.write_bytes(b'{}');target.chmod(0o600)
  os.link(target,self.root/('a'*32+'.json'))
  self.assertFalse(self.gate.inspect_http(request()).private_stored)
 def test_file_mode_drift_blocks(self):
  receipt,_=self.record(request());(self.root/(receipt.capture_id+'.json')).chmod(0o644)
  self.assertFalse(self.gate.inspect_http(request()).private_stored)
 def test_record_count_quota_no_overwrite(self):
  ids=[self.record(request())[0].capture_id for _ in range(q.MAX_RECORDS)]
  receipt=self.gate.inspect_http(request());self.assertEqual(receipt.reason,'private_store_quota');self.assertFalse(receipt.private_stored)
  self.assertEqual(len(set(ids)),q.MAX_RECORDS);self.assertEqual(len(list(self.root.iterdir())),q.MAX_RECORDS)
 def test_quota_survives_reopening(self):
  with patch.object(q,'MAX_RECORDS',1):
   self.record(request())
   with q.PrivateStore(str(self.root)) as reopened:
    self.assertFalse(q.QuarantineGate(reopened).inspect_http(request()).private_stored)
 def test_byte_quota_blocks(self):
  with patch.object(q,'MAX_STORE_BYTES',1):self.assertFalse(self.gate.inspect_http(request()).private_stored)
  self.assertEqual(list(self.root.iterdir()),[])
 def test_storage_error_never_exposes_error_value(self):
  with patch.object(self.store,'write',side_effect=OSError(ID)):
   receipt=self.gate.inspect_http(request())
  self.assertEqual(receipt.reason,'quarantine_unavailable');self.assertNotIn(ID,json.dumps(receipt.public()))
 def test_unknown_rejection_reason_not_exported(self):
  with patch.object(self.store,'write',side_effect=q.Rejected(ID)):
   receipt=self.gate.inspect_http(request())
  self.assertEqual(receipt.reason,'quarantine_unavailable');self.assertNotIn(ID,json.dumps(receipt.public()))
 def test_credential_redaction_is_case_insensitive(self):
  _,r=self.record(request(extras='cOoKiE: '+COOKIE+'\r\nPrOxY-AuThOrIzAtIoN: '+AUTH+'\r\n'))
  self.assertNotIn(COOKIE,json.dumps(r));self.assertNotIn(AUTH,json.dumps(r))
 def test_failed_write_leaves_no_partial_capture(self):
  with patch.object(q.os,'write',side_effect=OSError(ID)):
   receipt=self.gate.inspect_http(request())
  self.assertFalse(receipt.private_stored);self.assertEqual(list(self.root.iterdir()),[])
 def test_incomplete_and_pipelined_requests_rejected(self):
  for raw in (b'GET / HTTP/1.1\r\n',request()+request(),request(body=BODY)[:-1]):
   with self.subTest(size=len(raw)):
    receipt=self.gate.inspect_http(raw);self.assertFalse(receipt.private_stored);self.assertEqual(receipt.decision,'blocked')
 def test_duplicate_host_or_length_rejected(self):
  for extra in ('Host: level3.blizzard.com\r\n','Content-Length: 0\r\nContent-Length: 0\r\n','Transfer-Encoding: chunked\r\n'):
   self.assertFalse(self.gate.inspect_http(request(extras=extra)).private_stored)
 def test_unknown_and_conflicting_host_rejected(self):
  for raw in (request().replace(b'level3.blizzard.com',b'example.invalid'),request('http://us.version.battle.net/file'),request('http://level3.blizzard.com@evil/file')):
   self.assertFalse(self.gate.inspect_http(raw).private_stored)
 def test_target_and_header_smuggling_rejected(self):
  for raw in (request('/x#fragment'),request('//evil/file'),request(extras=' Folded: value\r\n'),request(extras='X-Id: value\x00\r\n')):
   self.assertFalse(self.gate.inspect_http(raw).private_stored)
 def test_tls_and_connect_not_treated_as_http_capture(self):
  for raw in (b'\x16\x03\x01\x00\x10'+b'X'*16,b'CONNECT level3.blizzard.com:443 HTTP/1.1\r\nHost: level3.blizzard.com\r\n\r\n'):
   self.assertFalse(self.gate.inspect_http(raw).private_stored)
 def test_limits(self):
  for raw in (b'X'*(q.MAX_REQUEST+1),request(body=b'X'*(q.MAX_BODY+1)),b''):
   self.assertFalse(self.gate.inspect_http(raw).private_stored)
 def test_review_path_traversal_rejected(self):
  for ident in ('../target','a'*32+'.json','',None):
   with self.assertRaises(q.Rejected):self.store.read_for_local_review(ident)
 def test_windows_storage_fails_closed(self):
  with patch.object(q.os,'name','nt'),self.assertRaises(q.Rejected) as error:q.PrivateStore('unused')
  self.assertEqual(str(error.exception),'windows_storage_not_validated')
 def test_concurrent_capture_bounded(self):
  with ThreadPoolExecutor(max_workers=8) as pool:receipts=list(pool.map(self.gate.inspect_http,[request()]*32))
  self.assertEqual(sum(r.private_stored for r in receipts),q.MAX_RECORDS)
  self.assertTrue(all(r.decision=='blocked' and r.upstream_attempts==0 for r in receipts))
 def test_request_duplicates_preserved_not_deduplicated(self):
  a,_=self.record(request());b,_=self.record(request());self.assertNotEqual(a.capture_id,b.capture_id)
 def test_no_automatic_catalog_entry(self):
  receipt,r=self.record(request('/audit-fixture/file.bin'))
  self.assertFalse(r['approval_granted']);self.assertNotIn('resource_id',r);self.assertEqual(receipt.decision,'blocked')

if __name__=='__main__':unittest.main(verbosity=2)
