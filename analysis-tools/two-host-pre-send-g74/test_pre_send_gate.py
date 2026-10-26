import unittest,json
from pathlib import Path
from pre_send_gate import Policy,CompleteRequestGate,load_policy,MAX_REQUEST,FIXED_UA,CDN_HOST,VERSION_HOST
from download_path_audit import Reference

P='/tpr/agent/data/ab/cd/abcdef0123456789abcdef0123456789'
ROUTE='/v2/products/agent/versions'
def request(target=P,host=CDN_HOST,headers=b'',method=b'GET',body=b''):
 return method+b' '+target.encode()+b' HTTP/1.1\r\nHost: '+host.encode()+b'\r\n'+headers+b'\r\n'+body
class T(unittest.TestCase):
 def setUp(self):
  self.refs=Reference({P:[{'kind':k,'product':'agent','public_encoded_bytes':100}
                         for k in ('public_download_manifest_entry','public_encoding_EKey_entry')]})
  self.policy=Policy(self.refs,[ROUTE])
 def decide(self,b):return self.policy.evaluate(b)
 def no(self,b):
  d=self.decide(b);self.assertFalse(d.allowed);self.assertEqual(d.wire,b'');self.assertEqual(d.host,'')
  self.assertNotIn('PRIVATE_SENTINEL',json.dumps(d.audit()))
 def test_public_CDN_request_rebuilt(self):
  d=self.decide(request(headers=b'User-Agent: '+FIXED_UA.encode()+b'\r\nContent-Length: 0\r\nConnection: keep-alive\r\n'))
  self.assertTrue(d.allowed)
  self.assertEqual(d.wire,('GET '+P+' HTTP/1.1\r\nHost: '+CDN_HOST+'\r\nAccept: */*\r\nConnection: close\r\n\r\n').encode())
 def test_metadata_route(self):
  d=self.decide(request(ROUTE,VERSION_HOST));self.assertTrue(d.allowed);self.assertEqual(d.host,VERSION_HOST)
 def test_unknown_and_wrong_host_negative(self):
  for h in ['PRIVATE_SENTINEL.invalid',CDN_HOST+':80',CDN_HOST+'.',CDN_HOST.upper(),VERSION_HOST]:self.no(request(host=h))
 def test_query_and_noncanonical_path_negative(self):
  for p in [P+'?id=PRIVATE_SENTINEL',P+'?seqn=1',P+'#x',P+'/',P.upper(),P.replace('/ab/','/ef/'),P.replace('/data/','/%64ata/'),'http://'+CDN_HOST+P,'//'+CDN_HOST+P]:self.no(request(p))
 def test_method_and_version_negative(self):
  for m in [b'POST',b'HEAD',b'CONNECT',b'get']:self.no(request(method=m))
  for suffix in [b'HTTP/1.0',b'HTTP/2',b'HTTP/1.1 ']:self.no(request().replace(b'HTTP/1.1',suffix))
 def test_body_and_pipelining_negative(self):
  for tail in [b'PRIVATE_SENTINEL',b'\r\n',request(),b'\x00']:
   self.no(request(body=tail))
 def test_framing_and_credentials_negative(self):
  for h in [b'Content-Length: 1',b'Content-Length: 00',b'Transfer-Encoding: chunked',b'Cookie: PRIVATE_SENTINEL',b'Authorization: PRIVATE_SENTINEL',b'Proxy-Authorization: PRIVATE_SENTINEL',b'X-Machine: PRIVATE_SENTINEL',b'Accept-Encoding: gzip',b'Expect: 100-continue',b'Upgrade: h2c']:
   self.no(request(headers=h+b'\r\n'))
 def test_header_value_validation(self):
  for h in [b'User-Agent: PRIVATE_SENTINEL',b'User-Agent: phoenix-agent/1.0 PRIVATE_SENTINEL',b'Accept: PRIVATE_SENTINEL',b'Connection: PRIVATE_SENTINEL']:
   self.no(request(headers=h+b'\r\n'))
 def test_duplicate_and_ambiguous_headers(self):
  for h in [b'Host: '+CDN_HOST.encode(),b'hOsT: '+CDN_HOST.encode(),b'Accept: */*\r\nAccept: */*',b'Range: bytes=0-99\r\nrange: bytes=0-99',b' Host: '+CDN_HOST.encode(),b'Host : '+CDN_HOST.encode(),b': x',b'Broken',b'X_thing: x']:
   self.no(request(headers=h+b'\r\n'))
 def test_noncanonical_octets_negative(self):
  for x in [b'\t',b'\x00',b'\x7f',b'\xff',b'\n',b'\r']:
   self.no(request(headers=b'Accept: */*'+x+b'\r\n'))
 def test_full_range_canonicalized(self):
  d=self.decide(request(headers=b'Range: bytes=000-099\r\n'));self.assertTrue(d.allowed)
  self.assertIn(b'Range: bytes=0-99\r\n',d.wire);self.assertNotIn(b'000-099',d.wire)
 def test_bad_ranges_negative(self):
  for r in [b'bytes=0-98',b'bytes=1-99',b'bytes=0-100',b'bytes=0-',b'bytes=-100',b'bytes=0-99,0-99',b'bytes=99-0',b'PRIVATE_SENTINEL']:
   self.no(request(headers=b'Range: '+r+b'\r\n'))
 def test_metadata_query_alias_and_range_negative(self):
  for p in [ROUTE+'?seqn=123',ROUTE+'?id=PRIVATE_SENTINEL','/agent/versions','/v2/products/unknown/versions']:
   self.no(request(p,VERSION_HOST))
  self.no(request(ROUTE,VERSION_HOST,b'Range: bytes=0-99\r\n'))
 def test_incomplete_and_multiple_messages(self):
  for b in [b'',request()[:-1],request()+request(),b'GET /',b'\x16\x03\x03\x00\x10']:
   self.no(b)
 def test_size_header_bounds(self):
  self.no(b'x'*(MAX_REQUEST+1))
  self.no(request(headers=b'Accept: */*\r\n'*33))
 def test_every_split_point_has_no_early_output(self):
  raw=request(headers=b'Range: bytes=0-99\r\n');expected=self.decide(raw)
  for i in range(len(raw)+1):
   g=CompleteRequestGate(self.policy)
   self.assertIs(g.feed(raw[:i]),True);self.assertIs(g.feed(raw[i:]),True)
   self.assertEqual(g.finish(),expected);self.assertEqual(g._buffer,bytearray())
 def test_one_byte_fragments(self):
  g=CompleteRequestGate(self.policy)
  for b in request():self.assertTrue(g.feed(bytes([b])))
  self.assertTrue(g.finish().allowed)
 def test_append_private_data_before_finish_denied(self):
  g=CompleteRequestGate(self.policy);self.assertTrue(g.feed(request()));self.assertTrue(g.feed(b'PRIVATE_SENTINEL'))
  self.assertFalse(g.finish().allowed);self.assertEqual(g._buffer,bytearray())
 def test_finish_is_single_use(self):
  g=CompleteRequestGate(self.policy);g.feed(request());self.assertTrue(g.finish().allowed)
  self.assertFalse(g.feed(b'PRIVATE_SENTINEL'));self.assertEqual(g.finish().reason,'gate_already_finished')
 def test_failed_gate_cannot_recover(self):
  g=CompleteRequestGate(self.policy);self.assertFalse(g.feed(b'x'*(MAX_REQUEST+1)));self.assertFalse(g.feed(request()))
  self.assertEqual(g.finish().reason,'request_size')
 def test_nonbytes_input_denied(self):
  for v in ['PRIVATE_SENTINEL',bytearray(request()),None,True,123]:
   g=CompleteRequestGate(self.policy);self.assertFalse(g.feed(v));self.assertFalse(g.finish().allowed)
   self.assertFalse(self.decide(v).allowed)
 def test_validation_exception_fail_closed_no_message(self):
  class Broken:
   def evaluate(self,b):raise RuntimeError('PRIVATE_SENTINEL')
  g=CompleteRequestGate(Broken());g.feed(request());d=g.finish();self.assertEqual(d.reason,'validation_failure')
  self.assertNotIn('PRIVATE_SENTINEL',json.dumps(d.audit()))
 def test_caller_reference_mutation_cannot_widen_policy(self):
  self.refs['/PRIVATE_SENTINEL']=self.refs[P];self.refs[P][0]['public_encoded_bytes']=99
  self.no(request('/PRIVATE_SENTINEL'));self.assertTrue(self.decide(request(headers=b'Range: bytes=0-99\r\n')).allowed)
 def test_canonical_output_not_input_variation(self):
  one=self.decide(request())
  two=self.decide(request(headers=b'aCcEpT:   */*  \r\nConnection: keep-alive\r\n'))
  self.assertTrue(two.allowed);self.assertEqual(one.wire,two.wire)
 def test_pinned_real_reference_positive_and_near_boundary(self):
  from download_path_audit import load_reference,full_object_size
  base=Path(__file__).parent;policy=load_policy(base);refs,_=load_reference(base)
  path=next(p for p in sorted(refs) if full_object_size(p,refs) is not None and not refs.ranges.get(p) and full_object_size(p,refs)>1)
  size=full_object_size(path,refs)
  self.assertTrue(policy.evaluate(request(path,headers=('Range: bytes=0-'+str(size-1)+'\r\n').encode())).allowed)
  self.assertFalse(policy.evaluate(request(path,headers=('Range: bytes=0-'+str(size-2)+'\r\n').encode())).allowed)
  self.assertTrue(policy.evaluate(request(ROUTE,VERSION_HOST)).allowed)
 def test_pinned_bts_path_positive(self):
  from schema_attribution import public_config_paths,load_extra_refs
  base=Path(__file__).parent;policy=load_policy(base)
  paths=public_config_paths(load_extra_refs(base));path=next(p for p,rr in paths.items() if any(r['product']=='bts' for r in rr))
  self.assertTrue(policy.evaluate(request(path)).allowed)
  self.assertFalse(policy.evaluate(request(path+'?id=PRIVATE_SENTINEL')).allowed)
 def test_reference_pin_change_is_not_auto_accepted(self):
  import tempfile,shutil
  base=Path(__file__).parent
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp)
   for n in ['public-download-reference.json','public-schema-reference.json']:
    shutil.copyfile(base/n,tmp/n)
   (tmp/'public-download-reference.json').write_bytes((tmp/'public-download-reference.json').read_bytes()+b' ')
   with self.assertRaises(ValueError):load_policy(tmp)
 def test_schema_pin_change_is_not_auto_accepted(self):
  import tempfile,shutil
  base=Path(__file__).parent
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp)
   for n in ['public-download-reference.json','public-schema-reference.json']:
    shutil.copyfile(base/n,tmp/n)
   (tmp/'public-schema-reference.json').write_bytes((tmp/'public-schema-reference.json').read_bytes()+b' ')
   with self.assertRaises(ValueError):load_policy(tmp)
 def test_body_cannot_be_hidden_by_zero_content_length(self):
  self.no(request(headers=b'Content-Length: 0\r\n',body=b'PRIVATE_SENTINEL'))
 def test_all_header_fragment_points_then_denied_tail(self):
  raw=request()
  for i in range(len(raw)+1):
   gate=CompleteRequestGate(self.policy);gate.feed(raw[:i]);gate.feed(raw[i:]);gate.feed(b'PRIVATE_SENTINEL')
   d=gate.finish();self.assertFalse(d.allowed);self.assertEqual(d.wire,b'')
