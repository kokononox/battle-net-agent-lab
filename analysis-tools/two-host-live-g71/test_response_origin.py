import unittest,json
from response_origin import ResponseOrigin,locate,split_http,Reject
K='0123456789abcdef0123456789abcdef';P='/tpr/fixture/config/01/23/'+K
BODY=('Region!STRING:0|BuildConfig!HEX:16\nus|'+K+'\n').encode()
def req(route='/agent/versions'):
 return ('GET '+route+' HTTP/1.1\r\nHost: us.version.battle.net\r\n\r\n').encode()
def resp(body=BODY,extra=b''):
 return b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\n'+extra+b'\r\n'+body
class ResponseOriginTests(unittest.TestCase):
 def test_location_and_independent(self):
  a=ResponseOrigin([{'route':'/v2/products/agent/versions','status':200,'text':BODY.decode()}]);a.feed(1,'out',req());a.feed(1,'in',resp(extra=('ETag: "'+K+'"\r\n').encode()));a.target(K,P);r=a.report();x=r['targets'][0];self.assertEqual(x['paired_response_occurrences'][0]['route'],'/agent/versions');self.assertTrue(x['independent_reference_occurrences']);self.assertIn('BuildConfig',json.dumps(r));self.assertNotIn(K,json.dumps(r));self.assertNotIn(P,json.dumps(r))
 def test_fragmentation_every_byte(self):
  a=ResponseOrigin()
  for b in req():a.feed(1,'out',bytes([b]))
  for b in resp():a.feed(1,'in',bytes([b]))
  a.target(K,P);self.assertEqual(len(a.rows[0]['paired_response_occurrences']),1)
 def test_context_isolation(self):
  a=ResponseOrigin();a.feed(1,'out',req());a.feed(2,'in',resp());a.target(K,P);self.assertFalse(a.rows[0]['paired_response_occurrences']);self.assertEqual(a.counts['response_without_observed_request'],1)
 def test_FIFO_two_requests(self):
  a=ResponseOrigin();a.feed(1,'out',req('/agent/cdns')+req('/bna/versions'));a.feed(1,'in',resp(b'x')+resp());a.target(K,P);self.assertEqual(a.rows[0]['paired_response_occurrences'][0]['route'],'/bna/versions')
 def test_informational_does_not_pop(self):
  a=ResponseOrigin();a.feed(1,'out',req());a.feed(1,'in',b'HTTP/1.1 100 Continue\r\n\r\n'+resp());a.target(K,P);self.assertEqual(len(a.rows[0]['paired_response_occurrences']),1)
 def test_later_match_not_prior(self):
  a=ResponseOrigin();a.target(K,P);a.feed(1,'out',req());a.feed(1,'in',resp());self.assertFalse(a.rows[0]['paired_response_occurrences'][0]['preceded_target_observation'])
 def test_chunked(self):
  a=ResponseOrigin();a.feed(1,'out',req());a.feed(1,'in',b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'+format(len(BODY),'x').encode()+b'\r\n'+BODY+b'\r\n0\r\n\r\n');a.target(K,P);self.assertTrue(a.rows[0]['paired_response_occurrences'])
 def test_ambiguous_rejected(self):
  a=ResponseOrigin();a.feed(1,'out',req());a.feed(1,'in',resp(extra=b'Transfer-Encoding: chunked\r\n'));a.target(K,P);self.assertFalse(a.rows[0]['paired_response_occurrences']);self.assertEqual(a.counts['ambiguous_framing'],1)
 def test_encoded_body_not_attributed(self):
  a=ResponseOrigin();a.feed(1,'out',req());a.feed(1,'in',resp(extra=b'Content-Encoding: gzip\r\n'));a.target(K,P);self.assertFalse(a.rows[0]['paired_response_occurrences']);self.assertEqual(a.counts['unsupported_content_encoding'],1)
 def test_private_header_name_not_exported(self):
  x=locate(K,{'private_thing':[K]},b'');self.assertEqual(x[0]['field'],'<other_header>');self.assertNotIn('private_thing',json.dumps(x))
 def test_unknown_route_redacted(self):
  a=ResponseOrigin();a.feed(1,'out',req('/private_path?secret=SENTINEL_PRIVATE_QUERY'));a.feed(1,'in',resp());a.target(K,P);r=json.dumps(a.report());self.assertNotIn('private_path',r);self.assertNotIn('SENTINEL_PRIVATE_QUERY',r)
 def test_json_fixed_key(self):
  x=locate(K,{},json.dumps({'BuildConfig':K}).encode());self.assertEqual(x[0]['field'],'BuildConfig')
 def test_status_304_no_body(self):
  a=ResponseOrigin();a.feed(1,'out',req()+req());a.feed(1,'in',b'HTTP/1.1 304 Not Modified\r\nContent-Length: 100\r\n\r\n'+resp());a.target(K,P);self.assertEqual(len(a.rows[0]['paired_response_occurrences']),1)
 def test_close_delimited_not_guessed(self):
  a=ResponseOrigin();a.feed(1,'out',req());a.feed(1,'in',b'HTTP/1.1 200 OK\r\n\r\n'+BODY);a.target(K,P);self.assertEqual(a.counts['close_delimited_unsupported'],1)
 def test_bad_table_shape_not_field(self):
  x=locate(K,{},b'BadHeader\n'+K.encode());self.assertEqual(x[0]['area'],'body')
 def test_substring_not_exact(self):
  x=locate(K,{},BODY.replace(K.encode(),b'prefix'+K.encode()));self.assertEqual(x[0]['match'],'substring')
 def test_independent_non200_excluded(self):
  a=ResponseOrigin([{'route':'/agent/versions','status':404,'text':BODY.decode()}]);a.target(K,P);self.assertFalse(a.rows[0]['independent_reference_occurrences'])
 def test_wrong_request_host_rejected(self):
  a=ResponseOrigin();a.feed(1,'out',req().replace(b'us.version.battle.net',b'other.example'));a.feed(1,'in',resp());a.target(K,P);self.assertFalse(a.rows[0]['paired_response_occurrences'])
 def test_context_after_error_stays_blocked(self):
  a=ResponseOrigin();a.feed(1,'out',b'invalid\r\n\r\n');a.feed(1,'out',req());a.feed(1,'in',resp());a.target(K,P);self.assertFalse(a.rows[0]['paired_response_occurrences'])

 def test_HEAD_rejected_not_misframed(self):
  a=ResponseOrigin();a.feed(1,'out',req().replace(b'GET ',b'HEAD '));self.assertEqual(a.counts['non_GET_pairing_unsupported'],1)

 def test_embedded_JSON_string(self):
  body=json.dumps({'config':{'settings':{'c++_x64':json.dumps({'hash':K})}}}).encode();x=locate(K,{},body);self.assertEqual(x[0]['area'],'embedded_JSON_value');self.assertEqual(x[0]['field'],'hash');self.assertEqual(x[0]['match'],'exact_value')
 def test_MIME_table(self):
  body=b'--boundary\r\nContent-Type: text/plain\r\n\r\n'+BODY+b'\r\n--boundary--\r\n';x=locate(K,{'content-type':['multipart/mixed; boundary=boundary']},body);self.assertEqual(x[0]['field'],'BuildConfig');self.assertEqual(x[0]['wrapper'],'MIME_part')
 def test_BLTE_chunkless_N(self):
  x=locate(K,{},b'BLTE\0\0\0\0N'+BODY);self.assertEqual(x[0]['wrapper'],'BLTE_chunkless_N');self.assertEqual(x[0]['field'],'BuildConfig')
 def test_unsupported_BLTE_not_stripped(self):
  self.assertFalse(locate(K,{},b'BLTE\0\0\0\0E'+BODY))
 def test_typed_table_after_preamble(self):
  x=locate(K,{},b'-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n'+BODY);self.assertEqual(x[0]['field'],'BuildConfig')
 def test_pinned_ProductConfig_refs_revalidate(self):
  from response_origin import load_pinned_product_refs
  from pathlib import Path
  refs=load_pinned_product_refs(Path(__file__).parent);self.assertEqual(len(refs),2);self.assertTrue(all(r['kind']=='pinned_ProductConfig' for r in refs))
 def test_whole_public_doc_containment(self):
  text=json.dumps({'hash':K});a=ResponseOrigin([{'route':'pinned_ProductConfig:agent','kind':'pinned_ProductConfig','status':200,'text':text}]);a.feed(1,'out',req());a.feed(1,'in',resp(b'wrapper'+text.encode()+b'end'));a.target(K,P);x=a.rows[0]['paired_response_occurrences'][0];self.assertTrue(x['pinned_public_body_equalities'][0]['entire_pinned_document_contained']);self.assertTrue(any(v.get('field')=='hash' for v in x['locations']));self.assertNotIn(K,json.dumps(a.report()))
 def test_dynamic_blob_route_redacted(self):
  a=ResponseOrigin();a.feed(1,'out',req('/v1/products/agent/blobs/'+K));a.feed(1,'in',resp());a.target(K,P);x=a.rows[0]['paired_response_occurrences'][0];self.assertEqual(x['route'],'/v1/products/agent/blobs/<opaque_key>');self.assertNotIn(K,json.dumps(a.report()))

 def test_MIME_boundary_case_preserved(self):
  body=b'--CASEboundary\r\nContent-Type: text/plain\r\n\r\n'+BODY+b'\r\n--CASEboundary--\r\n';x=locate(K,{'content-type':['multipart/mixed; boundary=CASEboundary']},body);self.assertEqual(x[0]['field'],'BuildConfig')
