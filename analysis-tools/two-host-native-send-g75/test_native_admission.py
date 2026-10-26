import unittest,json
from native_admission import admit_exact
from pre_send_gate import Policy,CDN_HOST
from download_path_audit import Reference
P='/tpr/agent/data/ab/cd/abcdef0123456789abcdef0123456789'
class T(unittest.TestCase):
 def setUp(self):
  refs=Reference({P:[{'kind':k,'product':'agent','public_encoded_bytes':100} for k in ('public_download_manifest_entry','public_encoding_EKey_entry')]})
  self.p=Policy(refs,[])
  self.raw=('GET '+P+' HTTP/1.1\r\nHost: '+CDN_HOST+'\r\nAccept: */*\r\nConnection: close\r\n\r\n').encode()
 def test_exact_unchanged_only(self):
  self.assertEqual(admit_exact(self.p,self.raw),{'allow':True,'reason':'exact_canonical_public_input'})
 def test_noncanonical_but_policy_allowed_must_not_be_rewritten(self):
  for raw in [self.raw.replace(b'Connection: close',b'Connection: keep-alive'),self.raw.replace(b'Accept: */*\r\n',b''),self.raw.replace(b'Host:',b'hOsT:')]:
   self.assertTrue(self.p.evaluate(raw).allowed)
   self.assertEqual(admit_exact(self.p,raw),{'allow':False,'reason':'requires_canonical_input'})
 def test_incomplete_every_prefix_denied(self):
  for i in range(len(self.raw)):
   self.assertFalse(admit_exact(self.p,self.raw[:i])['allow'])
 def test_appended_private_tail_denied(self):
  self.assertFalse(admit_exact(self.p,self.raw+b'PRIVATE_SENTINEL')['allow'])
 def test_query_identifier_denied_no_raw_output(self):
  raw=self.raw.replace(P.encode(),(P+'?id=PRIVATE_SENTINEL').encode())
  r=admit_exact(self.p,raw);self.assertFalse(r['allow']);self.assertNotIn('PRIVATE_SENTINEL',json.dumps(r))
 def test_size_type_cap(self):
  for raw in [b'x'*16385,b'',None,bytearray(self.raw),'PRIVATE_SENTINEL']:
   self.assertFalse(admit_exact(self.p,raw)['allow'])
 def test_internal_exception_fail_closed(self):
  class Broken:
   def evaluate(self,b):raise RuntimeError('PRIVATE_SENTINEL')
  r=admit_exact(Broken(),self.raw);self.assertEqual(r,{'allow':False,'reason':'native_validation_failure'})
 def test_valid_range_requires_canonical_digits(self):
  raw=self.raw[:-2]+b'Range: bytes=0-99\r\n\r\n'
  self.assertTrue(admit_exact(self.p,raw)['allow'])
  r=admit_exact(self.p,raw.replace(b'bytes=0-99',b'bytes=000-099'))
  self.assertEqual(r,{'allow':False,'reason':'requires_canonical_input'})
