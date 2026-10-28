import hashlib,unittest
import public_manifest_sizes as p
class Sizes(unittest.TestCase):
 def fixture(self,extra=''):
  raw=('build-uid = wow\nbuild-name = WOW-70575patch12.1.5_Retail\n'+''.join(n+' = '+'a'*32+' '+'b'*32+'\n'+n+'-size = 200240171 188058470\n'for n in ('encoding','download','install'))+extra).encode();key=hashlib.md5(raw).hexdigest();url='https://level3.ssl.blizzard.com/tpr/wow/config/'+key[:2]+'/'+key[2:4]+'/'+key;return raw,key,url
 def test_exact_sizes_and_conditional_claim(self):
  r=p.analyze(*self.fixture());self.assertEqual(r['manifests']['encoding']['encoded_bytes'],188058470);self.assertTrue(r['encoding_object_exceeds_phase_threshold']);self.assertFalse(r['actual_agent_object_transfer_identified']);self.assertFalse(r['game_payload_requested'])
 def test_content_key_mismatch(self):
  raw,key,url=self.fixture()
  with self.assertRaises(Exception):p.analyze(raw+b' ',key,url)
 def test_unknown_fields_not_exported(self):
  r=p.analyze(*self.fixture('private_arbitrary_label = arbitrary value\n'));self.assertNotIn('private_arbitrary_label',str(r))
 def test_no_redirect_or_wrong_origin(self):
  raw,key,url=self.fixture()
  for u in (url.replace('https:','http:'),url.replace('level3.ssl.blizzard.com','example.com'),url+'?x=1'):
   with self.assertRaises(ValueError):p.analyze(raw,key,u)
 def test_limit_before_parsing(self):
  with self.assertRaises(ValueError):p.analyze(b'x'*1048577,'a'*32,'')
 def test_size_type_and_negative_refused(self):
  for bad in ('-1','1e8','NaN','0'):
   raw,key,url=self.fixture();raw=raw.replace(b'188058470',bad.encode());key=hashlib.md5(raw).hexdigest();url='https://level3.ssl.blizzard.com/tpr/wow/config/'+key[:2]+'/'+key[2:4]+'/'+key
   with self.assertRaises(ValueError):p.analyze(raw,key,url)
if __name__=='__main__':unittest.main()
