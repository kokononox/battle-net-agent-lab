import dataclasses,hashlib,unittest
from test_release_core import target
import release_core as c
import config_binding as b

def pair(v='1.1.0.200',extra=b''):
 t=target(v);raw=('build-uid = wow\nbuild-name = WOW-'+str(t.build_id)+'patch'+t.version.rsplit('.',1)[0]+'_Retail\n').encode()
 for i,n in enumerate(('install','download','encoding')):raw+=(n+' = '+str(i+1)*32+' '+str(i+5)*32+'\n'+n+'-size = 100 80\n').encode()
 raw+=extra;bk=hashlib.md5(raw).hexdigest();cdn=('archives = '+'e'*32+'\nbuilds = '+bk+'\n').encode();return dataclasses.replace(t,build_config=bk,cdn_config=hashlib.md5(cdn).hexdigest()),raw,cdn
class ConfigTests(unittest.TestCase):
 def bad(self,fn,*args):
  with self.assertRaises(c.InvalidRelease):fn(*args)
 def test_identity_binding(self):
  r=b.bind(*pair());self.assertTrue(r['build_config_md5_verified']);self.assertEqual(len(r['manifest_descriptors']),3);self.assertFalse(r['manifest_blobs_fetched']);self.assertFalse(r['apply_authorized'])
 def test_another_future_release_same_code(self):
  r=b.bind(*pair('19.4.0.90001'));self.assertEqual(r['target']['version'],'19.4.0.90001')
 def test_build_hash_mismatch(self):
  t,r,d=pair();self.bad(b.bind,t,r+b' ',d)
 def test_cdn_hash_mismatch(self):
  t,r,d=pair();self.bad(b.bind,t,r,d+b' ')
 def test_wrong_build_name(self):
  t,r,d=pair();self.bad(b.bind,dataclasses.replace(t,version='1.2.0.200'),r,d)
 def test_duplicate_config_key(self):
  t,r,d=pair(extra=b'build-uid = wow\n');self.bad(b.bind,t,r,d)
 def test_cdn_other_build(self):
  t,r,d=pair();d=b'builds = '+b'f'*32+b'\n';t=dataclasses.replace(t,cdn_config=hashlib.md5(d).hexdigest());self.bad(b.bind,t,r,d)
 def test_optional_no_builds_list(self):
  t,r,d=pair();d=b'archives = '+b'e'*32+b'\n';t=dataclasses.replace(t,cdn_config=hashlib.md5(d).hexdigest());self.assertFalse(b.bind(t,r,d)['cdn_explicit_build_membership_checked'])
 def test_missing_key_pair(self):self.bad(b.descriptor,{'install':['a'*32],'install-size':['100','80']},'install')
 def test_zero_size(self):self.bad(b.descriptor,{'install':['a'*32,'b'*32],'install-size':['0','80']},'install')
 def test_oversize(self):self.bad(b.descriptor,{'install':['a'*32,'b'*32],'install-size':[str(512*1024**2+1),'80']},'install')
 def test_unknown_manifest(self):self.bad(b.descriptor,{},'arbitrary')
 def test_urls_are_config_not_assets(self):
  for url in b.config_urls(pair()[0]):self.assertIn('/config/',url);self.assertNotIn('/data/',url)
 def test_asset_request_rejected(self):self.bad(b.ConfigTransport(pair()[0]).fetch,'https://us.cdn.blizzard.com/tpr/wow/data/aa/bb/object')
 def test_arbitrary_config_request_rejected(self):self.bad(b.ConfigTransport(pair()[0]).fetch,'https://other.example/tpr/wow/config/aa/bb/'+'a'*32)
if __name__=='__main__':unittest.main()
