import tempfile,hashlib,json,dataclasses,unittest,io,contextlib
from pathlib import Path
from test_release_core import target
from test_catalogue_readers import install,download,encoding
from build_catalogue import build
from release_core import InvalidRelease

def fixture(root,v='19.1.0.99000'):
 base=root/'base';objects=root/'objects';base.mkdir();objects.mkdir();t=target(v);raw=('build-uid = wow\nbuild-name = WOW-'+str(t.build_id)+'patch'+v.rsplit('.',1)[0]+'_Retail\n').encode();proofs=[]
 for i,(name,data) in enumerate([('install',install()),('download',download()),('encoding',encoding())]):
  ck=hashlib.md5(data).hexdigest();ek=str(i+1)*32;raw+=(name+' = '+ck+' '+ek+'\n'+name+'-size = '+str(len(data))+' 80\n').encode();(objects/(name+'.decoded')).write_bytes(data);proofs.append({'name':name,'ckey':ck,'decoded_sha256':hashlib.sha256(data).hexdigest()})
 bk=hashlib.md5(raw).hexdigest();cdn=('builds = '+bk+'\n').encode();t=dataclasses.replace(t,build_config=bk,cdn_config=hashlib.md5(cdn).hexdigest());(base/'observed-build.config').write_bytes(raw);(base/'observed-cdn.config').write_bytes(cdn);(objects/'METADATA-VERIFIED-to-share.json').write_text(json.dumps({'format':'approved-dynamic-metadata-receipt-1','status':'three_metadata_objects_identity_and_blte_verified','target':t.public(),'metadata':proofs}));return base,objects
class BuildTests(unittest.TestCase):
 def run_build(self,base,objects):
  with contextlib.redirect_stdout(io.StringIO()):return build(base,objects)
 def test_dynamic_small_fixture_and_integrity(self):
  with tempfile.TemporaryDirectory() as tmp:
   base,o=fixture(Path(tmp));r=self.run_build(base,o);self.assertEqual(r['target']['version'],'19.1.0.99000');self.assertEqual(r['counts']['download_records'],1);self.assertEqual(r['counts']['install_entries'],1);self.assertTrue(all(v==0 for v in r['coverage'].values()));self.assertFalse(r['required_set_selected']);self.assertFalse(r['installation_ready']);self.assertEqual(r['database']['integrity_check'],'ok')
 def test_another_version_without_code_change(self):
  with tempfile.TemporaryDirectory() as tmp:
   base,o=fixture(Path(tmp),'20.0.0.100001');self.assertEqual(self.run_build(base,o)['target']['version'],'20.0.0.100001')
 def test_altered_raw_input_rejected(self):
  with tempfile.TemporaryDirectory() as tmp:
   base,o=fixture(Path(tmp));p=o/'download.decoded';data=bytearray(p.read_bytes());data[-1]^=1;p.write_bytes(data)
   with self.assertRaises(InvalidRelease):self.run_build(base,o)
   self.assertFalse((o/'TARGET-CATALOGUE.sqlite').exists())
 def test_unverified_receipt_rejected(self):
  with tempfile.TemporaryDirectory() as tmp:
   base,o=fixture(Path(tmp));p=o/'METADATA-VERIFIED-to-share.json';r=json.loads(p.read_text());r['status']='not_verified';p.write_text(json.dumps(r))
   with self.assertRaises(InvalidRelease):self.run_build(base,o)
 def test_existing_output_not_overwritten(self):
  with tempfile.TemporaryDirectory() as tmp:
   base,o=fixture(Path(tmp));p=o/'TARGET-CATALOGUE.sqlite';p.write_bytes(b'keep')
   with self.assertRaises(InvalidRelease):self.run_build(base,o)
   self.assertEqual(p.read_bytes(),b'keep')
if __name__=='__main__':unittest.main()
