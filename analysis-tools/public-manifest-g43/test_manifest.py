"""Fully offline tests: public metadata fixtures, never executable payloads."""
import base64,hashlib,io,json,socket,struct,sys,unittest,zlib
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import discover as d
import manifests as m
P=Path(__file__).resolve().parents[2]/'reports/public-manifest-g43'
F=json.loads((P/'public-fixtures.json').read_text());DATA={k:base64.b64decode(v['base64'],validate=True) for k,v in F['objects'].items()}
D=json.loads((P/'discovery.json').read_text());C=json.loads((P/'configs.json').read_text());M=json.loads((P/'manifest-objects.json').read_text())
def blob(row):return DATA[Path(row['snapshot']).name]
def plain(row):return m.decode_blte(blob(row),row['expected_decoded_bytes'],row['ekey'])
def chunkless(mode,data):return b'BLTE\0\0\0\0'+mode+data
class MetadataTests(unittest.TestCase):
 def setUp(self):
  self.socket=patch('socket.socket',side_effect=AssertionError('network_forbidden_in_tests'));self.socket.start()
  self.open=patch.object(d.OPENER,'open',side_effect=AssertionError('network_forbidden_in_tests'));self.open.start()
 def tearDown(self):self.open.stop();self.socket.stop()
 def test_fixture_hash_and_size(self):
  for name,r in F['objects'].items():self.assertEqual(len(DATA[name]),r['bytes']);self.assertEqual(hashlib.sha256(DATA[name]).hexdigest(),r['sha256'])
  for r in D['requests']+C['requests']+M['requests']:self.assertEqual(hashlib.sha256(blob(r)).hexdigest(),r['sha256']);self.assertEqual(len(blob(r)),r['bytes'])
 def test_psv_roundtrip(self):
  for kind in ('versions','cdns'):self.assertEqual(d.psv(DATA['v1-'+kind+'.bin']),D['parsed']['v1-'+kind])
  row=next(r for r in D['parsed']['v1-versions']['rows'] if r['Region']=='us');self.assertEqual(row['VersionsName'],'2.53.6.17952')
 def test_psv_rejects_bad_schema(self):
  for b in (b'A!STRING:0|A!STRING:0\nx|y',b'not-psv',b'A!STRING:0|B!STRING:0\nx',b'A!STRING:0\nx\ty',b'x'*262145):
   with self.assertRaises(ValueError):d.psv(b)
 def test_three_config_keys_match_public_metadata(self):
  for r in C['requests']:self.assertEqual(hashlib.md5(blob(r)).hexdigest(),r['content_key']);self.assertTrue(r['content_key_md5_matches'])
  v=next(r for r in D['parsed']['v1-versions']['rows'] if r['Region']=='us')
  for r in C['requests']:self.assertEqual(r['content_key'],v[{'build':'BuildConfig','cdn':'CDNConfig','product':'ProductConfig'}[r['kind']]])
 def test_blte_keys_sizes_and_decoded_hashes(self):
  for r in M['requests']:
   b=plain(r);self.assertEqual(len(b),r['expected_decoded_bytes']);self.assertEqual(hashlib.md5(b).hexdigest(),r['ckey']);self.assertEqual(hashlib.sha256(b).hexdigest(),r['decoded_sha256'])
 def test_install_full_parse(self):
  r=next(r for r in M['requests'] if r['kind']=='install');self.assertEqual(m.parse_install(plain(r)),json.loads((P/'install-manifest.json').read_text()))
 def test_download_full_parse(self):
  r=next(r for r in M['requests'] if r['kind']=='download');self.assertEqual(m.parse_download(plain(r)),json.loads((P/'download-manifest.json').read_text()))
 def test_blte_rejects_corruption(self):
  for r in M['requests']:
   b=blob(r)
   for changed in (b[:-1],b[:-1]+bytes([b[-1]^1]),b+b'extra'):
    with self.assertRaises(ValueError):m.decode_blte(changed,r['expected_decoded_bytes'],r['ekey'])
   with self.assertRaises(ValueError):m.decode_blte(b,r['expected_decoded_bytes'],'0'*32)
 def test_reject_unsupported_compression_modes(self):
  for mode in (b'E',b'F',b'X'):
   b=chunkless(mode,b'opaque')
   with self.assertRaises(ValueError):m.decode_blte(b,6,hashlib.md5(b).hexdigest())
 def test_reject_zlib_expansion_and_trailing(self):
  b=chunkless(b'Z',zlib.compress(b'X'*(m.MAX+1)))
  with self.assertRaises(ValueError):m.decode_blte(b,m.MAX,hashlib.md5(b).hexdigest())
  b=chunkless(b'Z',zlib.compress(b'hello')+b'extra')
  with self.assertRaises(ValueError):m.decode_blte(b,5,hashlib.md5(b).hexdigest())
 def test_reject_manifest_truncation_and_trailing(self):
  for kind,parser in (('install',m.parse_install),('download',m.parse_download)):
   b=plain(next(r for r in M['requests'] if r['kind']==kind))
   for changed in (b[:2],b[:-1],b+b'extra'):
    with self.assertRaises(ValueError):parser(changed)
 def test_reject_unsafe_install_names(self):
  for name in ('../bad','a/../bad','C:/bad','/absolute','\\server\\share'):
   b=b'IN\x01\x10'+struct.pack('>HI',0,1)+name.encode()+b'\0'+b'X'*16+b'\0\0\0\1'
   with self.assertRaises(ValueError):m.parse_install(b)
 def test_url_gate_rejects_untrusted_inputs_before_network(self):
  for url in ('http://us.version.battle.net/bna/versions','https://telemetry-in.battle.net/data','https://us.version.battle.net/bna/versions?client_id=X','https://u:p@us.version.battle.net/bna/versions','https://us.version.battle.net:444/bna/versions','https://us.version.battle.net/bna/versions#X'):
   with self.assertRaises(ValueError):d.request(url,'negative')
 def test_fixed_request_headers_and_redirect_refusal(self):
  import urllib.error
  def fake(req,timeout):
   self.assertEqual(req.get_method(),'GET');self.assertEqual(req.get_header('User-agent'),'BattleNetPublicManifestReview/0.1');self.assertIsNone(req.data);self.assertIsNone(req.get_header('Cookie'));self.assertIsNone(req.get_header('Authorization'))
   raise urllib.error.HTTPError(req.full_url,302,'redirect',{'Location':'http://untrusted.invalid/'},io.BytesIO(b''))
  with patch.object(d.OPENER,'open',side_effect=fake):r,b=d.request('https://us.version.battle.net/bna/versions','redirect-test')
  self.assertFalse(r['accepted']);self.assertEqual(r['status'],302);self.assertIsNone(b);self.assertFalse(r['redirects_followed'])
 def test_no_runtime_approval_or_executable_download(self):
  for e in (D,C,M):self.assertFalse(e['installer_executed']);self.assertFalse(e['payload_downloaded']);self.assertEqual(e['catalog_entries_approved'],0)
  self.assertEqual(M['entry_downloads_attempted'],0);self.assertFalse(M['encoding_mapping_parsed']);self.assertFalse(M['platform_filter_applied'])
if __name__=='__main__':unittest.main()
