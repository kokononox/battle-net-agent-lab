"""Offline contract tests. Synthetic bytes are not evidence of Battle.net payload success."""
import base64,copy,hashlib,io,json,os,socket,sys,tempfile,unittest,urllib.error,zlib
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import fetch_samples as f
RAW=(Path(__file__).parent/'plan.review-only.json').read_bytes();PLAN=json.loads(RAW)
class Response(io.BytesIO):
 def __init__(self,data,status=200,headers=None):super().__init__(data);self.code=status;self.headers=headers or {}
class Contracts(unittest.TestCase):
 def setUp(self):self.guard=patch('socket.socket',side_effect=AssertionError('network_forbidden'));self.guard.start()
 def tearDown(self):self.guard.stop()
 def validate_changed(self,p):
  raw=json.dumps(p).encode()
  with patch.object(f,'PLAN_SHA256',hashlib.sha256(raw).hexdigest()):return f.load_plan(raw)
 def test_exact_plan_pin_and_budgets(self):
  p=f.load_plan(RAW);self.assertEqual(p['max_requests'],3);self.assertEqual(p['max_encoded_bytes'],11771)
  with self.assertRaises(f.Rejected):f.load_plan(RAW+b' ')
 def test_url_injection_rejected_after_trusted_pin(self):
  for url in ('http://us.cdn.blizzard.com/x','https://telemetry-in.battle.net/data',PLAN['entries'][0]['url']+'?client_id=x',PLAN['entries'][0]['url']+'#fragment','https://u:p@us.cdn.blizzard.com/x'):
   p=copy.deepcopy(PLAN);p['entries'][0]['url']=url
   with self.assertRaises(f.Rejected):self.validate_changed(p)
 def test_extra_fields_or_duplicate_targets_rejected(self):
  p=copy.deepcopy(PLAN);p['entries'][0]['Cookie']='secret'
  with self.assertRaises(f.Rejected):self.validate_changed(p)
  p=copy.deepcopy(PLAN);p['entries'][1]=copy.deepcopy(p['entries'][0])
  with self.assertRaises(f.Rejected):self.validate_changed(p)
 def test_wrong_budget_rejected(self):
  for name in ('max_requests','max_encoded_bytes'):
   p=copy.deepcopy(PLAN);p[name]+=1
   with self.assertRaises(f.Rejected):self.validate_changed(p)
 def test_request_is_fixed_get_without_private_headers(self):
  for e in PLAN['entries']:
   r=f.request(e);self.assertEqual(r.get_method(),'GET');self.assertIsNone(r.data);self.assertEqual(r.get_header('User-agent'),'BattleNetFixedSampleReview/0.1')
   for name in ('Cookie','Authorization','Proxy-authorization','Referer'):self.assertIsNone(r.get_header(name))
 def test_non200_has_no_body_read(self):
  class NeverRead(Response):
   def read(self,*a):raise AssertionError('body_read_for_denied_response')
  for status in (301,302,307,404,206,500):
   with self.assertRaises(f.Rejected):f.read_response(NeverRead(b'ignored',status),4)
 def test_redirect_handler_does_not_follow(self):self.assertIsNone(f.NoRedirect().redirect_request(None,None,302,'',{},'https://example.invalid'))
 def test_exact_streamed_size(self):self.assertEqual(f.read_response(Response(b'data',headers={'Content-Length':'4'}),4),b'data')
 def test_oversize_or_short_body_rejected(self):
  for b in (b'abc',b'abcde'):
   with self.assertRaises(f.Rejected):f.read_response(Response(b),4)
 def test_encoding_range_and_ambiguous_length_rejected(self):
  for h in ({'Content-Encoding':'gzip'},{'Content-Range':'bytes 0-3/20'},{'Content-Length':'4','Transfer-Encoding':'chunked'},{'Content-Length':'999999'}):
   with self.assertRaises(f.Rejected):f.read_response(Response(b'data',headers=h),4)
 def fixture(self):
  plain=b'OFFLINE-SYNTHETIC-ONLY';b=b'BLTE\0\0\0\0Z'+zlib.compress(plain);e={'encoded_bytes':len(b),'decoded_bytes':len(plain),'ekey':hashlib.md5(b).hexdigest(),'ckey':hashlib.md5(plain).hexdigest()};return e,b,plain
 def test_synthetic_blte_hashes_not_real_payload(self):
  e,b,p=self.fixture();r,plain=f.verify(e,b);self.assertEqual(plain,p);self.assertEqual(r['encoded_sha256'],hashlib.sha256(b).hexdigest());self.assertEqual(r['decoded_sha256'],hashlib.sha256(p).hexdigest())
 def test_synthetic_corruption_and_wrong_ckey_rejected(self):
  e,b,_=self.fixture()
  with self.assertRaises(ValueError):f.verify(e,b[:-1]+bytes([b[-1]^1]))
  e['ckey']='0'*32
  with self.assertRaises(f.Rejected):f.verify(e,b)
 def test_private_files_non_executable_no_overwrite(self):
  with tempfile.TemporaryDirectory() as tmp,patch.object(f,'PRIVATE',Path(tmp)/'private'):
   f.private_setup();f.save_private('sample_1.encoded.bin',b'data');self.assertEqual((f.PRIVATE/'sample_1.encoded.bin').stat().st_mode&0o777,0o600)
   with self.assertRaises(FileExistsError):f.save_private('sample_1.encoded.bin',b'replace')
 def test_three_failures_consume_attempts_and_no_rerun(self):
  class Opener:
   def __init__(self):self.count=0
   def open(self,request,timeout):self.count+=1;raise urllib.error.HTTPError(request.full_url,404,'fixed',{},io.BytesIO(b''))
  op=Opener()
  with tempfile.TemporaryDirectory() as tmp,patch.object(f,'PRIVATE',Path(tmp)/'private'),patch.object(f,'REPORT',Path(tmp)),patch.object(f.urllib.request,'build_opener',return_value=op),redirect_stdout(io.StringIO()):
   self.assertFalse(f.main());r=json.loads((Path(tmp)/'fetch-evidence.local.json').read_text());self.assertEqual(op.count,3);self.assertEqual(r['attempts_reserved'],3);self.assertEqual(r['encoded_budget_reserved'],11771);self.assertEqual(r['verified_payload_count'],0)
   with self.assertRaisesRegex(f.Rejected,'one_shot'):f.main()
   self.assertEqual(op.count,3)
 def test_real_observed_evidence_is_failure_not_fixture_success(self):
  r=json.loads((Path(__file__).resolve().parents[2]/'reports/sample-download-g45/fetch-evidence.json').read_text());self.assertEqual(r['status'],'sample_plan_incomplete');self.assertEqual([x['http_status'] for x in r['results']],[404,404,404]);self.assertTrue(all(not x['verified'] for x in r['results']));self.assertTrue(all('encoded_sha256' not in x for x in r['results']));self.assertEqual(r['runtime_approved_entries'],0)
 def test_next_index_plan_has_not_executed(self):
  r=json.loads((Path(__file__).resolve().parents[2]/'reports/sample-download-g45/next-index-plan.unexecuted.json').read_text());self.assertFalse(r['executed']);self.assertEqual(len(r['entries']),46);self.assertTrue(all(not x['requested'] for x in r['entries']));self.assertFalse(r['sample_archive_locations_proven']);self.assertFalse(r['range_requests_issued'])
if __name__=='__main__':unittest.main()
