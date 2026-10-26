"""Post-fetch OFFLINE evidence checks; these never issue network requests."""
import base64,hashlib,json,socket,unittest
from unittest.mock import patch
import fetch_indices as f
from index_parser import parse_index
class Tests(unittest.TestCase):
 def setUp(self):self.p=patch.object(socket.socket,'connect',side_effect=AssertionError('network forbidden'));self.p.start()
 def tearDown(self):self.p.stop()
 def read(self,name):return json.loads((f.OUT/name).read_text())
 def test_all_16_actual_fixtures(self):
  r=self.read('fetch-evidence.json');fix=self.read('public-index-fixtures.json')['objects'];plan=f.plan((f.HERE/'plan.review-only.json').read_bytes());self.assertEqual(len(fix),16)
  total=0
  for e,row in zip(plan['entries'],r['results'],strict=True):
   b=base64.b64decode(fix[e['id']]['base64'],validate=True);self.assertEqual(f.sha(b),row['sha256']);self.assertEqual(len(b),e['expected_bytes']);self.assertEqual(f.verify(e,b)['entry_count'],row['record_count']);self.assertTrue(row['verified']);total+=len(b)
  self.assertEqual(total,272368)
 def test_merged_coverage(self):
  d=self.read('complete-index-lookup.json');a=d['index_audits'];self.assertEqual({x['id'] for x in a},{'index_'+str(i) for i in range(1,47)});self.assertEqual(len(a),46);self.assertEqual(sum(x['kind']=='archive_index' for x in a),45);self.assertEqual(sum(x['source']=='G50' for x in a),16);self.assertTrue(all(x['verified'] for x in a));self.assertEqual(sum(x['bytes'] for x in a),623408)
 def test_independent_third_key_record_scan(self):
  fix=self.read('public-index-fixtures.json')['objects'];b=base64.b64decode(fix['index_2']['base64']);target=bytes.fromhex('2f49790cbe4824363b14d37c9cb889d4');n=int.from_bytes(b[-12:-8],'little');blocks=(n+169)//170;hits=[]
  # Scan raw aligned records directly, without parse_index or locate's parsed rows.
  for block in range(blocks):
   for q in range(0,4096-23,24):
    pos=block*4096+q
    if b[pos:pos+16]==target:hits.append((int.from_bytes(b[pos+16:pos+20],'big'),int.from_bytes(b[pos+20:pos+24],'big')))
  self.assertEqual(hits,[(7461,65064708)])
  d=self.read('complete-index-lookup.json');third=next(x for x in d['sample_locations'] if x['sample_id']=='sample_3');self.assertEqual(len(third['locations']),1);self.assertEqual(third['locations'][0]['range_end'],65072168)
 def test_source_and_unexecuted_next_plan(self):
  pre=self.read('preflight.json');r=self.read('fetch-evidence.json')
  for name,digest in pre['source_hashes'].items():self.assertEqual(f.sha((f.HERE/name).read_bytes()),digest);self.assertEqual(r['source_hashes'][name],digest)
  p=self.read('next-third-sample-plan.unexecuted.json');self.assertFalse(p['executed']);self.assertEqual(p['max_requests'],1);self.assertEqual(p['expected_application_body_bytes'],7461);self.assertEqual(p['runtime_approved_entries'],0);self.assertTrue(p['reject_full_archive_200_before_body'])
if __name__=='__main__':unittest.main()
