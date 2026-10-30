import copy,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import phase1_core as c,lookup3
KEY=b'K'*32

def header(key,span=30,flags=b'\x01\x00'):
 h=key[::-1]+span.to_bytes(4,'little')+flags
 return h+lookup3.hashlittle(h,0x3D6BE971).to_bytes(4,'little')+bytes(4)
def block(suffix=b'abcdefghijklm',archive=0):return b''.join(header(bytes([n])+archive.to_bytes(2,'little')+suffix)for n in range(16))
def info(build='0'*32):return ('Product!STRING:0|Active!DEC:1|Version!STRING:0|Build Key!HEX:16\nwow|1|12.1.5.70448|'+build+'\n').encode()

class Phase1(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.root=Path(self.t.name)/'WoW';self.data=self.root/'Data'/'data';self.data.mkdir(parents=True);(self.root/'.build.info').write_bytes(info());(self.data/'data.000').write_bytes(block()+self.payload())
 def payload(self,body=b'BLTEabc',key=b'E'*16):return header(key,30+len(body),bytes(2))+body
 def snap(self,label='A1',suffix=b'abcdefghijklm'):
  (self.data/'data.000').write_bytes(block(suffix)+self.payload());return c.capture(self.root,label,KEY,True)
 def doc(self,*args):return self.snap(*args)['document']
 def test_capture_and_public_scope(self):
  s=self.snap();r=c.public_capture(s['document']);self.assertEqual(r['candidate_blocks'],1);self.assertEqual(r['complete_encoded_blte_records_sampled'],1);self.assertFalse(r['whole_game_scanned']);self.assertFalse(r['machine_identity_proven'])
 def test_key_validation(self):
  for key in(b'',b'x'*31,'bad'):
   with self.assertRaises(c.Refused):c.key_ok(key)
 def test_modern_candidate_archive_16bit(self):
  self.assertIsNotNone(c.candidate(block(archive=256),256,KEY));self.assertIsNone(c.candidate(block(archive=256),0,KEY))
 def test_legacy_candidate(self):
  raw=b''.join(header(bytes([n,2])+b'1234567'+bytes(7))for n in range(16));self.assertEqual(c.candidate(raw,2,KEY)['layout'],'legacy7_candidate')
 def test_zero_tail_not_identity_candidate(self):self.assertIsNone(c.candidate(block(bytes(13)),0,KEY))
 def test_bad_checksum(self):
  raw=bytearray(block());raw[22]^=1;self.assertIsNone(c.candidate(bytes(raw),0,KEY));r,valid,stop=c.records(bytes(raw),KEY);self.assertEqual(valid,0);self.assertEqual(stop,'unverified_header_checksum_a')
 def test_duplicate_buckets(self):self.assertIsNone(c.candidate(block()[:30]*16,0,KEY))
 def test_truncated_record_not_hashed(self):
  items,n,stop=c.records(self.payload()[:-1],KEY);self.assertEqual(items,[]);self.assertEqual(stop,'record_extends_sample')
 def test_payload_comparison_separate_from_headers(self):
  a=self.doc();b=self.doc('B1',b'NOPQRSTUVWXYZ');p=c.compare([a,b],KEY)['pairs'][0];self.assertEqual(p['different_candidate_pairs'],1);self.assertEqual(p['equal_encoded_body_sets'],1)
 def test_three_way_candidate_not_identity_proof(self):
  a=self.doc();a2=self.doc('A2');b=self.doc('B1',b'NOPQRSTUVWXYZ');r=c.compare([a,a2,b],KEY);self.assertEqual(r['a_repeat_stable_b_distinct_candidate_archives'],1);self.assertEqual(r['assessment'],'environment_linked_candidate_requires_controls');self.assertFalse(r['machine_identity_proven'])
 def test_a_repeat_change_count(self):
  a=self.doc();a2=self.doc('A2',b'NOPQRSTUVWXYZ');b=self.doc('B1',b'1234567890123');self.assertEqual(c.compare([a,a2,b],KEY)['a_repeat_changed_candidate_archives'],1)
 def test_same_candidate_no_absence_claim(self):
  r=c.compare([self.doc(),self.doc('B1')],KEY);self.assertFalse(r['absence_of_fingerprint_proven']);self.assertEqual(r['assessment'],'no_distinguishing_candidate_in_sample')
 def test_unrecognized_shape_no_absence_claim(self):
  a=self.doc();b=self.doc('B1');a['archives'][0]['candidate']=None;b['archives'][0]['candidate']=None;r=c.compare([a,b],KEY);self.assertEqual(r['pairs'][0]['common_candidate_archive_ids'],0);self.assertFalse(r['absence_of_fingerprint_proven'])
 def test_active_build_mismatch_refused(self):
  a=self.doc();(self.root/'.build.info').write_bytes(info('1'*32));b=self.doc('B1')
  with self.assertRaisesRegex(c.Refused,'active_build_mismatch'):c.compare([a,b],KEY)
 def test_wrong_key_and_tamper_refused(self):
  s=self.snap()
  with self.assertRaises(c.Refused):c.parse_snapshot(c.canonical(s),b'J'*32)
  s['document']['label']='B1'
  with self.assertRaises(c.Refused):c.parse_snapshot(c.canonical(s),KEY)
 def test_private_roundtrip(self):
  s=self.snap();self.assertEqual(c.parse_snapshot(c.canonical(s),KEY),s['document'])
 def test_public_never_contains_tokens_paths_or_keys(self):
  a=self.doc();b=self.doc('B1',b'NOPQRSTUVWXYZ');text=json.dumps([c.public_capture(a),c.compare([a,b],KEY)]);self.assertNotIn(str(self.root),text);self.assertNotIn(KEY.hex(),text)
  for d in(a,b):
   self.assertNotIn(d['build_tag'],text);self.assertNotIn(d['comparison_key_id'],text)
   for arc in d['archives']:self.assertNotIn(arc['candidate']['tag'],text);self.assertNotIn(arc['prefix_tag'],text)
 def test_no_conditions_attestation_refused(self):
  with self.assertRaises(c.Refused):c.capture(self.root,'A1',KEY)
 def test_duplicate_sample_refused(self):
  a=self.doc()
  with self.assertRaises(c.Refused):c.compare([a,a],KEY)
 def test_required_labels(self):
  with self.assertRaises(c.Refused):c.compare([self.doc('A2'),self.doc('B1')],KEY)
 def test_json_duplicate_key_refused(self):
  with self.assertRaises(c.Refused):c.parse_snapshot(b'{"document":{},"document":{}}',KEY)
 def test_schema_extra_field_refused(self):
  d=self.doc();d['raw_hostname']='do-not-accept'
  with self.assertRaises(c.Refused):c.validate(d)
 def test_symlink_refused(self):
  p=Path(self.t.name)/'linked'
  try:p.symlink_to(self.root,target_is_directory=True)
  except OSError:self.skipTest('symlinks unavailable')
  with self.assertRaises(c.Refused):c.capture(p,'A1',KEY,True)
 def test_hardlinked_archive_refused(self):
  p=self.data/'data.000'
  try:os.link(p,Path(self.t.name)/'hardlink')
  except OSError:self.skipTest('hardlinks unavailable')
  with self.assertRaises(c.Refused):c.capture(self.root,'A1',KEY,True)
 def test_reader_mutation_final_check(self):
  reader=c.Reader();reader.read(self.data/'data.000',c.PREFIX);(self.data/'data.000').write_bytes(b'changed')
  with self.assertRaises(c.Refused):reader.finish()
 def test_budget_refused(self):
  r=c.Reader();r.used=c.BUDGET
  with self.assertRaises(c.Refused):r.read(self.data/'data.000',c.PREFIX)
 def test_sampled_deadline(self):
  r=c.Reader();r.deadline=0
  with self.assertRaises(c.Refused):r.read(self.data/'data.000',c.PREFIX)
 def test_prefix_read_bound(self):
  (self.data/'data.000').write_bytes(block()+bytes(c.PREFIX+100));d=c.capture(self.root,'A1',KEY,True)['document'];self.assertEqual(d['archives'][0]['prefix_bytes'],c.PREFIX);self.assertLessEqual(d['bytes_read'],c.BUDGET)
 def test_record_walk_bound(self):
  records,n,stop=c.records(self.payload()*100,KEY);self.assertEqual(len(records),c.MAX_RECORDS);self.assertEqual(stop,'record_count_limit')
 def test_selected_whole_index(self):
  (self.data/'0000000001.idx').write_bytes(b'synthetic-index');a=self.doc();b=self.doc('B1');self.assertEqual(c.compare([a,b],KEY)['pairs'][0]['equal_whole_index_pairs'],1)
 def test_oversized_index_is_skipped(self):
  with (self.data/'0000000001.idx').open('wb')as f:f.truncate(4*c.MIB+1)
  d=self.doc();self.assertEqual(d['indices_skipped'],1)
 def test_duplicate_archive_ids_refused(self):
  (self.data/'data.0000').write_bytes(block())
  with self.assertRaises(c.Refused):self.doc()
 def test_output_inside_game_refused(self):
  with self.assertRaises(c.Refused):c.write_new(self.root/'bad.snapshot',b'x',self.root)
 def test_output_does_not_overwrite(self):
  p=Path(self.t.name)/'test.snapshot';c.write_new(p,b'x',self.root)
  with self.assertRaises(FileExistsError):c.write_new(p,b'y',self.root)
  self.assertEqual(p.read_bytes(),b'x')
 def test_input_file_size_limit(self):
  p=Path(self.t.name)/'input';p.write_bytes(b'x'*40)
  with self.assertRaises(c.Refused):c.read_small(p,32)
 def test_empty_archive_is_inconclusive(self):
  (self.data/'data.000').write_bytes(b'');d=c.capture(self.root,'A1',KEY,True)['document'];self.assertIsNone(d['archives'][0]['candidate']);self.assertEqual(d['archives'][0]['verified_header_a_count'],0)
 def test_altered_flags_not_candidate(self):
  raw=b''.join(header(bytes([n])+bytes(2)+b'abcdefghijklm',flags=bytes(2))for n in range(16));self.assertIsNone(c.candidate(raw,0,KEY))
 def test_different_encoded_bodies_not_decoded_claim(self):
  a=self.doc();b=self.doc('B1');b['archives'][0]['records'][0]['body']='f'*64;r=c.compare([a,b],KEY);self.assertEqual(r['pairs'][0]['different_encoded_body_sets'],1);self.assertFalse(r['decoded_game_payloads_compared'])
 def test_a2_without_candidates_not_stable_proof(self):
  a=self.doc();a2=self.doc('A2');b=self.doc('B1',b'NOPQRSTUVWXYZ');a2['archives'][0]['candidate']=None;r=c.compare([a,a2,b],KEY);self.assertEqual(r['three_way_common_candidate_archives'],0);self.assertEqual(r['a_repeat_stable_b_distinct_candidate_archives'],0)
if __name__=='__main__':unittest.main()
