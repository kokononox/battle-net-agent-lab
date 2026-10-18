import json,sqlite3,unittest
from reuse_candidates import classify_candidates,archive_stats
from release_core import InvalidRelease
class Tests(unittest.TestCase):
 def db(self,keys=None,refs=None,stats=None):
  d=sqlite3.connect(':memory:');self.addCleanup(d.close);d.executescript('CREATE TABLE target_objects(ekey BLOB PRIMARY KEY,prefix BLOB,encoded_size INTEGER); CREATE TABLE local_refs(prefix BLOB,archive_id INTEGER,offset INTEGER,span INTEGER,member TEXT,ordinal INTEGER); CREATE TABLE archive_sizes(archive_id INTEGER PRIMARY KEY,bytes INTEGER);');keys=keys if keys is not None else [(b'a'*16,b'a'*9,52)];d.executemany('INSERT INTO target_objects VALUES(?,?,?)',keys);d.executemany('INSERT INTO local_refs VALUES(?,?,?,?,?,?)',refs or []);d.executemany('INSERT INTO archive_sizes VALUES(?,?)',[(1,1000)]if stats is None else stats);return d
 def r(self,span=52,offset=10,ordinal=0):return (b'a'*9,1,offset,span,'0000000001.idx',ordinal)
 def test_no_reference_unknown_not_missing(self):
  r=classify_candidates(self.db());self.assertEqual(r['without_reference_in_uploaded_copy_UNKNOWN'],1);self.assertEqual(r['proven_missing_objects'],0);self.assertIsNone(r['required_network_download_bytes'])
 def test_direct_is_candidate_only(self):
  r=classify_candidates(self.db(refs=[self.r()]));self.assertEqual(r['with_size_and_reported_bounds_candidate_NOT_content_proof'],1);self.assertEqual(r['reuse_authorized_objects'],0);self.assertEqual(r['reuse_credit_bytes'],0)
 def test_prefix30_not_assumed_native_header(self):
  r=classify_candidates(self.db(refs=[self.r(82)]));self.assertEqual(r['with_size_and_reported_bounds_candidate_NOT_content_proof'],1);self.assertFalse(r['active_generation_proven'])
 def test_paired_locators_not_selected(self):
  r=classify_candidates(self.db(refs=[self.r(52,40),self.r(82,10,1)]));self.assertEqual(r['with_multiple_compatible_bounded_locators_NOT_arbitrarily_selected'],1);self.assertEqual(r['reuse_authorized_objects'],0)
 def test_wrong_size(self):
  r=classify_candidates(self.db(refs=[self.r(51)]));self.assertEqual(r['with_any_prefix_reference'],1);self.assertEqual(r['with_size_and_reported_bounds_candidate_NOT_content_proof'],0)
 def test_outside_reported_bounds(self):
  r=classify_candidates(self.db(refs=[self.r(offset=990)]));self.assertEqual(r['with_size_and_reported_bounds_candidate_NOT_content_proof'],0);self.assertEqual(r['proven_missing_objects'],0)
 def test_missing_archive_stat(self):
  r=classify_candidates(self.db(refs=[self.r()],stats=[]));self.assertEqual(r['with_compatible_locator_but_missing_stat_UNKNOWN'],1);self.assertEqual(r['with_size_and_reported_bounds_candidate_NOT_content_proof'],0)
 def test_prefix_collision_not_full_identity(self):
  r=classify_candidates(self.db(keys=[(b'a'*16,b'a'*9,52),(b'a'*9+b'b'*7,b'a'*9,52)],refs=[self.r()]));self.assertEqual(r['target_prefix_collision_groups'],1);self.assertEqual(r['reuse_authorized_objects'],0)
 def test_wrong_prefix(self):
  r=classify_candidates(self.db(refs=[(b'z'*9,1,10,52,'x',0)]));self.assertEqual(r['with_any_prefix_reference'],0)
 def test_empty_target(self):self.assertEqual(classify_candidates(self.db(keys=[]))['candidate_target_objects'],0)
 def stat(self,files=None):return json.dumps({'format':'windows-storage-stat-only-1','status':'three_direct_storage_directories_reviewed_NOT_content_proof','folders':[{'relative_directory':'Data/data','files':files if files is not None else [{'name':'data.001','kind':'archive','bytes':1000}]}]}).encode()
 def test_stat(self):self.assertEqual(archive_stats(self.stat()),{1:1000})
 def test_duplicate_stat_not_guessed(self):
  with self.assertRaises(InvalidRelease):archive_stats(self.stat([{'name':'data.001','kind':'archive','bytes':5}]*2))
 def test_stat_path_rejected(self):
  with self.assertRaises(InvalidRelease):archive_stats(self.stat([{'name':'../data.001','kind':'archive','bytes':5}]))
 def test_boolean_stat_rejected(self):
  with self.assertRaises(InvalidRelease):archive_stats(self.stat([{'name':'data.001','kind':'archive','bytes':True}]))
 def test_zero_stat_preserved(self):self.assertEqual(archive_stats(self.stat([{'name':'data.001','kind':'archive','bytes':0}])),{1:0})
if __name__=='__main__':unittest.main()
