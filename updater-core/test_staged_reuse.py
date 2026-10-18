import contextlib,dataclasses,hashlib,io,json,sqlite3,tempfile,unittest
from pathlib import Path
from test_release_core import fixture_baseline
from test_build_catalogue import fixture
from test_metadata_objects import fixture as blte_fixture
from build_catalogue import build
from candidate_plan import build_candidate
from release_core import InvalidRelease,RunCheckpoint,TargetSnapshot
from local_candidates import ObjectSpec
from archive_transfer import ArchiveSource,ArchiveResponse,archive_url
from segment_stage import SegmentStage
from staged_reuse import reverify_candidate_stage
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.b,self.o=fixture(self.root)
  with contextlib.redirect_stdout(io.StringIO()):build(self.b,self.o)
  self.plan=self.root/'plan';p=build_candidate(self.b,self.o,self.plan,'Windows');self.cp=RunCheckpoint(fixture_baseline(),TargetSnapshot.restore(p['target']));self.raw,s=blte_fixture(b'abcde',b'N');self.spec=ObjectSpec(s.ckey,s.ekey,s.decoded_size,s.encoded_size);self.src=ArchiveSource('1'*32,'2'*64,100)
  self.stage=SegmentStage.create(self.root/'stage',self.cp,self.spec,self.src);self.stage.append(ArchiveResponse(archive_url(self.cp,self.src),100,100+len(self.raw)-1,1000,'"cache"',self.raw),(0,len(self.raw)-1));self.update_db()
 def update_db(self):
  # Synthetic catalogue uses arbitrary keys; substitute one valid BLTE pair,
  # then bind the receipts to those exact synthetic DB bytes.
  p=self.o/'TARGET-CATALOGUE.sqlite';d=sqlite3.connect(p);d.execute('DELETE FROM content_links');d.execute('DELETE FROM encodings');d.execute('INSERT INTO content_links VALUES(?,?,?)',(bytes.fromhex(self.spec.ckey),bytes.fromhex(self.spec.ekey),self.spec.decoded_size));d.execute('INSERT INTO encodings VALUES(?,?,?)',(bytes.fromhex(self.spec.ekey),self.spec.encoded_size,0));d.commit();d.close();r=json.loads((self.o/'CATALOGUE-VERIFIED-to-share.json').read_bytes());r['database']={'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()};(self.o/'CATALOGUE-VERIFIED-to-share.json').write_text(json.dumps(r));p=self.plan/'CANDIDATE-PLAN.sqlite';d=sqlite3.connect(p);d.execute('DELETE FROM selected_download');d.execute('INSERT INTO selected_download VALUES(?,?,?,?)',(0,bytes.fromhex(self.spec.ekey),self.spec.encoded_size,0));d.commit();d.close();r2=json.loads((self.plan/'CANDIDATE-PLAN-to-share.json').read_bytes());r2['source_catalogue_sha256']=r['database']['sha256'];r2['database']={'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()};(self.plan/'CANDIDATE-PLAN-to-share.json').write_text(json.dumps(r2))
 def run_reuse(self):return reverify_candidate_stage(self.stage,self.plan,self.o)
 def test_verified_input_not_installed_reuse(self):
  raw,r=self.run_reuse();self.assertEqual(raw,self.raw);self.assertTrue(r['eligible_as_verified_staging_input']);self.assertFalse(r['installed_content_reuse_authorized']);self.assertIsNone(r['required_network_download_bytes'])
 def test_receipt_flags_not_an_authority(self):
  r=json.loads((self.plan/'CANDIDATE-PLAN-to-share.json').read_bytes());r['apply_authorized']=True;(self.plan/'CANDIDATE-PLAN-to-share.json').write_text(json.dumps(r));self.assertFalse(self.run_reuse()[1]['apply_authorized'])
 def test_tampered_stage(self):
  name=self.stage.doc['segments'][0]['name'];(self.stage.path/name).write_bytes(b'x'*len(self.raw))
  with self.assertRaises(InvalidRelease):self.run_reuse()
 def test_changed_target(self):
  r=json.loads((self.plan/'CANDIDATE-PLAN-to-share.json').read_bytes());r['target']['version']='19.2.0.99001';r['target']['build_id']=99001;(self.plan/'CANDIDATE-PLAN-to-share.json').write_text(json.dumps(r))
  with self.assertRaises(InvalidRelease):self.run_reuse()
 def test_tampered_plan(self):
  p=self.plan/'CANDIDATE-PLAN.sqlite';raw=p.read_bytes();p.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
  with self.assertRaises(InvalidRelease):self.run_reuse()
 def test_missing_selected_key(self):
  p=self.plan/'CANDIDATE-PLAN.sqlite';d=sqlite3.connect(p);d.execute('DELETE FROM selected_download');d.commit();d.close();r=json.loads((self.plan/'CANDIDATE-PLAN-to-share.json').read_bytes());r['database']['sha256']=hashlib.sha256(p.read_bytes()).hexdigest();(self.plan/'CANDIDATE-PLAN-to-share.json').write_text(json.dumps(r))
  with self.assertRaises(InvalidRelease):self.run_reuse()
class SchemaRegression(unittest.TestCase):
 def test_primary_key_first_without_rowid_integrity(self):
  from pathlib import Path
  # Check the exact table statement shipped in the builder, not a second schema.
  import reuse_candidates
  source=Path(reuse_candidates.__file__).read_text();ddl=source.split('CREATE TABLE local_refs(',1)[1].split(';',1)[0];d=sqlite3.connect(':memory:');d.execute('CREATE TABLE local_refs('+ddl);d.execute('INSERT INTO local_refs(prefix,archive_id,offset,span,member,ordinal) VALUES(?,?,?,?,?,?)',(b'a'*9,1,10,52,'0000000001.idx',0));d.commit();self.assertEqual(d.execute('PRAGMA integrity_check').fetchall(),[('ok',)]);d.close()
 def test_msb_against_independent_tactsharp_bitarray_recipe(self):
  for byte in range(256):
   reverse=((byte*0x0202020202)&0x010884422010)%1023
   for bit in range(8):self.assertEqual(bool(byte&(0x80>>bit)),bool(reverse&(1<<bit)))
if __name__=='__main__':unittest.main()
