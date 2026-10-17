"""Synthetic decision/schema cases, plus native workspace read-only checks."""
from dataclasses import replace
import hashlib,json,os,sqlite3,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import build_update_plan as p
import source_binding as b
import staging_sample as s
import retail_update_cycle as cycle

T=p.Target(cycle.TARGET,s.OPTION['target_ckey'],158,33940,full_route=True)
P=p.Patch(**s.OPTION,source='fresh_encoded',patch_route=True,capability=p.CAPABILITY)
B={'product':'wow','region':'eu','version':'fixture','build_config':'a'*32,'cdn_config':'b'*32,'download_ckey':'c'*32,'download_ekey':'d'*32}

def run(ts=(T,),ps=(P,),**kw):return p.plan(ts,ps,target_binding=B,scope={'kind':'synthetic_unit_fixture'},**kw)
def action(t=T,ps=(P,)):return run([t],ps)['rows'][0]['action']
def snapshot(root):return {str(x.relative_to(root)):(x.read_bytes(),b.fp(x.stat())) for x in root.rglob('*') if x.is_file()}

class Decisions(unittest.TestCase):
 def test_patch_smaller(self):self.assertEqual(action(),'patch');self.assertEqual(run()['conditional_payload_bytes'],117)
 def test_fresh_reuse(self):self.assertEqual(action(replace(T,local='fresh_encoded')),'reuse')
 def test_reuse_zero(self):self.assertEqual(run([replace(T,local='fresh_encoded')])['conditional_payload_bytes'],0)
 def test_prior_target_not_reused(self):self.assertEqual(action(replace(T,local='prior_encoded')),'needs_verification')
 def test_candidate_not_reused(self):self.assertEqual(action(replace(T,local='candidate'),[]),'full_download')
 def test_decoded_not_encoded(self):self.assertEqual(action(replace(T,local='decoded_only'),[]),'full_download')
 def test_unknown_source_not_patch(self):self.assertEqual(action(ps=[replace(P,source='unknown')]),'full_download')
 def test_prior_source_not_patch(self):self.assertEqual(action(ps=[replace(P,source='prior_encoded')]),'full_download')
 def test_decoded_source_not_patch(self):self.assertEqual(action(ps=[replace(P,source='decoded_only')]),'full_download')
 def test_unproven_patch_not_executable(self):self.assertEqual(action(ps=[replace(P,capability='unproven')]),'full_download')
 def test_patch_route_missing(self):self.assertEqual(action(ps=[replace(P,patch_route=False)]),'full_download')
 def test_local_patch_zero(self):self.assertEqual(run(ps=[replace(P,patch_local=True)])['conditional_payload_bytes'],0)
 def test_no_route_unknown(self):self.assertIsNone(run([replace(T,full_route=False)],[])['conditional_payload_bytes'])
 def test_unknown_total_not_subtotal(self):
  t=replace(T,ekey='1'*32,ckey='2'*32,full_route=False);r=run([T,t]);self.assertIsNone(r['conditional_payload_bytes']);self.assertEqual(r['known_unique_payload_bytes_subtotal'],117)
 def test_unmapped_not_transferred(self):self.assertEqual(action(replace(T,mapped=False),[]),'needs_verification')
 def test_duplicate_target_dedup(self):r=run([T,T]);self.assertEqual(r['target_objects_evaluated'],1);self.assertEqual(r['conditional_payload_bytes'],117)
 def test_duplicate_target_conflict(self):
  with self.assertRaises(b.BindingError):run([T,replace(T,encoded_size=159)])
 def test_same_patch_key_size_conflict(self):
  with self.assertRaises(b.BindingError):run(ps=[P,replace(P,patch_size=118,capability='unproven')])
 def test_wrong_capability_edge(self):
  with self.assertRaises(b.BindingError):run(ps=[replace(P,ordinal=1)])
 def test_wrong_capability_encoding(self):
  with self.assertRaises(b.BindingError):run([replace(T,ekey='1'*32)])
 def test_bad_key(self):
  with self.assertRaises(b.BindingError):run([replace(T,ekey='A'*32)])
 def test_boolean_size_rejected(self):
  with self.assertRaises(b.BindingError):run([replace(T,encoded_size=True)])
 def test_zero_size_rejected(self):
  with self.assertRaises(b.BindingError):run([replace(T,encoded_size=0)])
 def test_wrong_patch_target(self):
  with self.assertRaises(b.BindingError):p.decide(T,[replace(P,target_size=1,capability='unproven')])
 def test_preview_not_evaluation_limit(self):r=run(preview_limit=0);self.assertEqual(r['rows'],[]);self.assertEqual(r['target_objects_evaluated'],1);self.assertEqual(r['rows_omitted'],1)
 def test_no_production_claims(self):
  r=run();self.assertIsNone(r['required_network_download_bytes']);self.assertFalse(r['apply_authorized']);self.assertFalse(r['full_game_build_plan']);self.assertFalse(r['installed_build_detected']);self.assertFalse(r['installation_ready'])
 def test_full_when_patch_not_supported(self):
  q=replace(P,capability='unproven',patch_size=1000);self.assertEqual(action(ps=[q]),'full_download')
 def test_empty_selection(self):self.assertEqual(run([],[])['conditional_payload_bytes'],0)
 def test_bad_preview_limit(self):
  with self.assertRaises(b.BindingError):run(preview_limit=-1)
 def test_deterministic_patch_choice(self):self.assertEqual(run(ps=[P,P])['rows'][0]['selected_patch']['patch_key'],P.patch_key)

class SavedAdapter(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.path=self.root/'content-plan-fixture.sqlite'
  self.db=sqlite3.connect(self.path);self.db.executescript('CREATE TABLE metadata(name TEXT PRIMARY KEY,value TEXT); CREATE TABLE plan(ekey BLOB,ckey BLOB,encoded_size INTEGER,decoded_size INTEGER,mapping_state TEXT,transfer_supported INTEGER,route_kind TEXT);')
  for k,v in [('target_binding',B),('plan_id',self.path.stem),('plan_summary',{'selected_unique_objects':2,'tag_selection':{'policy':'synthetic'}})]:self.db.execute('INSERT INTO metadata VALUES (?,?)',(k,json.dumps(v)))
  for ek in [bytes.fromhex(T.ekey),bytes.fromhex('1'*32)]:self.db.execute('INSERT INTO plan VALUES (?,?,?,?,?,?,?)',(ek,bytes.fromhex(T.ckey),158,33940,'mapped',1,'archive_range'))
  self.db.commit();self.db.close()
 def tearDown(self):self.temp.cleanup()
 def load(self,**kw):
  with patch.object(b,'load_metadata',return_value=([s.a.PatchOption(**s.OPTION)],{},B)):
   return p.saved_plan(self.path,self.root,**kw)
 def edit(self,sql,args=()):
  with sqlite3.connect(self.path) as db:db.execute(sql,args)
 def test_uses_saved_plan_route(self):r=self.load();self.assertEqual(r['actions'],{'full_download':2});self.assertEqual(r['conditional_payload_bytes'],316)
 def test_unknown_sources_not_missing(self):r=self.load();self.assertFalse(r['not_found_means_missing_or_corrupt']);self.assertEqual(r['rows'][0]['patch_diagnostics'],{'source_needs_fresh_full_verification':1})
 def test_bound_limit(self):r=self.load(limit=1);self.assertFalse(r['scope']['evaluated_all_saved_rows']);self.assertEqual(r['target_objects_evaluated'],1)
 def test_readonly(self):before=snapshot(self.root);self.load();self.assertEqual(before,snapshot(self.root))
 def test_binding_conflict(self):
  self.edit('UPDATE metadata SET value=? WHERE name=?',(json.dumps(dict(B,download_ekey='e'*32)),'target_binding'))
  with self.assertRaises(b.BindingError):self.load()
 def test_summary_conflict(self):
  self.edit('UPDATE metadata SET value=? WHERE name=?',(json.dumps({'selected_unique_objects':1,'tag_selection':{}}),'plan_summary'))
  with self.assertRaises(b.BindingError):self.load()
 def test_duplicate_ekey(self):
  self.edit('UPDATE plan SET ekey=?',(bytes.fromhex(T.ekey),))
  with self.assertRaises(b.BindingError):self.load()
 def test_wrong_plan_id(self):
  self.edit('UPDATE metadata SET value=? WHERE name=?',(json.dumps('wrong'),'plan_id'))
  with self.assertRaises(b.BindingError):self.load()
 def test_sidecar_rejected(self):
  Path(str(self.path)+'-journal').write_bytes(b'x')
  with self.assertRaises(b.BindingError):self.load()
 def test_symlink_rejected(self):
  link=self.root/'link.sqlite';link.symlink_to(self.path)
  self.path=link
  with self.assertRaises(b.BindingError):self.load()
 def test_invalid_limit(self):
  with self.assertRaises(b.BindingError):self.load(limit=0)

class Workspace(unittest.TestCase):
 def test_source_workspace_real_gate_readonly(self):
  root=Path(os.environ['SAMPLE_UPDATER_TEMPLATE']);before=snapshot(root);r=p.workspace_plan(root)
  self.assertEqual(r['actions'],{'patch':1});self.assertEqual(r['conditional_payload_bytes'],0);self.assertEqual(before,snapshot(root))
 def test_committed_workspace_real_gate_readonly(self):
  root=Path(os.environ['PLANNER_COMMITTED_WORKSPACE']);before=snapshot(root);r=p.workspace_plan(root)
  self.assertEqual(r['actions'],{'reuse':1});self.assertEqual(r['conditional_payload_bytes'],0);self.assertEqual(before,snapshot(root))
 def test_cli_bad_input_safe(self):
  r=subprocess.run([sys.executable,'-B',p.__file__,'workspace','--root','/does-not-exist'],capture_output=True,text=True)
  self.assertEqual(r.returncode,1);self.assertEqual(json.loads(r.stdout)['status'],'stopped_safely');self.assertEqual(r.stderr,'')
if __name__=='__main__':unittest.main()
