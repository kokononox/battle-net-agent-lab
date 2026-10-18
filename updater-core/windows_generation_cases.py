"""Real Windows kernel sharing tests, NEW synthetic owned trees only."""
import dataclasses,json,os,tempfile,unittest
from pathlib import Path
from release_core import InvalidRelease
from installed_identity import select_active
from test_generation_copy_contract import fixture
from windows_generation_view import WindowsGenerationView

class GenerationViewCases(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name)/'owned-fixture';self.root.mkdir();self.build=fixture();self.write(self.build)
 def tearDown(self):self.t.cleanup()
 def write(self,c):
  (self.root/'.build.info').write_bytes(c.info)
  key=select_active(c.info)['buildkey'];p=self.root/'Data'/'config'/key[:2]/key[2:4];p.mkdir(parents=True,exist_ok=True);(p/key).write_bytes(c.config)
  self.d=self.root/'Data'/'data';self.d.mkdir(parents=True,exist_ok=True);(self.d/'shmem').write_bytes(c.control)
  for name,raw in c.indexes.items():(self.d/name).write_bytes(raw)
 def observe(self):
  with WindowsGenerationView(self.root)as view:return view.observe()
 def test_v7_all_19_files_held(self):
  with WindowsGenerationView(self.root)as view:
   r=view.observe();self.assertEqual(len(view.streams),19);self.assertEqual(r['files_opened'],19);self.assertTrue(r['native_handle_capture_implemented']);self.assertTrue(r['published_control_references_checked'])
 def test_v8_no_location_guess(self):
  self.write(fixture(version=8));r=self.observe();self.assertEqual(r['index_family'],8);self.assertIn('v8_archive_location_fields_opaque',r['blockers'])
 def test_v4_control_profile(self):self.write(fixture(protocol=4));self.assertEqual(self.observe()['control_profile']['protocol'],4)
 def test_budget_actual_reads(self):
  r=self.observe();c=self.build;n=sum(map(len,c.indexes.values()));self.assertEqual(r['actual_content_bytes_read'],5*(len(c.info)+len(c.config))+3*len(c.control)+2*n);self.assertLessEqual(r['actual_content_bytes_read'],r['maximum_content_bytes_read'])
 def test_shmem_write_blocked(self):
  with WindowsGenerationView(self.root)as view:
   view.observe()
   with self.assertRaises(OSError):(self.d/'shmem').write_bytes(b'bad')
 def test_all_indexes_write_blocked(self):
  with WindowsGenerationView(self.root)as view:
   view.observe()
   for name in self.build.indexes:
    with self.subTest(name=name):
     with self.assertRaises(OSError):(self.d/name).write_bytes(b'bad')
 def test_index_delete_blocked(self):
  with WindowsGenerationView(self.root)as view:
   view.observe()
   with self.assertRaises(OSError):(self.d/next(iter(self.build.indexes))).unlink()
 def test_control_rename_blocked(self):
  with WindowsGenerationView(self.root)as view:
   view.observe()
   with self.assertRaises(OSError):(self.d/'shmem').rename(self.d/'renamed')
 def test_data_directory_rename_blocked(self):
  with WindowsGenerationView(self.root)as view:
   view.observe()
   with self.assertRaises(OSError):self.d.rename(self.d.with_name('other'))
 def test_existing_control_writer_refused(self):
  with (self.d/'shmem').open('r+b'):
   with self.assertRaises(OSError):self.observe()
 def test_existing_last_index_writer_refused_and_prior_released(self):
  name=list(self.build.indexes)[-1]
  with (self.d/name).open('r+b'):
   with self.assertRaises(OSError):self.observe()
  (self.d/'shmem').write_bytes(self.build.control)
  (self.d/next(iter(self.build.indexes))).write_bytes(next(iter(self.build.indexes.values())))
 def test_missing_index_no_fallback(self):
  name=next(iter(self.build.indexes));(self.d/name).rename(self.d/'000000ffff.idx')
  with self.assertRaises(OSError):self.observe()
  self.assertFalse((self.d/name).exists())
 def test_unreferenced_larger_filename_not_read(self):
  (self.d/'000000ffff.idx').write_bytes(b'unknown');r=self.observe();self.assertEqual(r['selected_index_files'],16);self.assertFalse(r['newer_filename_fallback_used']);self.assertFalse(r['complete_directory_inventory_observed'])
 def test_hardlinked_control_refused(self):
  os.link(self.d/'shmem',self.d/'control-link')
  with self.assertRaises(InvalidRelease):self.observe()
 def test_hardlinked_index_refused(self):
  name=next(iter(self.build.indexes));os.link(self.d/name,self.d/'index-link')
  with self.assertRaises(InvalidRelease):self.observe()
 def test_pending_state_no_repair(self):
  self.write(fixture(state=2))
  with self.assertRaises(InvalidRelease):self.observe()
  self.assertEqual((self.d/'shmem').read_bytes(),fixture(state=2).control)
 def test_checksum_failure_no_repair(self):
  name=next(iter(self.build.indexes));raw=bytearray(self.build.indexes[name]);raw[4]^=1;(self.d/name).write_bytes(raw)
  with self.assertRaises(InvalidRelease):self.observe()
  self.assertEqual((self.d/name).read_bytes(),raw)
 def test_failure_closes_all_handles(self):
  (self.d/list(self.build.indexes)[-1]).unlink();view=WindowsGenerationView(self.root)
  with self.assertRaises(OSError):view.observe()
  self.assertTrue(view.closed);self.assertFalse(view.streams);self.assertFalse(view.handles)
 def test_release_allows_write_again(self):
  self.observe()
  for name,raw in self.build.indexes.items():(self.d/name).write_bytes(raw)
  (self.d/'shmem').write_bytes(self.build.control)
 def test_no_authority_promotion(self):
  r=self.observe()
  for k in ('active_generation_proven','client_successful_bind_proven','store_semantic_binding_proven','coherent_live_snapshot_proven','local_reuse_authorized','fresh_installed_preferences_proven','required_set_selected','installation_ready','apply_authorized','write_access_requested'):self.assertFalse(r[k],k)
  self.assertIsNone(r['required_network_download_bytes']);self.assertIsNone(r['game_access']);self.assertEqual(r['archive_bytes_read'],0);self.assertEqual(r['lru_bytes_read'],0)
 def test_report_no_private_path_or_control_name(self):
  text=json.dumps(self.observe());self.assertNotIn(str(self.root),text);self.assertNotIn('Global',text);self.assertNotIn('Private',text)
 def test_single_use(self):
  with WindowsGenerationView(self.root)as view:
   view.observe()
   with self.assertRaises(InvalidRelease):view.observe()
 def test_extension_not_claimed_qualified(self):
  self.write(fixture(ext=True));self.assertIn('control_extension_semantics_unqualified',self.observe()['blockers'])
 def test_oversize_control_no_content_read(self):
  with (self.d/'shmem').open('wb')as f:f.truncate(65537)
  with self.assertRaises(InvalidRelease):self.observe()
