"""Native Windows tests on NEW owned temp trees only, never installed games."""
import os,tempfile,unittest
from pathlib import Path
from installed_identity import select_active
from release_core import InvalidRelease
from test_installed_identity import CONFIG,KEY,info
from test_installed_preferences import BASE
from windows_metadata_pair import WindowsMetadataPair
class MetadataPairCases(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name)/'owned-copy';self.root.mkdir();self.i=self.root/'.build.info';self.i.write_bytes(info(tags=BASE));self.c=self.root/'Data'/'config'/KEY[:2]/KEY[2:4]/KEY;self.c.parent.mkdir(parents=True);self.c.write_bytes(CONFIG)
 def tearDown(self):self.t.cleanup()
 def test_success_exact_pair(self):
  with WindowsMetadataPair(self.root)as pair:r=pair.observe()
  self.assertEqual(r['files_opened'],2);self.assertEqual(r['actual_content_bytes_read'],2*(self.i.stat().st_size+self.c.stat().st_size));self.assertTrue(r['metadata_pair_write_delete_denied_while_held']);self.assertFalse(r['active_generation_proven']);self.assertIsNone(r['game_access'])
 def test_info_write_blocked_while_held(self):
  with WindowsMetadataPair(self.root)as pair:
   pair.observe()
   with self.assertRaises(OSError):self.i.write_bytes(b'replace')
 def test_config_write_blocked_while_held(self):
  with WindowsMetadataPair(self.root)as pair:
   pair.observe()
   with self.assertRaises(OSError):self.c.write_bytes(b'replace')
 def test_info_delete_blocked_while_held(self):
  with WindowsMetadataPair(self.root)as pair:
   pair.observe()
   with self.assertRaises(OSError):self.i.unlink()
 def test_config_rename_blocked_while_held(self):
  with WindowsMetadataPair(self.root)as pair:
   pair.observe()
   with self.assertRaises(OSError):self.c.rename(self.c.with_name('other'))
 def test_root_rename_blocked_while_held(self):
  with WindowsMetadataPair(self.root)as pair:
   pair.observe()
   with self.assertRaises(OSError):self.root.rename(self.root.with_name('other'))
 def test_ancestor_branch_rename_blocked(self):
  with WindowsMetadataPair(self.root)as pair:
   pair.observe()
   with self.assertRaises(OSError):self.c.parent.rename(self.c.parent.with_name('other'))
 def test_sharing_violation_existing_writer(self):
  # Ordinary CRT writable handle is incompatible with share-read observation.
  with self.c.open('r+b')as writer:
   with self.assertRaises(OSError):
    with WindowsMetadataPair(self.root)as pair:pair.observe()
 def test_readable_after_release(self):
  with WindowsMetadataPair(self.root)as pair:pair.observe()
  self.c.write_bytes(CONFIG);self.i.write_bytes(info(tags=BASE));self.assertEqual(self.c.read_bytes(),CONFIG)
 def test_missing_config_no_creation(self):
  self.c.unlink()
  with self.assertRaises(OSError):
   with WindowsMetadataPair(self.root)as pair:pair.observe()
  self.assertFalse(self.c.exists())
 def test_invalid_config_fail_no_repair(self):
  self.c.write_bytes(CONFIG+b'bad')
  with self.assertRaises(ValueError):
   with WindowsMetadataPair(self.root)as pair:pair.observe()
  self.assertEqual(self.c.read_bytes(),CONFIG+b'bad')
 def test_hardlinked_info_refused(self):
  os.link(self.i,self.root/'info-link')
  with self.assertRaises(InvalidRelease):
   with WindowsMetadataPair(self.root)as pair:pair.observe()
 def test_hardlinked_config_refused(self):
  os.link(self.c,self.root/'config-link')
  with self.assertRaises(InvalidRelease):
   with WindowsMetadataPair(self.root)as pair:pair.observe()
 def test_file_size_budget(self):
  with self.i.open('wb')as f:f.truncate(1048577)
  with self.assertRaises(InvalidRelease):
   with WindowsMetadataPair(self.root)as pair:pair.observe()
 def test_closed_not_reused(self):
  pair=WindowsMetadataPair(self.root);pair.close()
  with self.assertRaises(InvalidRelease):pair.observe()
 def test_single_use(self):
  with WindowsMetadataPair(self.root)as pair:
   pair.observe()
   with self.assertRaises(InvalidRelease):pair.observe()
 def test_no_enumeration_or_other_storage_reads(self):
  (self.root/'shmem').write_bytes(b'ignored');(self.root/'Data'/'lru').write_bytes(b'ignored')
  with WindowsMetadataPair(self.root)as pair:r=pair.observe()
  self.assertEqual([r[k]for k in ('directory_enumerations','shmem_bytes_read','lru_bytes_read','index_bytes_read','archive_bytes_read')],[0]*5);self.assertFalse(r['write_access_requested'])
 def test_private_tags_not_in_report(self):
  self.i.write_bytes(info(tags=BASE.replace('speech?','speech? acct-PRIVATE?')))
  with WindowsMetadataPair(self.root)as pair:r=pair.observe()
  self.assertNotIn('PRIVATE',str(r));self.assertNotIn(str(self.root),str(r))
 def test_external_paths_not_accepted(self):
  for path in ('relative','\\\\server\\share','C:\\x\\..\\y','C:\\x:stream','C:\\CON','C:\\x\\'):
   with self.assertRaises(InvalidRelease):WindowsMetadataPair(path)
 def test_unheld_info_can_be_modified_after_failure(self):
  self.c.unlink()
  with self.assertRaises(OSError):
   with WindowsMetadataPair(self.root)as pair:pair.observe()
  self.i.write_bytes(info(tags=BASE))
