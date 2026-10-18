"""Native Windows tests; only new owned synthetic trees, never installed games."""
import dataclasses,os,tempfile,unittest
from pathlib import Path
from release_core import InvalidRelease
from test_local_content_capture import sample
from test_release_core import target
from test_local_archive_capture import archive_fixture
from local_archive_capture import ArchiveReadRequest
from windows_archive_capture import WindowsArchiveCapture
class ArchiveCases(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name);self.root=self.base/'owned';self.path=self.root/'Data'/'data'/'data.003';self.path.parent.mkdir(parents=True);self.scratch=self.base/'scratch';self.scratch.mkdir();self.raw,self.spec=sample();self.req=ArchiveReadRequest(target(),self.spec,3,700,'prefix30-agent9824',30+len(self.raw));self.original=archive_fixture(self.raw,self.spec);self.path.write_bytes(self.original)
 def acquire(self,reader,req=None):
  c,r=reader.capture(req or self.req,scratch=self.scratch);self.addCleanup(c.close);return c,r
 def test_exact_one_archive_full_identity(self):
  with WindowsArchiveCapture(self.root)as reader:
   c,r=self.acquire(reader);self.assertTrue(c.verify()['full_ckey_verified']);self.assertEqual(len(reader.streams),1);self.assertEqual(r['archive_application_content_bytes_read'],self.req.span);self.assertTrue(r['unbuffered_source_reads'])
 def test_source_write_refused(self):
  with WindowsArchiveCapture(self.root)as reader:
   self.acquire(reader)
   with self.assertRaises(OSError):self.path.write_bytes(b'bad')
 def test_source_delete_refused(self):
  with WindowsArchiveCapture(self.root)as reader:
   self.acquire(reader)
   with self.assertRaises(OSError):self.path.unlink()
 def test_source_rename_refused(self):
  with WindowsArchiveCapture(self.root)as reader:
   self.acquire(reader)
   with self.assertRaises(OSError):self.path.rename(self.path.with_name('other'))
 def test_parent_rename_refused(self):
  with WindowsArchiveCapture(self.root)as reader:
   self.acquire(reader)
   with self.assertRaises(OSError):self.path.parent.rename(self.path.parent.with_name('other'))
 def test_existing_writer_refused(self):
  with self.path.open('r+b')as writer:
   with WindowsArchiveCapture(self.root)as reader:
    with self.assertRaises(OSError):self.acquire(reader)
    self.assertTrue(reader.closed)
 def test_hardlinked_source_refused(self):
  os.link(self.path,self.base/'alias')
  with WindowsArchiveCapture(self.root)as reader:
   with self.assertRaises(InvalidRelease):self.acquire(reader)
   self.assertTrue(reader.closed)
 def test_missing_archive_no_creation_or_fallback(self):
  self.path.unlink();(self.path.parent/'data.004').write_bytes(self.original)
  with WindowsArchiveCapture(self.root)as reader:
   with self.assertRaises(OSError):self.acquire(reader)
  self.assertFalse(self.path.exists())
 def test_stat_bounds_failure_releases_handles(self):
  self.path.write_bytes(b'short')
  with WindowsArchiveCapture(self.root)as reader:
   with self.assertRaises(InvalidRelease):self.acquire(reader)
   self.assertTrue(reader.closed)
  self.path.write_bytes(self.original);self.assertEqual(list(self.scratch.iterdir()),[])
 def test_header_failure_releases_handles_and_copy(self):
  b=bytearray(self.original);b[700]^=1;self.path.write_bytes(b)
  with WindowsArchiveCapture(self.root)as reader:
   with self.assertRaises(InvalidRelease):self.acquire(reader)
   self.assertTrue(reader.closed)
  self.path.write_bytes(self.original);self.assertEqual(list(self.scratch.iterdir()),[])
 def test_payload_failure_cleans_copy(self):
  b=bytearray(self.original);b[730+len(self.raw)-1]^=1;self.path.write_bytes(b)
  with WindowsArchiveCapture(self.root)as reader:
   with self.assertRaises(InvalidRelease):self.acquire(reader)
  self.assertEqual(list(self.scratch.iterdir()),[]);self.path.write_bytes(self.original)
 def test_copy_outlives_source_and_source_can_change_after_release(self):
  with WindowsArchiveCapture(self.root)as reader:c,r=self.acquire(reader)
  self.path.write_bytes(b'changed');self.assertTrue(c.verify()['full_ckey_verified'])
 def test_direct_layout_must_be_explicit(self):
  self.path.write_bytes(b'x'*700+self.raw+b'trailer');req=dataclasses.replace(self.req,layout='direct-blte',byte_budget=len(self.raw))
  with WindowsArchiveCapture(self.root)as reader:c,r=self.acquire(reader,req);self.assertEqual(r['header_bytes_read'],0)
 def test_single_use_closes_source_on_second_attempt(self):
  with WindowsArchiveCapture(self.root)as reader:
   c,r=self.acquire(reader)
   with self.assertRaises(InvalidRelease):self.acquire(reader)
   self.assertTrue(reader.closed);self.assertTrue(c.verify()['full_ckey_verified'])
 def test_closed_reader_refused(self):
  reader=WindowsArchiveCapture(self.root);reader.close()
  with self.assertRaises(InvalidRelease):self.acquire(reader)
 def test_metadata_observe_disabled(self):
  with WindowsArchiveCapture(self.root)as reader:
   with self.assertRaises(InvalidRelease):reader.observe()
   self.assertEqual(reader.streams,[])
 def test_no_metadata_required_or_other_reads_claimed(self):
  with WindowsArchiveCapture(self.root)as reader:
   c,r=self.acquire(reader)
   for k in('build_info_bytes_read','build_config_bytes_read','index_bytes_read','shmem_bytes_read','lru_bytes_read','directory_enumerations'):self.assertEqual(r[k],0,k)
   self.assertFalse(r['apply_authorized']);self.assertFalse(r['live_archive_backend_qualified']);self.assertNotIn(str(self.root),str(r))
