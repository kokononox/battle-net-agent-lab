"""In-memory sequencing/failure tests; NOT native Windows sharing evidence."""
import io,unittest
from pathlib import Path
from installed_identity import select_active
from release_core import need,InvalidRelease
from test_generation_copy_contract import fixture
from windows_generation_view import WindowsGenerationView

class MemoryView(WindowsGenerationView):
 def __init__(self,c=None):
  c=fixture()if c is None else c;self.root=Path('/owned');self.closed=False;self.streams=[];self.handles=[];self.opened=[];self.reads={};self.hook=None
  key=select_active(c.info)['buildkey'];self.blobs={'.build.info':c.info,key:c.config,'shmem':c.control,**c.indexes}
 def _directory(self,path):pass
 def _file(self,path,cap):
  name=path.name
  if name not in self.blobs:raise FileNotFoundError()
  raw=self.blobs[name];need(0<len(raw)<=cap,'metadata_file_budget');f=io.BytesIO(raw);f.name=name;self.streams.append((f,len(raw)));self.opened.append(name);return f,len(raw)
 def _read(self,f,n):
  name=f.name;self.reads[name]=self.reads.get(name,0)+1
  if self.hook:self.hook(self,f,self.reads[name])
  return WindowsGenerationView._read(f,n)
 def close(self):
  for f,n in self.streams:f.close()
  self.streams=[];self.handles=[];self.closed=True

class LogicCases(unittest.TestCase):
 def test_success_accounting_and_nineteen_files(self):
  with MemoryView()as view:
   r=view.observe();self.assertEqual(len(view.opened),19);self.assertEqual(view.reads['.build.info'],5);self.assertEqual(view.reads['shmem'],3);self.assertEqual(sum(view.reads.values()),45);self.assertEqual(r['directory_enumerations'],0)
 def test_indexes_all_open_before_first_index_read(self):
  with MemoryView()as view:
   def hook(v,f,n):
    if f.name.endswith('.idx'):self.assertEqual(len(v.opened),19)
   view.hook=hook;view.observe()
 def test_control_mutation_on_second_read_stops(self):
  with MemoryView()as view:
   def hook(v,f,n):
    if f.name=='shmem'and n==2:f.seek(-1,2);f.write(b'\x01')
   view.hook=hook
   with self.assertRaisesRegex(InvalidRelease,'control_changed'):view.observe()
   self.assertTrue(view.closed)
 def test_control_mutation_after_index_rereads_stops(self):
  with MemoryView()as view:
   def hook(v,f,n):
    if f.name=='shmem'and n==3:f.seek(-1,2);f.write(b'\x01')
   view.hook=hook
   with self.assertRaisesRegex(InvalidRelease,'control_changed_after_indexes'):view.observe()
 def test_index_mutation_on_reread_stops(self):
  with MemoryView()as view:
   def hook(v,f,n):
    if f.name=='0000000000.idx'and n==2:f.seek(44);f.write(b'\xff')
   view.hook=hook
   with self.assertRaisesRegex(InvalidRelease,'index_bytes_changed'):view.observe()
 def test_baseline_mutation_at_final_check_stops(self):
  with MemoryView()as view:
   def hook(v,f,n):
    if f.name=='.build.info'and n==5:f.seek(-1,2);f.write(b'!')
   view.hook=hook
   with self.assertRaisesRegex(InvalidRelease,'metadata_changed_after_indexes'):view.observe()
 def test_missing_final_index_releases_prior_handles(self):
  with MemoryView()as view:
   del view.blobs['0f0000000f.idx']
   with self.assertRaises(FileNotFoundError):view.observe()
   self.assertTrue(view.closed);self.assertFalse(view.streams)
 def test_larger_filename_not_opened(self):
  with MemoryView()as view:
   view.blobs['000000ffff.idx']=b'never read';view.observe();self.assertNotIn('000000ffff.idx',view.opened)
 def test_control_name_not_exported(self):
  with MemoryView()as view:
   r=view.observe();self.assertNotIn('Global',str(r));self.assertFalse(r['client_successful_bind_proven']);self.assertIsNone(r['game_access'])
 def test_failure_does_not_leave_streams(self):
  with MemoryView(fixture(state=2))as view:
   with self.assertRaises(InvalidRelease):view.observe()
   self.assertTrue(view.closed);self.assertEqual(view.streams,[])
if __name__=='__main__':unittest.main()
