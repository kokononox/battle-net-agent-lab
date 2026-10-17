"""Boundary tests for direct live-file admission and pinned FD identity."""
import fcntl,json,os,shutil,struct,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import agent_archive_direct as d
import owned_v8_lock as locks
import patch_audit as a
import retail_v8_cycle as base
import source_binding as b
ORACLE=Path(os.environ['DIRECT_ORACLE']).resolve()
TEMPLATE=Path(os.environ['RETAIL_DIRECT_CYCLE_TEMPLATE']).resolve()
class DirectBoundaryTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()/'cycle';shutil.copytree(TEMPLATE,self.root)
 def tearDown(self):self.temp.cleanup()
 def read(self,addresses=[480]*4,**kw):return d.compare(ORACLE,self.root,addresses,**kw)
 def test_no_lock_is_rejected(self):
  with self.assertRaises(a.AuditError):self.read()
 def test_arbitrary_marked_directory_is_not_admitted(self):
  with tempfile.TemporaryDirectory() as p:
   root=Path(p).resolve();(root/'data.000').write_bytes((self.root/'data.000').read_bytes());(root/'.archive-insert-research.json').write_text('{"format":"archive-insert-owned-fixture-1"}')
   with self.assertRaises(a.AuditError):d.compare(ORACLE,root,[480])
 def test_current_lock_only_covers_its_own_root(self):
  other=Path(self.temp.name).resolve()/'other';shutil.copytree(self.root,other)
  with base.locked(self.root):
   with self.assertRaises(a.AuditError):d.compare(ORACLE,other,[480])
 def test_expired_lock_is_rejected(self):
  with base.locked(self.root):self.read()
  with self.assertRaises(a.AuditError):self.read()
 def test_fd_is_live_named_inode_and_readonly(self):
  original=d.subprocess.run;seen=[]
  def run(*args,**kw):
   fd,lockfd=kw['pass_fds'];self.assertEqual(b.fp(os.fstat(fd)),b.fp((self.root/'data.000').stat()));self.assertEqual(fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE,os.O_RDONLY);self.assertEqual(b.fp(os.fstat(lockfd)),b.fp((self.root/'LOCK').stat()));seen.append(fd)
   return original(*args,**kw)
  with base.locked(self.root):
   with patch.object(d.subprocess,'run',run):rows=self.read()
  self.assertEqual(len(seen),1);self.assertTrue(rows.proof['same_live_inode_read_not_snapshot']);self.assertEqual(rows.proof['snapshots_created'],0)
 def test_native_rejects_writable_inherited_archive_fd(self):
  fd=os.open(self.root/'data.000',os.O_RDWR)
  try:
   request=struct.pack('<Q14I3Q',480,188,1,0,0,0,1,fd,0,0,0,0,0,0,0,0,0,0)
   proc=subprocess.run([str(ORACLE)],input=request,capture_output=True,pass_fds=(fd,),timeout=5);self.assertNotEqual(proc.returncode,0)
  finally:os.close(fd)
 def test_native_rejects_write_mode_even_with_readonly_fd(self):
  fd=os.open(self.root/'data.000',os.O_RDONLY)
  try:
   request=struct.pack('<Q14I3Q',480,188,0,0,0,0,1,fd,0,0,0,0,0,0,0,0,0,0)
   proc=subprocess.run([str(ORACLE)],input=request,capture_output=True,pass_fds=(fd,),timeout=5);self.assertNotEqual(proc.returncode,0)
  finally:os.close(fd)
 def test_hardlinked_archive_rejected(self):
  os.link(self.root/'data.000',Path(self.temp.name)/'alias')
  with base.locked(self.root):
   with self.assertRaises(b.BindingError):self.read()
 def test_symlinked_archive_rejected(self):
  p=self.root/'data.000';p.rename(self.root/'saved');p.symlink_to(self.root/'saved')
  with base.locked(self.root):
   with self.assertRaises(b.BindingError):self.read()
 def test_wrong_marker_and_strict_layout_rejected(self):
  (self.root/'unexpected').write_bytes(b'!')
  with base.locked(self.root):
   with self.assertRaises(a.AuditError):self.read()
 def test_other_archive_address_rejected(self):
  with base.locked(self.root):
   with self.assertRaises(a.AuditError):self.read([(1<<30)+480])
 def test_unpublished_out_of_file_target_rejected(self):
  with base.locked(self.root):
   with self.assertRaises(a.AuditError):self.read([668])
 def test_source_read_and_reuse(self):
  with base.locked(self.root):rows=self.read()
  self.assertEqual([r['create_calls'] for r,data in rows],[1]*4);self.assertEqual([r['constructor_calls'] for r,data in rows],[1]*4)
 def test_open_error_maps_to8_and_next_attempt_recovers(self):
  with base.locked(self.root):rows=self.read(open_error=5,open_error_on=1)
  self.assertEqual([r['status'] for r,data in rows],[8,0,0,0]);self.assertEqual([r['create_calls'] for r,data in rows],[1,2,2,2])
 def test_read_error_keeps_cache(self):
  with base.locked(self.root):rows=self.read(read_error=5,read_error_on=2)
  self.assertEqual([r['status'] for r,data in rows],[0,8,0,0]);self.assertEqual([r['create_calls'] for r,data in rows],[1]*4)
 def test_eof_status_zero_is_not_exact(self):
  with base.locked(self.root):rows=self.read(read_error=38,read_error_on=2)
  self.assertEqual(rows[1][0]['status'],0)
  with self.assertRaises(a.AuditError):d.prior.require_exact(rows,188)
 def test_in_place_change_during_child_is_detected(self):
  original=d.subprocess.run
  def run(*args,**kw):
   result=original(*args,**kw);p=self.root/'data.000';data=bytearray(p.read_bytes());data[530]^=1;p.write_bytes(data);return result
  with base.locked(self.root):
   with patch.object(d.subprocess,'run',run):
    with self.assertRaises((a.AuditError,b.BindingError)):self.read()
 def test_path_replacement_during_child_is_detected(self):
  original=d.subprocess.run
  def run(*args,**kw):
   result=original(*args,**kw);p=self.root/'data.000';raw=p.read_bytes();p.rename(self.root/'old');p.write_bytes(raw);return result
  with base.locked(self.root):
   with patch.object(d.subprocess,'run',run):
    with self.assertRaises((a.AuditError,b.BindingError)):self.read()
 def test_competing_child_cannot_take_inherited_lock(self):
  with base.locked(self.root):
   p=subprocess.run([__import__('sys').executable,'-c',"import fcntl,sys; f=open(sys.argv[1],'r+b'); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)",str(self.root/'LOCK')],capture_output=True,timeout=5)
   self.assertNotEqual(p.returncode,0)
 def test_no_context_leak_after_exception(self):
  try:
   with base.locked(self.root):raise RuntimeError('test')
  except RuntimeError:pass
  with self.assertRaises(a.AuditError):locks.require(self.root)
if __name__=='__main__':unittest.main(verbosity=2)
