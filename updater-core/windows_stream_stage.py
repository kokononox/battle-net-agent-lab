"""Native Windows OWNED scratch stage. No game writes, scan, install or repair.
Uses shared format/geometry/verifier; native file sharing and guarded directories.
Synthetic backend testing is not native CASC/activation/power-loss qualification.
"""
import contextlib,hashlib,os
from pathlib import Path
from release_core import need
from stream_stage import StreamStage,stage_identity
from windows_store import WindowsStore

class WindowsStreamStage(StreamStage):
 @classmethod
 def create(cls,path,cp,spec,source):
  identity=stage_identity(cp,spec,source);store=WindowsStore(path,create=True)
  try:
   doc={'format':'stream-segment-stage-1','identity':identity,'committed_bytes':0,'etag':None,'archive_total':None,'segments':[]};store.write_new('journal.json',cls._encode(doc));return cls._attach(store,cp,spec,source,cp.baseline)
  except BaseException:store.close();raise
 @classmethod
 def restore(cls,path,cp,spec,source,current_baseline):
  store=WindowsStore(path)
  try:return cls._attach(store,cp,spec,source,current_baseline)
  except BaseException:store.close();raise
 @classmethod
 def _attach(cls,store,cp,spec,source,current_baseline):
  cp.resume(current_baseline);s=cls();s.store=store;s.path=Path(store.path);s.cp=cp;s.spec=spec;s.source=source;s.identity=stage_identity(cp,spec,source);s._load();return s
 def _root(self):self.store.check()
 def _read_journal(self):return self.store.read('journal.json',1024**2)
 def _open_segment(self,row):return self.store.open_read(row['name'],size=row['size'])
 def _write(self,name,raw):self.store.write_new(name,raw)
 def _replace(self,source,dest):self.store.replace(source,dest)
 def _sync(self,path):self.store.check() # No unsupported directory fsync claim.
 @contextlib.contextmanager
 def _lock(self):
  self._root();fd=self.store.create_handle('writer.lock')
  try:yield
  finally:os.close(fd);self.store.remove_lock()
 def summary(self):return dict(super().summary(),backend='native_windows_owned_scratch',power_loss_qualified=False,game_access=False)
 def verify(self):return dict(super().verify(),backend='native_windows_owned_scratch',power_loss_qualified=False,native_casc_writer_qualified=False)
 def close(self):
  if hasattr(self,'store'):self.store.close()
 def __enter__(self):return self
 def __exit__(self,*args):self.close()
