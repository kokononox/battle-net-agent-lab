"""Process-local proof of a cooperating POSIX lock on an owned V8 research root.
Not a permission boundary against hostile Python or noncooperating writers.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import fcntl,os
from pathlib import Path
import patch_audit as a
import source_binding as b
import synthetic_casc_store as fs
_ACTIVE=ContextVar('owned_v8_lock',default=None)
@dataclass(frozen=True)
class _Lease:
 root:Path
 fd:int
 pid:int
 directory_identity:tuple
 lock_identity:tuple
 marker_identity:tuple

def _validate(lease,root):
 root=b.safe(root);fs.no_game_ancestors(root)
 a.require(lease is not None and _ACTIVE.get() is lease and lease.pid==os.getpid() and root==lease.root,'direct_active_owned_lock_required')
 a.require((root.stat().st_dev,root.stat().st_ino)==lease.directory_identity,'direct_locked_root_replaced')
 a.require(tuple(b.fp(b.safe(root/'LOCK',True).stat()))==lease.lock_identity and tuple(b.fp(os.fstat(lease.fd)))==lease.lock_identity,'direct_lock_identity_changed')
 a.require(tuple(b.fp(b.safe(root/'RETAIL-V8-RESEARCH.json',True).stat()))==lease.marker_identity,'direct_marker_identity_changed')
 # Reassert the SAME open-file-description lock, not a second independently opened FD.
 fcntl.flock(lease.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 return lease

@contextmanager
def held(root,file):
 root=b.safe(root);fs.no_game_ancestors(root)
 a.require(_ACTIVE.get() is None,'direct_nested_lock_not_supported')
 marker=b.safe(root/'RETAIL-V8-RESEARCH.json',True);lock=b.safe(root/'LOCK',True)
 a.require(file.fileno()>2 and b.fp(os.fstat(file.fileno()))==b.fp(lock.stat()),'direct_named_lock_descriptor')
 a.require(fcntl.fcntl(file.fileno(),fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDWR,'direct_lock_descriptor_mode')
 fcntl.flock(file.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
 lease=_Lease(root,file.fileno(),os.getpid(),(root.stat().st_dev,root.stat().st_ino),tuple(b.fp(lock.stat())),tuple(b.fp(marker.stat())))
 token=_ACTIVE.set(lease)
 try:
  _validate(lease,root);yield
 finally:_ACTIVE.reset(token)

def require(root):
 lease=_ACTIVE.get();a.require(lease is not None,'direct_active_owned_lock_required')
 return _validate(lease,Path(root))
