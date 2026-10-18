"""Capture ONE caller-supplied bounded BLTE stream in a private temporary file.
Locators/generation/control are not authority: only exact target keys + size and
fresh verification of the captured bytes establish content identity. No paths to
source files, discovery, network, archive offsets, CLI, permanent cache or writer.
Scratch directory must already exist and be explicitly caller-owned. Numeric
budgets do NOT authorize reading installed files. File survives only in context.
"""
import tempfile
from release_core import need,TargetSnapshot
from stream_blte import StreamObjectSpec,verify_stream,BLOCK
MAX_CAPTURE=256*1024**2

class _CopyBounded:
 def __init__(self,source,dest,size):self.source=source;self.dest=dest;self.left=size;self.total=0
 def read(self,n):
  need(type(n)is int and 0<n<=BLOCK,'local_capture_read_block')
  # Virtual EOF: never read a sentinel byte outside the explicitly bounded object.
  if not self.left:return b''
  raw=self.source.read(min(n,self.left))
  need(type(raw)is bytes and 0<len(raw)<=min(n,self.left),'local_capture_source_read')
  need(self.dest.write(raw)==len(raw),'local_capture_short_write')
  self.left-=len(raw);self.total+=len(raw);return raw

class LocalContentCapture:
 def __init__(self):self.file=None;self.closed=True
 @classmethod
 def capture(cls,source,*,target,spec,scratch,byte_budget):
  need(type(target)is TargetSnapshot and type(spec)is StreamObjectSpec,'local_capture_typed_target_spec')
  need(type(byte_budget)is int and spec.encoded_size<=byte_budget<=MAX_CAPTURE,'local_capture_explicit_budget')
  obj=cls();obj.target=target;obj.spec=spec
  try:
   obj.file=tempfile.TemporaryFile(mode='w+b',dir=scratch);obj.closed=False
   bounded=_CopyBounded(source,obj.file,spec.encoded_size)
   proof=verify_stream(bounded,spec)
   need(bounded.total==spec.encoded_size and not bounded.left,'local_capture_incomplete')
   obj.file.flush();obj.file.seek(0)
   # Rehash/decode the exact independent copy, NOT the source a second time.
   copied=verify_stream(obj.file,spec)
   need(all(proof[k]==copied[k]for k in ('encoded_sha256','decoded_sha256','encoded_bytes','decoded_bytes','full_ekey_verified','full_ckey_verified')),'local_capture_copy_disagreement')
   obj.encoded_sha256=copied['encoded_sha256'];obj.decoded_sha256=copied['decoded_sha256']
   obj.source_bytes_read=bounded.total
   return obj
  except BaseException:obj.close();raise
 def verify(self):
  need(not self.closed and self.file is not None,'local_capture_closed')
  self.file.seek(0);proof=verify_stream(self.file,self.spec)
  need(proof['encoded_sha256']==self.encoded_sha256 and proof['decoded_sha256']==self.decoded_sha256,'local_capture_copy_changed')
  return dict(proof,format='local-content-independent-capture-1',target=self.target.public(),object=self.spec.public(),
      copied_content_identity_verified=True,source_generation_required_for_content_identity=False,
      source_generation_proven=False,source_store_binding_proven=False,source_quiescence_proven=False,
      source_bytes_read=self.source_bytes_read,temporary_copy_lifetime='until_close_or_context_exit',
      permanent_cache_created=False,source_path_or_locator_exported=False,
      source_read_authorized_by_this_api=False,source_write_access_requested=False,
      game_access=None,network_requests=0,required_set_selected=False,
      required_network_download_bytes=None,installed_content_reuse_authorized=False)
 def close(self):
  if self.file is not None:self.file.close();self.file=None
  self.closed=True
 def __enter__(self):need(not self.closed,'local_capture_closed');return self
 def __exit__(self,*_):self.close()
 def __del__(self):self.close()
