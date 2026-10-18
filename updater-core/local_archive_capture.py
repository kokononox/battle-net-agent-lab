"""ONE explicit archive span -> independent target-verified temporary capture.
No scan, alternate locator, index/control reads, network, source writes or CLI.
Two explicit layouts only; prefix30 remains a pinned Agent9824 research profile.
Numbers are parser bounds, NOT permission to read any installed file.
"""
from dataclasses import dataclass
from release_core import need,TargetSnapshot
from stream_blte import StreamObjectSpec,BLOCK
from local_content_capture import LocalContentCapture,MAX_CAPTURE
from local_spans import span_checksum_b
from lookup3 import hashlittle2

@dataclass(frozen=True)
class ArchiveReadRequest:
 target:TargetSnapshot
 spec:StreamObjectSpec
 archive_id:int
 offset:int
 layout:str
 byte_budget:int
 def __post_init__(self):
  need(type(self.target)is TargetSnapshot and type(self.spec)is StreamObjectSpec,'archive_request_target_spec')
  need(type(self.archive_id)is int and 0<=self.archive_id<=999,'archive_request_id')
  need(type(self.offset)is int and 0<=self.offset<1<<30,'archive_request_offset')
  need(self.layout in ('direct-blte','prefix30-agent9824'),'archive_request_layout')
  need(self.spec.encoded_size<=MAX_CAPTURE,'archive_capture_payload_budget')
  need(type(self.byte_budget)is int and self.byte_budget==self.span,'archive_request_exact_budget')
  need(self.offset+self.span<=1<<30,'archive_request_segment_boundary')
 @property
 def header_bytes(self):return 30 if self.layout=='prefix30-agent9824'else 0
 @property
 def span(self):return self.header_bytes+self.spec.encoded_size

class _Window:
 def __init__(self,stream,request):
  self.stream=stream;self.left=request.span;self.total=0
  need(stream.seek(request.offset)==request.offset,'archive_seek_position')
 def read(self,n):
  need(type(n)is int and 0<n<=BLOCK,'archive_read_block')
  if not self.left:return b''
  wanted=min(n,self.left);raw=self.stream.read(wanted)
  need(type(raw)is bytes and 0<len(raw)<=wanted,'archive_truncated_or_oversized_read')
  self.left-=len(raw);self.total+=len(raw);return raw

def _header(raw,request):
 need(len(raw)==30,'archive_header_truncated')
 need(raw[:16]==bytes.fromhex(request.spec.ekey)[::-1]and int.from_bytes(raw[16:20],'little')==request.span,'archive_header_key_or_size')
 need(raw[20:22]==bytes(2),'archive_header_flags')
 need(int.from_bytes(raw[22:26],'little')==hashlittle2(raw[:22],0x3D6BE971)[0],'archive_header_checksum_a')
 need(raw[26:30]==span_checksum_b(raw[:26],request.archive_id,request.offset),'archive_header_checksum_b')

def capture_archive_stream(stream,*,archive_size,request,scratch):
 """Caller supplies an owned/authorized UNBUFFERED seekable stream and size.
 Portable tests use memory streams. Native adapter below supplies raw FileIO.
 This function does not infer, inspect or authorize a source filesystem path.
 """
 need(type(request)is ArchiveReadRequest,'archive_typed_request')
 need(type(archive_size)is int and 0<archive_size<=1<<30 and request.offset+request.span<=archive_size,'archive_reported_bounds')
 window=_Window(stream,request);capture=None
 try:
  if request.header_bytes:
   parts=[];left=30
   while left:
    raw=window.read(left);parts.append(raw);left-=len(raw)
   _header(b''.join(parts),request)
  capture=LocalContentCapture.capture(window,target=request.target,spec=request.spec,scratch=scratch,byte_budget=request.spec.encoded_size)
  need(window.total==request.byte_budget and not window.left,'archive_content_budget_disagreement')
  report=dict(format='bounded-archive-independent-capture-1',status='one_explicit_span_captured_and_target_content_verified',
    object=request.spec.public(),target=request.target.public(),layout=request.layout,
    archive_application_content_bytes_read=window.total,maximum_archive_application_content_bytes=request.byte_budget,
    header_bytes_read=request.header_bytes,header_checksums_verified=bool(request.header_bytes),
    header_profile='pinned_agent9824_research_profile'if request.header_bytes else'not_present_explicit_direct_layout',
    source_stream_bytes_outside_requested_span=0,source_read_accounting_scope='application_reads_NOT_disk_sector_prefetch',
    source_paths_exported=False,raw_header_exported=False,source_location_exported=False,
    automatic_fallback_used=False,control_bytes_read=0,index_bytes_read=0,lru_bytes_read=0,shmem_bytes_read=0,
    source_generation_proven=False,source_store_binding_proven=False,source_read_approval_implied=False,
    required_set_selected=False,installed_content_reuse_authorized=False,required_network_download_bytes=None,
    network_requests=0,game_access=None,installation_ready=False,apply_authorized=False)
  return capture,report
 except BaseException:
  if capture is not None:capture.close()
  raise
