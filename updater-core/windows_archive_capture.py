"""Native Windows one-archive reader library, no CLI or installation discovery.
Explicit-root handles pin ancestors, deny ordinary source write/delete and reject
reparse/offline/recall/nonregular/hardlinked files. No universal snapshot claim.
Actual tests use newly created owned synthetic trees, never installed games.
"""
import io
from release_core import need
from windows_metadata_pair import WindowsMetadataPair
from local_archive_capture import ArchiveReadRequest,capture_archive_stream

class WindowsArchiveCapture(WindowsMetadataPair):
 def observe(self):need(False,'archive_use_capture_not_metadata_observe')
 def capture(self,request,*,scratch):
  result=None
  try:
   need(type(request)is ArchiveReadRequest,'archive_typed_request')
   need(not self.closed and not self.streams,'archive_capture_single_use')
   data=self.root/'Data';self._directory(data);data=data/'data';self._directory(data)
   buffered,size=self._file(data/f'data.{request.archive_id:03d}',1<<30)
   # Do NOT call BufferedReader.read: it may prefetch beyond a tiny approved span.
   # The wrapper owns this same fd but has never read; raw FileIO is unbuffered.
   raw=buffered.raw;need(type(raw)is io.FileIO,'archive_unbuffered_native_file_required')
   result,report=capture_archive_stream(raw,archive_size=size,request=request,scratch=scratch)
   report.update(source='native_windows_one_explicit_archive',source_files_opened=1,
      unbuffered_source_reads=True,ordinary_write_delete_denied_while_held=True,
      ancestors_held_deny_delete=True,source_handle_lifetime='until_close_or_context_exit',
      independent_copy_outlives_source_handle=True,directory_enumerations=0,
      build_info_bytes_read=0,build_config_bytes_read=0,source_write_access_requested=False,
      universal_mapped_writer_exclusion_qualified=False,live_archive_backend_qualified=False)
   return result,report
  except BaseException:
   if result is not None:result.close()
   self.close();raise
