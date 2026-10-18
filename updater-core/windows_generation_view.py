"""Explicit-root native Windows read view. No CLI, game discovery or writer.
Keeps all 19 read handles and ancestor handles alive until context exit.
Control references are a published sequence, NOT evidence of client bind/use.
Ordinary sharing locks are not a snapshot or an exclusion of mapped writes.
"""
import datetime
from generation_copy_contract import GenerationCopy,review_copies,MAX_INDEX_BYTES
from copied_control import inspect_copy
from windows_metadata_pair import WindowsMetadataPair

class WindowsGenerationView(WindowsMetadataPair):
 def observe(self):
  try:
   metadata=super().observe()  # two reads each, both streams remain held
   directory=self.root/'Data'/'data'
   self._directory(directory)
   control,n=self._file(directory/'shmem',65536)
   raw=self._read(control,n)
   published=inspect_copy(raw,[])
   names=tuple(r['sequence_filename']for r in published['sequence_observations'])
   # Read exactly the control-referenced names, never maximum filename/discovery.
   pairs={}
   for name in names:
    pairs[name]=self._file(directory/name,MAX_INDEX_BYTES)
   fi,ni=self.streams[0];fc,nc=self.streams[1]
   def copy(control_bytes):
    return GenerationCopy(self._read(fi,ni),self._read(fc,nc),control_bytes,names,
                          {name:self._read(f,size)for name,(f,size)in pairs.items()})
   before=copy(raw)
   after=copy(self._read(control,n))
   result=review_copies(before,after)
   # Last control read brackets all index rereads, rather than merely preceding them.
   final_control=self._read(control,n)
   from release_core import need
   need(final_control==raw,'generation_view_control_changed_after_indexes')
   # A final metadata read brackets the same interval as well.
   need(self._read(fi,ni)==before.info and self._read(fc,nc)==before.config,
        'generation_view_metadata_changed_after_indexes')
   blockers=[b for b in result['blockers']if b not in (
       'held_read_handle_capture_not_implemented_for_control_and_indexes',
       'source_root_and_capture_time_not_bound')]
   blockers += ['native_same_root_path_capture_not_product_store_semantic_binding',
                'all_preexisting_mapping_cases_not_qualified',
                'complete_inventory_not_enumerated']
   result.update(format='native-windows-held-generation-view-1',
      status='held_read_view_structurally_checked_NOT_client_generation_proof',
      source='explicit_root_native_windows_read_handles',
      game_access=None,root_kind_not_inferred=True,filesystem_reads=None,
      files_opened=19,all_read_handles_still_held=True,
      handle_guarantee_lifetime="until_explicit_close_or_context_exit",
      ordinary_write_delete_denied_while_held=True,ancestors_held_deny_delete=True,
      metadata_pair_observed_at_utc=metadata['metadata_pair_observed_at_utc'],
      read_view_rechecked_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
      observed_distinct_content_bytes=ni+nc+n+sum(z for f,z in pairs.values()),
      actual_content_bytes_read=5*(ni+nc)+3*n+2*sum(z for f,z in pairs.values()),
      maximum_content_bytes_read=5*5242880+3*65536+2*16*MAX_INDEX_BYTES,
      inventory_scope='exact_control_references_only_NOT_directory_inventory',
      complete_directory_inventory_observed=False,directory_enumerations=0,
      archive_bytes_read=0,lru_bytes_read=0,write_access_requested=False,
      published_control_references_checked=True,client_successful_bind_proven=False,
      native_handle_capture_implemented=True,store_semantic_binding_proven=False,
      fresh_installed_preferences_proven=False,blockers=blockers)
   return result
  except BaseException:
   self.close();raise
