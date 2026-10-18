"""Pure bounded consistency contract for TWO caller-supplied copied rounds.
No file IO, path discovery, native handles, locks, retries, network or writer.
A stable byte bundle is NOT a coherent live snapshot or active-generation proof.
The existing V4/V5 and V7/V8 readers remain research profiles, not vendor truth.
"""
from dataclasses import dataclass
import hashlib,json,struct
from release_core import need
from installed_preferences import inspect_preferences
from copied_control import inspect_copy
from local_candidates import parse_v7
from local_v8_readonly import primary_records

MAX_INDEX_BYTES=4*1024**2
MAX_ROUND_BYTES=16*MAX_INDEX_BYTES+1048576+4194304+65536
@dataclass(frozen=True)
class GenerationCopy:
 info:bytes
 config:bytes
 control:bytes
 inventory:tuple
 indexes:dict

def digest(raw):return hashlib.sha256(raw).hexdigest()

def _shape(c):
 need(type(c)is GenerationCopy,'generation_copy_type')
 for name,cap in (('info',1048576),('config',4194304),('control',65536)):
  raw=getattr(c,name);need(type(raw)is bytes and 0<len(raw)<=cap,'generation_copy_metadata_budget')
 need(type(c.inventory)is tuple and 16<=len(c.inventory)<=512,'generation_copy_inventory_budget')
 need(type(c.indexes)is dict and len(c.indexes)==16,'generation_copy_index_count')
 need(all(type(k)is str and type(v)is bytes and 40<=len(v)<=MAX_INDEX_BYTES for k,v in c.indexes.items()),'generation_copy_index_shape')
 total=len(c.info)+len(c.config)+len(c.control)+sum(map(len,c.indexes.values()))
 need(total<=MAX_ROUND_BYTES,'generation_copy_total_budget')
 # Source geometry/name validation is delegated to the bounded research reader.
 control=inspect_copy(c.control,list(c.inventory))
 names={row['sequence_filename']for row in control['sequence_observations']}
 need(control['matched_buckets']==16,'generation_copy_referenced_index_missing')
 need(set(c.indexes)==names,'generation_copy_index_set_not_control_referenced')
 return total,control

def review_copies(before,after):
 total,control=_shape(before);total2,other=_shape(after)
 need(before.info==after.info and before.config==after.config,'generation_copy_baseline_changed')
 need(before.control==after.control,'generation_copy_control_changed')
 need(set(before.inventory)==set(after.inventory),'generation_copy_inventory_changed')
 need(before.indexes==after.indexes,'generation_copy_index_bytes_changed')
 facts=inspect_preferences(before.info,before.config)
 state=control['primary_observation']['research_state']
 # No recovery/reset interpretation: these states stop this consistency contract.
 need(state==1,'generation_copy_nonquiescent_research_state')
 rows=[];families=set()
 for row in control['sequence_observations']:
  name=row['sequence_filename'];raw=before.indexes[name];version=struct.unpack_from('<H',raw,8)[0];bucket=row['bucket']
  if version==7:
   records,proof=parse_v7(raw,name);count=len(records);opaque=False
  elif version==8:
   records,proof=primary_records(raw,bucket);count=len(records);opaque=True
  else:need(False,'generation_copy_unknown_index_format')
  families.add(version)
  rows.append({'bucket':bucket,'sequence':row['sequence'],'member':name,'bytes':len(raw),'sha256':digest(raw),'index_format':version,'primary_records':count,'structural_checksums_verified':True,'v8_location_qwords_remain_opaque':opaque,'newer_inventory_member_ignored':row['inventory_has_newer_sequence']})
 need(len(families)==1,'generation_copy_mixed_index_families_unqualified')
 identities={'info_sha256':digest(before.info),'config_sha256':digest(before.config),'control_sha256':digest(before.control),'inventory':sorted(before.inventory),'indexes':[{'member':r['member'],'sha256':r['sha256'],'bytes':r['bytes']}for r in rows]}
 bundle=digest(json.dumps(identities,sort_keys=True,separators=(',',':')).encode())
 blockers=['research_control_and_generation_semantics_not_independently_qualified','source_root_and_capture_time_not_bound','sequential_equal_bytes_not_atomic_snapshot_or_ABA_protection','control_name_to_store_binding_not_proven','index_to_build_or_profile_binding_not_proven','held_read_handle_capture_not_implemented_for_control_and_indexes','actual_game_or_launcher_use_not_observed']
 if control['extension_observations']:blockers.append('control_extension_semantics_unqualified')
 if 8 in families:blockers.append('v8_archive_location_fields_opaque')
 return {'format':'two-round-generation-copy-contract-1','status':'stable_copied_bundle_structurally_checked_NOT_active_generation_proof','scope':'caller_supplied_owned_copied_bytes_only','bundle_sha256':bundle,'baseline':facts['baseline'],'profile':facts['profile'],'control_profile':{'protocol':control['protocol'],'bytes':len(before.control),'sha256':digest(before.control),'research_state':state,'matched_buckets':16,'extension_semantics_qualified':False,'name_field_exported':False,'source_binding_proven':False},'index_observations':rows,'selected_index_files':16,'index_family':next(iter(families)),'newer_filename_fallback_used':False,'both_rounds_bytes_equal':True,'per_round_content_bytes':total,'two_round_content_bytes':total+total2,'maximum_per_round_content_bytes':MAX_ROUND_BYTES,'input_round_order_or_capture_times_verified':False,'no_change_between_rounds_proven':False,'live_capture_scope_approved':False,'additional_file_read_authorized':False,'copied_bundle_consistency_checked':True,'fresh_installed_preferences_proven':False,'active_generation_proven':False,'coherent_live_snapshot_proven':False,'local_reuse_authorized':False,'required_set_selected':False,'required_network_download_bytes':None,'blockers':blockers,'native_agent_executed':False,'filesystem_reads':0,'filesystem_writes':0,'network_requests':0,'game_access':False,'installation_ready':False,'apply_authorized':False}
