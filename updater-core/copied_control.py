"""Bounded read-only observer for explicit copied Agent-9824 control bytes.
Research profile, NOT a universal CASC specification or live-store activation.
No path, registry, mmap, native Agent, network, filesystem or mutation operations.
"""
import hashlib,re,struct
from release_core import need
PATTERN=re.compile('[0-9a-f]{10}\\.idx')
SOURCE='https://github.com/kokononox/battle-net-agent-lab/blob/7916903f5378f72a28f745fd30fe3ae11670451a/downloader/patch_audit_lab/shmem_readonly.py'
def inspect_copy(raw,index_names):
 need(type(raw)is bytes and 0x150<=len(raw)<=65536,'copied_control_size');need(type(index_names)is list and len(index_names)<=512 and all(type(n)is str and PATTERN.fullmatch(n) and int(n[:2],16)<16 for n in index_names),'index_name_inventory');need(len(index_names)==len(set(index_names)),'duplicate_index_inventory')
 version,header=struct.unpack_from('<II',raw);need(version in (4,5),'unsupported_control_protocol');size,offset=struct.unpack_from('<II',raw,0x108);need(size==0x2ab8 and header==(0x150 if version==4 else 0x154) and offset==(0x150 if version==4 else 0x1000),'unsupported_control_geometry');need(header<=offset and offset+size<=len(raw),'control_truncated');name=raw[8:0x108];need(name.startswith(b'Global\\') and b'\0' in name,'unsupported_name_shape')
 flags=None;bitmap=None;extensions=[]
 if version==5:
  flags=struct.unpack_from('<I',raw,0x150)[0];need(flags&~3==0,'unsupported_control_flags')
  if flags&2:
   need(len(raw)>=0x258,'extension_header_truncated');bitmap=struct.unpack_from('<I',raw,0x154)[0];need(bitmap&~1==0,'unsupported_extension_slot')
   if bitmap&1:
    length=struct.unpack_from('<I',raw,0x158)[0];pos=struct.unpack_from('<I',raw,0x1d8)[0];need(length==0x228 and pos==0x4000 and pos+length<=len(raw),'unsupported_extension_geometry');state=struct.unpack_from('<I',raw,pos)[0];extensions.append({'slot':0,'bytes':length,'recognized_diagnostic_state':state in (1,2),'raw_contents_exported':False,'full_semantics_proven':False})
 stop=offset+size if not extensions else 0x4000+0x228;expected=(stop+15)&~15 if version==4 else (stop+4095)&~4095;need(len(raw)==expected,'copied_control_file_geometry_mismatch')
 state,count,index,opaque=struct.unpack_from('<4I',raw,offset);need(state in (0,1,2) and count<=0x442,'unsupported_primary_state_or_count');pending=state==2
 if pending:
  need(index<count,'pending_index_outside_count');saved_b,saved_a=struct.unpack_from('<QQ',raw,offset+0x10);need(saved_a<1<<40 and saved_b<1<<40,'saved_value_outside_profile')
 rows=[]
 for bucket,seq in enumerate(struct.unpack_from('<16I',raw,0x110)):
  filename=f'{bucket:02x}{seq:08x}.idx';versions=[int(n[2:10],16) for n in index_names if int(n[:2],16)==bucket];rows.append({'bucket':bucket,'sequence':seq,'sequence_filename':filename,'file_in_uploaded_inventory':filename in index_names,'inventory_has_newer_sequence':any(v>seq for v in versions)})
 match=sum(x['file_in_uploaded_inventory'] for x in rows)
 return {'format':'copied-control-sequence-review-1','status':'copied_control_geometry_and_index_inventory_consistent' if match==16 else 'copied_inventory_mismatch_UNKNOWN_not_corruption','protocol':version,'sha256':hashlib.sha256(raw).hexdigest(),'copied_member_bytes':len(raw),'declared_header_bytes':header,'payload_offset':offset,'payload_bytes':size,'v5_flags_profile_value':flags,'extension_bitmap_profile_value':bitmap,'extension_observations':extensions,'primary_observation':{'research_state':state,'state_label':{0:'reset_or_rebuild_observed_NOT_diagnosis',1:'state_one_observed_NOT_health_proof',2:'rollback_pending_observed_do_not_activate'}[state],'record_count_opaque_allocation_semantics':count,'record_count_is_NOT_archive_count':True,'rollback_pending_observed':pending,'arrays_or_saved_values_exported':False},'matched_buckets':match,'expected_buckets':16,'sequence_observations':rows,'name_field_exported':False,'name_source_binding_proven':False,'live_game_access':False,'live_generation_proven':False,'coherent_live_snapshot_proven':False,'requires_repair_proven':False,'required_download_bytes':None,'installation_ready':False,'apply_authorized':False,'source_reference':SOURCE}
