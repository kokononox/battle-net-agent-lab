"""Import prior-run evidence without promoting it to current reuse authorization.
Not a signature/attestation verifier: raw archive bytes are NOT replayed here.
"""
import hashlib,re
from release_core import need,strict_json,TargetSnapshot
from local_candidates import ObjectSpec

def import_receipt(raw,target,spec,scope):
 need(type(target)is TargetSnapshot and type(spec)is ObjectSpec and type(scope)is dict,'history_types');r=strict_json(raw);need(type(r)is dict,'receipt_object_required');need(scope.get('ckey','').lower()==spec.ckey and scope.get('ekey','').lower()==spec.ekey and scope.get('encoded_size')==spec.encoded_size and scope.get('decoded_size')==spec.decoded_size,'scope_descriptor_conflict')
 expected={'format':'bounded-local-object-proof-1','status':'one_bounded_object_verified','target_fixture_version':target.version,'ekey':spec.ekey,'ckey':spec.ckey,'index_member':scope['index_member'],'archive_member':'data.%03d'%scope['archive_id'],'fixed_offset':scope['offset'],'index_bytes_read':scope['index_bytes'],'archive_bytes_read':spec.encoded_size,'index_content_budget':scope['index_bytes'],'archive_content_budget':spec.encoded_size,'game_files_opened':2,'decoded_bytes':spec.decoded_size}
 for key,value in expected.items():need(type(r.get(key))is type(value) and r[key]==value,'receipt_scope_conflict_'+key)
 for key in ('full_ekey_verified','full_ckey_verified','blte_chunk_checksums_verified'):need(r.get(key)is True,'receipt_verification_missing')
 for key in ('game_modified','decoded_content_exported','active_generation_proven','entire_installation_health_proven','installed_profile_revalidated','automatic_continuation','installation_ready','apply_authorized'):need(r.get(key)is False,'receipt_scope_widened')
 for key in ('network_requests','shmem_bytes_read','lru_bytes_read'):need(type(r.get(key))is int and r[key]==0,'receipt_scope_widened')
 need(r.get('required_download_bytes')is None and type(r.get('blte_chunks'))is int and r['blte_chunks']>0,'receipt_incomplete');need(type(r.get('decoded_sha256'))is str and re.fullmatch('[0-9a-f]{64}',r['decoded_sha256']),'receipt_decoded_sha')
 return {'format':'historical-object-evidence-1','status':'prior_windows_run_report_consistent_with_pinned_probe','target':target.public(),'object':spec.public(),'receipt_sha256':hashlib.sha256(raw).hexdigest(),'source':'user_supplied_windows_probe_report','report_is_cryptographically_signed':False,'raw_archive_payload_independently_replayed_here':False,'observed_read_bytes':{'index':r['index_bytes_read'],'archive':r['archive_bytes_read']},'reported_decoded_sha256':r['decoded_sha256'],'probe_timestamp_available':False,'current_disk_state_proven':False,'active_generation_proven':False,'general_local_backend_qualified':False,'reuse_authorized':False,'additional_read_authorized':False,'additional_download_authorized':False,'apply_authorized':False,'installation_ready':False,'required_download_bytes':None}
