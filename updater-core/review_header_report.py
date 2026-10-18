"""Historical fixture review, not a generic installation attestation.
Reads only the supplied report and ONE copied index; never LRU/archive/network.
"""
import hashlib,json,zipfile,argparse
from pathlib import Path
from local_candidates import parse_v7
from release_core import need
EKEY='2bf8296553eb812b17ced6e1b07036d3'
CKEY='752c5f5f275a8044c478a6cf41fee61a'
INDEX_SHA='243936f9daa64ab4e54d995e1bf8a738c264a69917b99530afc8a00ce7379313'
def review(report_bytes,index):
 need(type(report_bytes)is bytes and len(report_bytes)<=16384,'report_budget');r=json.loads(report_bytes)
 fixed={'format':'bounded-archive-header-diagnostic-3','status':'header_layout_observed_object_verified','stage':'complete','target_fixture_version':'12.1.5.70448','ekey':EKEY,'ckey':CKEY,'index_member':'03000000c3.idx','archive_member':'data.021','fixed_offset':1073741722,'index_bytes_read':3014656,'archive_bytes_read':82,'index_content_budget':3014656,'archive_content_budget':82,'game_files_opened':2,'network_requests':0,'shmem_bytes_read':0,'lru_bytes_read':0,'decoded_bytes':64,'blte_chunks':1}
 for k,v in fixed.items():need(type(r.get(k))is type(v) and r[k]==v,'report_scope_'+k)
 for k in ('full_ekey_verified','full_ckey_verified','payload_verification_attempted','blte_magic_at_fixed_plus_30','blte_chunk_checksums_verified','raw_archive_header_exported'):need(r.get(k)is True,'report_positive_'+k)
 for k in ('game_modified','decoded_content_exported','active_generation_proven','entire_installation_health_proven','installed_profile_revalidated','automatic_continuation','installation_ready','apply_authorized','raw_blte_payload_exported'):need(r.get(k)is False,'report_boundary_'+k)
 need(r.get('required_download_bytes')is None,'report_required_size_unknown');h=r['header_observation'];need(h.get('header_bytes')==30 and h.get('header_hex_30')==bytes(30).hex() and h.get('header_sha256')==hashlib.sha256(bytes(30)).hexdigest() and h.get('research_profile_all_checks_match')is False,'zero_prefix_observation')
 need(r.get('decoded_sha256')=='ebf6d6702daa7e4953d4a7a9c05bbfa624f9cd7028df93d482707c985d12c1f7','decoded_digest_scope')
 refs,proof=parse_v7(index,'03000000c3.idx');need(proof['sha256']==INDEX_SHA,'pinned_copied_index');p,d=refs[28749:28751];need(p.prefix==d.prefix==bytes.fromhex(EKEY)[:9] and p.archive_id==d.archive_id==21 and p.offset==1073741722 and d.offset==1073741752 and p.span==82 and d.span==52,'actual_paired_reference_geometry')
 return {'format':'historical-zero-prefix-review-1','status':'user_receipt_and_copied_pair_consistent','report_sha256':hashlib.sha256(report_bytes).hexdigest(),'copied_index':proof,'pair_ordinals':[28749,28750],'zero_prefix_independently_checked_from_export':True,'full_payload_identity_user_reported':True,'raw_payload_independently_replayed_here':False,'report_cryptographically_signed':False,'native_header_validity_proven':False,'fresh_live_state_proven':False,'reuse_authorized':False,'installation_ready':False,'apply_authorized':False,'network_requests':0,'archive_payload_bytes_read_here':0,'lru_bytes_read_here':0}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--report',required=True);p.add_argument('--index-zip',required=True);p.add_argument('--output',required=True);a=p.parse_args()
 with zipfile.ZipFile(a.index_zip) as z:
  matches=[x for x in z.infolist() if x.filename.replace('\\','/').split('/')[-1]=='03000000c3.idx'];need(len(matches)==1 and matches[0].file_size==3014656,'one_bounded_copied_index');index=z.read(matches[0])
 out=review(Path(a.report).read_bytes(),index);Path(a.output).write_text(json.dumps(out,indent=2)+'\n');print(out['status'])
