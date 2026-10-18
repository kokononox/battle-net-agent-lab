"""Two explicit phases of the already approved 52-byte fixture.
Each phase reserves one request in an exclusive ledger before network. No retry.
Revalidates copied archive index + pinned config/target before either phase.
"""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import json,hashlib
from datetime import datetime,timezone
from release_core import need,RunCheckpoint,Baseline,TargetSnapshot
from cdn_routes import IndexRequest,archive_index_plan
from cdn_index import parse_cdn_index
from local_candidates import ObjectSpec
from archive_transfer import bind_source,ArchiveTransfer,ApprovedArchiveRanges
P=Path(__file__).resolve().parent
ROUTING=Path('/data/approved-unread-index-0.12')
STAGE=Path('/data/approved-archive-object-0.12')

def main():
 need(len(sys.argv)==3 and sys.argv[1]=='--execute-approved-phase' and sys.argv[2]in ('first','second'),'explicit_phase_flag');phase=sys.argv[2]
 approval=json.loads((ROUTING/'APPROVAL.json').read_bytes());need(approval['approved']is True and approval['payload']['encoded_size']==52 and approval['max_additional_payload_range_requests']==2 and approval['max_additional_payload_body_bytes']==52,'payload_approval_scope')
 scan=json.loads((ROUTING/'SCAN-to-share.json').read_bytes());need(scan['status']=='one_full_key_size_archive_route_verified' and scan['route']is not None,'verified_route_required');need(scan['index_requests_attempted']+2<=approval['max_total_requests'] and scan['index_application_body_bytes_read']+52<=approval['max_total_application_body_bytes'],'aggregate_scope_remaining')
 target=TargetSnapshot.restore(approval['target']);route=scan['route'];need(route['target']==target.public(),'route_target_changed');plan=archive_index_plan(target,(P/'observed-cdn.config').read_bytes());item=approval['requests'][route['approved_pass_ordinal']];need(item['previous_attempt_ordinal']==route['source_index_ordinal'],'approved_original_ordinal');request=plan[route['source_index_ordinal']];need(request.archive_key==route['archive_key']==item['archive_key'] and request.url==item['url'],'route_archive_ordinal')
 indexfile=ROUTING/'indices'/(request.archive_key+'.index');need(indexfile.stat().st_size<=item['read_ceiling_bytes'],'index_within_approved_cap');raw=indexfile.read_bytes();index=parse_cdn_index(raw,request.archive_key,len(raw));need(index.sha256==route['index_sha256'],'route_index_sha_changed')
 baseline=Baseline.restore(json.loads((P/'LIVE-RELEASE-OBSERVATION.json').read_bytes())['baseline']);cp=RunCheckpoint(baseline,target);spec=ObjectSpec(approval['payload']['ckey'],approval['payload']['ekey'],approval['payload']['decoded_size'],approval['payload']['encoded_size']);source=bind_source(cp,spec,index,request)
 if phase=='first':
  STAGE.mkdir(exist_ok=False);state=ArchiveTransfer(cp,spec,source);span=(0,25)
  with(STAGE/'PINNED-RUN.json').open('x')as f:json.dump({'checkpoint_sha256':hashlib.sha256(cp.serialize()).hexdigest(),'source':source.public(),'spec':spec.public(),'approval_source':'approved-unread-index-0.12/APPROVAL.json'},f,indent=2)
 else:
  prior=json.loads((STAGE/'first-result.json').read_bytes());need(prior['status']=='partial_checkpoint_saved' and prior['body_bytes_read']==26,'first_phase_complete');state=ArchiveTransfer.restore((STAGE/'partial-checkpoint.json').read_bytes(),cp,spec,source,baseline);need(len(state.partial)==26,'exact_26_byte_partial');span=(26,51)
 with(STAGE/(phase+'-reserved.json')).open('x')as f:json.dump({'relative_range':span,'physical_range':[source.offset+span[0],source.offset+span[1]],'max_body_bytes':26,'retry_allowed':False},f)
 transport=ApprovedArchiveRanges(cp,spec,source,(span,),True);receipt={'format':'approved-archived-object-phase-1','phase':phase,'status':'stopped_safely','relative_range':span,'source':source.public(),'baseline_evidence':'historical_uploaded_metadata_not_live_installation','target':target.public(),'game_access':False,'installation_ready':False,'apply_authorized':False}
 try:
  response=transport.fetch(span,state.etag,state.archive_total);state=state.accept(response,span)
  if phase=='first':
   raw=state.serialize()
   with(STAGE/'partial-checkpoint.json').open('xb')as f:f.write(raw)
   receipt.update(status='partial_checkpoint_saved',partial_bytes=26,checkpoint_sha256=hashlib.sha256(raw).hexdigest())
  else:
   proof=state.verified();need(proof['decoded_sha256']=='ebf6d6702daa7e4953d4a7a9c05bbfa624f9cd7028df93d482707c985d12c1f7','decoded_digest_different_from_prior_fixture')
   with(STAGE/'verified-object.blte').open('xb')as f:f.write(state.partial)
   receipt.update(status='resumed_archived_object_verified',proof=proof,decoded_digest_matches_prior_user_report=True,restored_after_separate_process=True)
 except Exception as e:receipt.update(error_type=type(e).__name__,code=str(e)[:300])
 finally:
  receipt.update(request_attempts=len(transport.attempted),body_bytes_read=transport.body_bytes_read,http_observations=transport.observations,at_utc=datetime.now(timezone.utc).isoformat())
  with(STAGE/(phase+'-result.json')).open('x')as f:json.dump(receipt,f,indent=2)
 print(json.dumps(receipt));return 0 if receipt['status']!='stopped_safely' else 2
if __name__=='__main__':sys.exit(main())
