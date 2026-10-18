"""Explicitly approved 52-byte historical fixture only; no implicit retries.
Two separate invocations; each durably reserves one request before network.
Not a production journal or source of permission for other objects.
"""
import argparse,hashlib,json,sys,urllib.request
from pathlib import Path
from datetime import datetime,timezone
from release_core import Baseline,Scope,TargetSnapshot,RunCheckpoint,need
from local_candidates import ObjectSpec
from range_resume import ObjectTransfer,ApprovedRanges
P=Path(__file__).parent

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--stage',required=True);ap.add_argument('--phase',choices=['first','second'],required=True);ap.add_argument('--approved-52-byte-fixture',action='store_true');a=ap.parse_args();need(a.approved_52_byte_fixture,'explicit_approval_required')
 stage=Path(a.stage);need(stage.is_absolute(),'owned_absolute_stage')
 if a.phase=='first':stage.mkdir(exist_ok=False)
 need(stage.is_dir(),'stage_exists')
 b=json.loads(Path('/data/baseline-review/BASELINE-to-share.json').read_bytes());base=Baseline(Scope(),b['installed_version_from_uploaded_metadata'],b['installed_build_config_md5'],b['build_info_sha256'],b['build_config_sha256']);target=TargetSnapshot.restore(json.loads((P/'reports/CATALOGUE-VERIFIED-to-share.json').read_bytes())['target']);cp=RunCheckpoint(base,target);spec=ObjectSpec('752c5f5f275a8044c478a6cf41fee61a','2bf8296553eb812b17ced6e1b07036d3',64,52)
 if a.phase=='first':state=ObjectTransfer(cp,spec);span=(0,25)
 else:
  prior=json.loads((stage/'first-result.json').read_bytes());need(prior['status']=='partial_checkpoint_saved','first_phase_complete');state=ObjectTransfer.restore((stage/'partial-checkpoint.json').read_bytes(),cp,spec,base);need(len(state.partial)==26,'exact_partial');span=(26,51)
 # Exclusive reservation prevents repeating this phase after errors/interruption.
 with (stage/(a.phase+'-attempt.json')).open('x') as f:json.dump({'phase':a.phase,'span':span,'request_reserved':True,'retry_authorized':False,'at_utc':datetime.now(timezone.utc).isoformat()},f)
 transport=ApprovedRanges(cp,spec,(span,),True);receipt={'format':'approved-range-fixture-phase-1','phase':a.phase,'range':span,'status':'stopped_safely','application_body_bytes_read':0,'game_reads':0,'game_writes':0,'installation_ready':False,'apply_authorized':False,'baseline_source':'historical_uploaded_metadata_not_fresh_live','target_fixture_version':target.version}
 # Observe response metadata without issuing any additional request.
 original=urllib.request.build_opener
 class ObservedOpener:
  def __init__(self,*handlers):self.inner=original(*handlers)
  def open(self,*args,**kwargs):
   r=self.inner.open(*args,**kwargs);receipt['http']={'status':r.status,'url':r.geturl(),'content_range':r.headers.get('Content-Range'),'content_length':r.headers.get('Content-Length'),'etag':r.headers.get('ETag'),'content_encoding':r.headers.get('Content-Encoding','identity')};return r
 urllib.request.build_opener=ObservedOpener
 try:
  result=transport.fetch(span,state.etag);state=state.accept(result,span)
  if a.phase=='first':
   raw=state.serialize()
   with (stage/'partial-checkpoint.json').open('xb') as f:f.write(raw)
   receipt.update(status='partial_checkpoint_saved',checkpoint_sha256=hashlib.sha256(raw).hexdigest(),partial_bytes=26)
  else:
   proof=state.verified();receipt.update(status='resumed_object_verified',proof=proof,decoded_matches_prior_user_report=proof.get('decoded_sha256')=='ebf6d6702daa7e4953d4a7a9c05bbfa624f9cd7028df93d482707c985d12c1f7')
   with (stage/'verified-object.blte').open('xb') as f:f.write(state.partial)
 except Exception as e:receipt.update(error_type=type(e).__name__,error=str(e)[:300])
 finally:
  urllib.request.build_opener=original;receipt['application_body_bytes_read']=transport.body_bytes_read;receipt['request_attempts']=len(transport.attempted);receipt['completed_at_utc']=datetime.now(timezone.utc).isoformat()
  with (stage/(a.phase+'-result.json')).open('x') as f:json.dump(receipt,f,indent=2)
 print(json.dumps(receipt,ensure_ascii=False));return 0 if receipt['status']!='stopped_safely' else 2
if __name__=='__main__':sys.exit(main())
