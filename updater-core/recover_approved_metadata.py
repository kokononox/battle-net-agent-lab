"""One user-approved pinned three-metadata recovery. Exclusive persistent ledger.
No retries/redirects/other targets/game assets; any failure stops the scope.
Approval is tied to explicit descriptors and URLs, not just a byte budget.
"""
import json,sys,hashlib
from pathlib import Path
from datetime import datetime,timezone
from release_core import need,TargetSnapshot
from config_binding import bind,ManifestDescriptor
from metadata_objects import MetadataSession,decode_file
P=Path(__file__).resolve().parent
STAGE=Path('/data/metadata-recovery-0.14')
def main():
 need(sys.argv[1:]==['--execute-approved-recovery'],'explicit_execution_flag')
 a=json.loads((P/'APPROVED-METADATA-RECOVERY.json').read_bytes());need(a.get('approved')is True and a.get('executed')is False,'fresh_approved_recovery_required')
 t=TargetSnapshot.restore(a['target']);bound=bind(t,(P/'observed-build.config').read_bytes(),(P/'observed-cdn.config').read_bytes());specs=tuple(ManifestDescriptor(**d)for d in bound['manifest_descriptors']);expected=[]
 for s in specs:
  k=s.ekey;expected.append(dict(s.public(),url=t.origins[0]+'/tpr/wow/data/'+k[:2]+'/'+k[2:4]+'/'+k,max_attempts=1,body_read_ceiling_bytes=s.encoded_size))
 budget=sum(s.encoded_size for s in specs);need(a['requests']==expected and a['max_requests']==3 and a['max_application_body_bytes']==budget and a['automatic_retries']==0 and a['redirects']==0 and a['game_access']is False and a['game_writes']is False and a['installation']is False,'exact_recovery_scope_required')
 STAGE.mkdir(exist_ok=False);(STAGE/'reservations').mkdir()
 with(STAGE/'APPROVAL.json').open('x')as f:json.dump(a,f,indent=2)
 session=MetadataSession(t,specs,budget);proofs=[];report={'format':'approved-pinned-metadata-recovery-1','status':'stopped_safely','target':t.public(),'max_requests':3,'body_ceiling_bytes':budget,'automatic_retries':0,'redirects':0,'game_asset_requests':0,'game_access':False,'game_writes':False,'installation_ready':False,'apply_authorized':False}
 try:
  for item in expected:
   name=item['name'];url=item['url'];spec=session.allowed[url]
   with(STAGE/'reservations'/(name+'.json')).open('x')as f:json.dump(item,f,indent=2)
   print(json.dumps({'receiving_metadata':name,'encoded_bytes':spec.encoded_size}),flush=True)
   transfer=session.fetch(url,STAGE/(name+'.blte'));proof=decode_file(STAGE/(name+'.blte'),STAGE/(name+'.decoded'),spec);proof.update(transfer);proofs.append(proof)
   with(STAGE/(name+'-VERIFIED.json')).open('x')as f:json.dump(proof,f,indent=2)
   print(json.dumps({'verified_metadata':name,'decoded_bytes':proof['decoded_bytes']}),flush=True)
  report.update(status='three_metadata_objects_identity_and_blte_verified',metadata=proofs)
  standard={'format':'approved-dynamic-metadata-receipt-1','status':report['status'],'target':t.public(),'metadata':proofs,'network_requests':len(session.requested),'encoded_metadata_network_bytes':session.used,'approved_encoded_byte_budget':budget,'game_asset_requests':0,'live_game_or_lab_access':False,'installation_ready':False,'apply_authorized':False,'required_game_download_bytes':None,'completed_at_utc':datetime.now(timezone.utc).isoformat()}
  with(STAGE/'METADATA-VERIFIED-to-share.json').open('x')as f:json.dump(standard,f,indent=2)
 except Exception as e:report.update(error_type=type(e).__name__,code=str(e)[:300],verified_metadata_before_stop=proofs)
 finally:
  report.update(network_requests=len(session.requested),application_body_bytes_read=session.used,at_utc=datetime.now(timezone.utc).isoformat())
  with(STAGE/'RECOVERY-to-share.json').open('x')as f:json.dump(report,f,indent=2)
 print(json.dumps({'status':report['status'],'requests':len(session.requested),'body_bytes':session.used}),flush=True)
 return 0 if report['status']=='three_metadata_objects_identity_and_blte_verified'else 2
if __name__=='__main__':sys.exit(main())
