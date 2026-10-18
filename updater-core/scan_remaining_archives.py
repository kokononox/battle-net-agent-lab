"""Sequential, approved metadata-only scan. Stops on first verified route or error.
No retries, redirects, fallback, full archive or game I/O. No implicit payload step.
"""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import json,hashlib,urllib.request,urllib.error,http.client
from datetime import datetime,timezone
from release_core import TargetSnapshot,NoRedirect,need
from cdn_routes import archive_index_plan,locate_in_verified_archive
from cdn_index import parse_cdn_index
from bounded_metadata import metadata_headers,read_metadata,capped_metadata_headers
P=Path(__file__).resolve().parent
S=Path('/data/approved-archive-route-0.11')
def main():
 need(sys.argv[1:]==['--continue-remaining-approved-indices'],'explicit_execution_flag')
 scope=json.loads((P/'NEXT-ARCHIVE-ROUTING-PERMISSION.json').read_bytes());target=TargetSnapshot.restore(scope['target']);plan=archive_index_plan(target,(P/'observed-cdn.config').read_bytes());need([x.public()for x in plan]==scope['index_requests'] and sum(x.expected_size for x in plan)==scope['max_index_body_bytes'],'approved_plan_identity')
 prior=json.loads((S/'SCAN-UNATTEMPTED-to-share.json').read_bytes());need(prior['index_requests_attempted']==2 and prior['index_application_body_bytes_read']==0 and prior['route']is None,'expected_prior_stop');need(json.loads((S/'APPROVAL.json').read_bytes())['approved']is True,'existing_approval')
 log=S/'INDEX-RESULTS.jsonl';total=0;attempts=2;verified=0;status='no_route_in_complete_verified_archive_plan';found=None;error=None
 for n,request in enumerate(plan):
  if n<2:continue
  need(attempts<scope['max_index_requests'],'request_budget');need(total+request.expected_size<=scope['max_index_body_bytes'],'remaining_body_budget')
  with(S/'attempts'/f'{n:04}.json').open('x')as f:json.dump(request.public(),f)
  attempts+=1;rec={'ordinal':n,'archive_key':request.archive_key,'expected_size':request.expected_size,'body_bytes_read':0,'status':'stopped_safely'};raw=None
  try:
   req=urllib.request.Request(request.url,headers={'User-Agent':'WoW-Updater-Approved-Archive-Route/0.11','Accept-Encoding':'identity'})
   with urllib.request.build_opener(NoRedirect).open(req,timeout=30)as r:
    rec['http_status']=r.status;rec['response_metadata']={'final_url':r.geturl(),'content_length':r.headers.get('Content-Length'),'content_range':r.headers.get('Content-Range'),'content_encoding':r.headers.get('Content-Encoding','identity'),'transfer_encoding':r.headers.get('Transfer-Encoding'),'etag':r.headers.get('ETag')};obs,framed_size=capped_metadata_headers(r,request.url,request.expected_size);rec['configured_size_matched']=(framed_size==request.expected_size)
    def account(nbytes):
     nonlocal total
     rec['body_bytes_read']+=nbytes;total+=nbytes
    raw=read_metadata(r,framed_size,account)
   index=parse_cdn_index(raw,request.archive_key,len(raw));need(index.route_kind=='archive','archive_list_requires_archive_index');route=locate_in_verified_archive(index,request,scope['object_ekey'],scope['object_encoded_size']);verified+=1;rec.update(status='index_verified',sha256=index.sha256,records=len(index.entries),pages=index.page_count,matching_records=1 if route else 0)
   with(S/'indices'/(request.archive_key+'.index')).open('xb')as f:f.write(raw)
   if route:found=dict(route,target=target.public(),source_index_ordinal=n);status='one_full_key_size_archive_route_verified'
  except urllib.error.HTTPError as e:rec.update(http_status=e.code,error_type=type(e).__name__,code=str(e));e.close();error=rec;status='stopped_safely'
  except Exception as e:rec.update(error_type=type(e).__name__,code=str(e)[:300]);error=rec;status='stopped_safely'
  with log.open('a')as f:f.write(json.dumps(rec)+'\n')
  if attempts%50==0 or found or error:print(json.dumps({'attempted':attempts,'verified':verified,'body_bytes':total,'status':status if found or error else 'scanning_approved_index_metadata'}),flush=True)
  if found or error:break
 report={'format':'approved-archive-route-scan-1','status':status,'index_requests_attempted':attempts,'indices_verified':verified,'index_application_body_bytes_read':total,'total_planned_indices':len(plan),'approved_index_body_ceiling':scope['max_index_body_bytes'],'route':found,'error':error,'first_two_indices_unverified_and_not_retried':True,'absence_proven':False,'retries':0,'redirects':0,'game_payload_bytes_read':0,'game_access':False,'installation_ready':False,'apply_authorized':False,'at_utc':datetime.now(timezone.utc).isoformat()}
 with(S/'SCAN-REMAINING-to-share.json').open('x')as f:json.dump(report,f,indent=2)
 if found:
  with(S/'VERIFIED-ROUTE.json').open('x')as f:json.dump(found,f,indent=2)
 print(json.dumps({'status':status,'attempts':attempts,'verified':verified,'body_bytes':total,'route_found':bool(found),'error':error}),flush=True)
 return 0 if found else 2
if __name__=='__main__':sys.exit(main())
