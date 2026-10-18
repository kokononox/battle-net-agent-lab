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
P=Path(__file__).resolve().parent
S=Path('/data/approved-archive-route-0.11')
def main():
 need(sys.argv[1:]==['--execute-user-approved-scope'],'explicit_execution_flag')
 scope=json.loads((P/'NEXT-ARCHIVE-ROUTING-PERMISSION.json').read_bytes());target=TargetSnapshot.restore(scope['target']);plan=archive_index_plan(target,(P/'observed-cdn.config').read_bytes());need([x.public()for x in plan]==scope['index_requests'] and sum(x.expected_size for x in plan)==scope['max_index_body_bytes'],'approved_plan_identity');S.mkdir(exist_ok=False);(S/'indices').mkdir();(S/'attempts').mkdir()
 with(S/'APPROVAL.json').open('x')as f:json.dump(dict(scope,approved=True,user_confirmation='بله'),f,indent=2)
 log=S/'INDEX-RESULTS.jsonl';total=0;attempts=0;verified=0;status='no_route_in_complete_verified_archive_plan';found=None;error=None
 for n,request in enumerate(plan):
  need(attempts<scope['max_index_requests'],'request_budget');need(total+request.expected_size<=scope['max_index_body_bytes'],'remaining_body_budget')
  with(S/'attempts'/f'{n:04}.json').open('x')as f:json.dump(request.public(),f)
  attempts+=1;rec={'ordinal':n,'archive_key':request.archive_key,'expected_size':request.expected_size,'body_bytes_read':0,'status':'stopped_safely'};raw=None
  try:
   req=urllib.request.Request(request.url,headers={'User-Agent':'WoW-Updater-Approved-Archive-Route/0.11','Accept-Encoding':'identity'})
   with urllib.request.build_opener(NoRedirect).open(req,timeout=30)as r:
    rec['http_status']=r.status;rec['etag']=r.headers.get('ETag');length=r.headers.get('Content-Length')
    need(r.status==200 and r.geturl()==request.url and not r.headers.get('Content-Range')and r.headers.get('Content-Encoding','identity').lower()in ('','identity')and length==str(request.expected_size),'index_response_rejected_before_body')
    parts=[];remaining=request.expected_size
    while remaining:
     try:block=r.read(min(65536,remaining))
     except http.client.IncompleteRead as e:
      rec['body_bytes_read']+=len(e.partial);total+=len(e.partial);raise
     need(type(block)is bytes and 0<len(block)<=remaining,'index_truncated');remaining-=len(block);rec['body_bytes_read']+=len(block);total+=len(block);parts.append(block)
    raw=b''.join(parts)
   index=parse_cdn_index(raw,request.archive_key,request.expected_size);need(index.route_kind=='archive','archive_list_requires_archive_index');route=locate_in_verified_archive(index,request,scope['object_ekey'],scope['object_encoded_size']);verified+=1;rec.update(status='index_verified',sha256=index.sha256,records=len(index.entries),pages=index.page_count,matching_records=1 if route else 0)
   with(S/'indices'/(request.archive_key+'.index')).open('xb')as f:f.write(raw)
   if route:found=dict(route,target=target.public(),source_index_ordinal=n);status='one_full_key_size_archive_route_verified'
  except urllib.error.HTTPError as e:rec.update(http_status=e.code,error_type=type(e).__name__,code=str(e));e.close();error=rec;status='stopped_safely'
  except Exception as e:rec.update(error_type=type(e).__name__,code=str(e)[:300]);error=rec;status='stopped_safely'
  with log.open('a')as f:f.write(json.dumps(rec)+'\n')
  if attempts%50==0 or found or error:print(json.dumps({'attempted':attempts,'verified':verified,'body_bytes':total,'status':status if found or error else 'scanning_approved_index_metadata'}),flush=True)
  if found or error:break
 report={'format':'approved-archive-route-scan-1','status':status,'index_requests_attempted':attempts,'indices_verified':verified,'index_application_body_bytes_read':total,'total_planned_indices':len(plan),'approved_index_body_ceiling':scope['max_index_body_bytes'],'route':found,'error':error,'remaining_indices_requested':False,'retries':0,'redirects':0,'game_payload_bytes_read':0,'game_access':False,'installation_ready':False,'apply_authorized':False,'at_utc':datetime.now(timezone.utc).isoformat()}
 with(S/'SCAN-to-share.json').open('x')as f:json.dump(report,f,indent=2)
 if found:
  with(S/'VERIFIED-ROUTE.json').open('x')as f:json.dump(found,f,indent=2)
 print(json.dumps({'status':status,'attempts':attempts,'verified':verified,'body_bytes':total,'route_found':bool(found),'error':error}),flush=True)
 return 0 if found else 2
if __name__=='__main__':sys.exit(main())
