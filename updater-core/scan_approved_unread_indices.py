"""One newly approved attempt per formerly-unread index URL, explicit read caps.
Stop at first full-key/size route. No retry, redirect, implicit payload or game I/O.
"""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import json,urllib.request,urllib.error
from datetime import datetime,timezone
from release_core import TargetSnapshot,NoRedirect,need
from cdn_routes import archive_index_plan,locate_in_verified_archive
from cdn_index import parse_cdn_index
from bounded_metadata import pinned_index_headers,read_metadata
P=Path(__file__).resolve().parent
S=Path('/data/approved-unread-index-0.12')
def main():
 need(sys.argv[1:]==['--execute-new-user-approved-scope'],'explicit_execution_flag')
 approval=json.loads((P/'NEXT-UNREAD-INDEX-PERMISSION.json').read_bytes());need(approval.get('approved')is True and approval.get('executed')is False and not approval.get('scope_closed',False),'fresh_unconsumed_explicit_approval_required');target=TargetSnapshot.restore(approval['target']);plan=archive_index_plan(target,(P/'observed-cdn.config').read_bytes());items=approval['requests'];need(len(items)==approval['max_index_requests']==694 and len(set(x['url']for x in items))==len(items) and sum(x['read_ceiling_bytes']for x in items)==approval['max_index_body_bytes'],'approved_scope_geometry')
 for item in items:
  r=plan[item['previous_attempt_ordinal']];need((r.archive_key,r.url)==(item['archive_key'],item['url']) and item['previous_body_bytes_read']==0,'approved_scope_membership')
 S.mkdir(exist_ok=False);(S/'indices').mkdir();(S/'attempts').mkdir()
 with(S/'APPROVAL.json').open('x')as f:json.dump(dict(approval,approved=True,user_confirmation='بله'),f,indent=2)
 total=0;attempts=0;verified=0;skipped=0;found=None;last_error=None
 for n,item in enumerate(items):
  request=plan[item['previous_attempt_ordinal']];cap=item['read_ceiling_bytes'];need(attempts<approval['max_index_requests'] and total+cap<=approval['max_index_body_bytes'],'approved_metadata_budget')
  with(S/'attempts'/f'{n:04}.json').open('x')as f:json.dump(item,f)
  attempts+=1;rec={'ordinal':n,'previous_attempt_ordinal':item['previous_attempt_ordinal'],'archive_key':request.archive_key,'read_ceiling_bytes':cap,'body_bytes_read':0,'status':'stopped_safely'}
  try:
   req=urllib.request.Request(request.url,headers={'User-Agent':'WoW-Updater-Approved-Unread-Index/0.12','Accept-Encoding':'identity'})
   with urllib.request.build_opener(NoRedirect).open(req,timeout=30)as response:
    h=response.headers;rec['response_metadata']={'status':response.status,'final_url':response.geturl(),'content_length':h.get('Content-Length'),'content_range':h.get('Content-Range'),'content_encoding':h.get('Content-Encoding','identity'),'etag':h.get('ETag')};_,size=pinned_index_headers(response,request.url,cap,approval['max_index_body_bytes']-total)
    def account(count):
     nonlocal total
     rec['body_bytes_read']+=count;total+=count
    raw=read_metadata(response,size,account)
   index=parse_cdn_index(raw,request.archive_key,len(raw));need(index.route_kind=='archive','archive_profile_required');route=locate_in_verified_archive(index,request,approval['payload']['ekey'],approval['payload']['encoded_size']);verified+=1;rec.update(status='index_verified',sha256=index.sha256,records=len(index.entries),pages=index.page_count,matching_records=1 if route else 0)
   with(S/'indices'/(request.archive_key+'.index')).open('xb')as f:f.write(raw)
   if route:found=dict(route,target=target.public(),source_index_ordinal=item['previous_attempt_ordinal'],approved_pass_ordinal=n)
  except urllib.error.HTTPError as e:rec.update(http_status=e.code,error_type=type(e).__name__,code=str(e));e.close();skipped+=1;last_error=rec
  except Exception as e:rec.update(error_type=type(e).__name__,code=str(e)[:300]);skipped+=1;last_error=rec
  with(S/'INDEX-RESULTS.jsonl').open('a')as f:f.write(json.dumps(rec)+'\n')
  if attempts%50==0 or found:print(json.dumps({'attempted':attempts,'verified':verified,'body_bytes':total,'skipped':skipped,'route_found':bool(found)}),flush=True)
  if found:break
 report={'format':'approved-unread-index-scan-1','status':'one_full_key_size_archive_route_verified' if found else 'route_unresolved','index_requests_attempted':attempts,'indices_verified':verified,'skipped_indices':skipped,'unrequested_indices':len(items)-attempts,'index_application_body_bytes_read':total,'approved_index_body_ceiling':approval['max_index_body_bytes'],'route':found,'last_error':last_error,'retries_in_this_scope':0,'redirects':0,'game_payload_bytes_read':0,'game_access':False,'installation_ready':False,'apply_authorized':False,'at_utc':datetime.now(timezone.utc).isoformat()}
 with(S/'SCAN-to-share.json').open('x')as f:json.dump(report,f,indent=2)
 if found:
  with(S/'VERIFIED-ROUTE.json').open('x')as f:json.dump(found,f,indent=2)
 print(json.dumps({'status':report['status'],'attempts':attempts,'verified':verified,'body_bytes':total,'skipped':skipped,'route':found}),flush=True);return 0 if found else 2
if __name__=='__main__':sys.exit(main())
