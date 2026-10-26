"""No network: verify all received index bytes, locate only three pinned sample keys."""
import base64,hashlib,json,sys
from pathlib import Path
from index_parser import parse_index
from bindings import validate,snapshot
BASE=Path(__file__).resolve().parents[2];ROOT=BASE if (BASE/'reports/sample-download-g45').exists() else BASE.parent/'g45'
OUT=BASE/'reports/archive-index-g46';STORE=BASE/'public-indices'
def run():
 receipt=json.loads((OUT/'fetch-evidence.json').read_text());samples=validate(BASE,ROOT,receipt)
 found={s['sample_id']:[] for s in samples};target={s['ekey']:s for s in samples};audits=[];verified=[]
 for r in receipt['results']:
  if not r['received_and_sized']:continue
  a={'id':r['id'],'key':r['archive_or_index_key'],'kind':r['kind'],'verified':False,'error_code':None}
  try:
   b=snapshot(BASE,r)
   p=parse_index(b,r['archive_or_index_key'],r['kind']);a.update(verified=True,entry_count=p['entry_count'],blocks_verified=len(p['blocks']),sha256=p['input_sha256']);verified.append((r,b,p))
   for e in p['entries']:
    if e['ekey'] not in target:continue
    s=target[e['ekey']];match=dict(e,index_id=r['id'],index_key=r['archive_or_index_key'],kind=r['kind'],size_matches_sample=e['encoded_bytes']==s['encoded_bytes'],index_verified=True,archive_body_verified=False)
    if r['kind']=='archive_index':match.update(archive_url=r['url'][:-6],range_start=e['offset'],range_end=e['offset']+e['encoded_bytes']-1)
    found[s['sample_id']].append(match)
  except (ValueError,OSError) as e:
   code=str(e);a['error_code']=code if code.replace('_','').isalpha() and len(code)<80 else 'index_parse_or_binding_failed'
  audits.append(a)
 matches=[{'sample_id':s['sample_id'],'ekey':s['ekey'],'expected_encoded_bytes':s['encoded_bytes'],'locations':found[s['sample_id']]} for s in samples]
 report={'schema':'archive_index_locations_g46_v1','received_index_count':len(audits),'verified_index_count':sum(a['verified'] for a in audits),'rejected_before_body_read_count':sum(not r['received_and_sized'] for r in receipt['results']),'all_46_indices_verified':len(audits)==46 and all(a['verified'] for a in audits),'index_audits':audits,'sample_locations':matches,'payload_downloaded':False,'range_requests_issued':False,'runtime_approved_entries':0,'production_catalog_modified':False,'missing_indices_prevent_exhaustive_coverage_claim':True,'publisher_signature_or_anti_fingerprinting_proven':False}
 proposals=[]
 for s in samples:
  options=[x for x in found[s['sample_id']] if x['kind']=='archive_index' and x['size_matches_sample']]
  if not options:continue
  pick=sorted(options,key=lambda x:(x['index_key'],x['range_start']))[0]
  proposals.append({'sample_id':s['sample_id'],'archive_url':pick['archive_url'],'range_header':'bytes='+str(pick['range_start'])+'-'+str(pick['range_end']),'range_start':pick['range_start'],'range_end':pick['range_end'],'expected_encoded_bytes':s['encoded_bytes'],'expected_decoded_bytes':s['decoded_bytes'],'ekey':s['ekey'],'ckey':s['ckey'],'source_index_id':pick['index_id'],'source_index_sha256':next(a['sha256'] for a in audits if a['id']==pick['index_id']),'executed':False,'runtime_approved':False})
 plan={'schema':'unexecuted_fixed_range_proposal_g46_v1','entries':proposals,'all_three_samples_have_archive_candidate':len(proposals)==3,'executed':False,'max_requests':len(proposals),'expected_encoded_bytes':sum(x['expected_encoded_bytes'] for x in proposals),'required_response_status':206,'require_exact_content_range_and_length':True,'reject_full_archive_200_before_body':True,'must_validate_blte_ckey_and_actual_sha256':True,'client_may_supply_offset_or_range':False,'runtime_approved_entries':0}
 (OUT/'index-verification.json').write_text(json.dumps(report,indent=2)+'\n');(OUT/'next-range-plan.unexecuted.json').write_text(json.dumps(plan,indent=2)+'\n')
 fixtures={'schema':'public_index_fixtures_g46_v1','contains_payload_or_private_capture':False,'objects':{r['id']:{'key':r['archive_or_index_key'],'kind':r['kind'],'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'base64':base64.b64encode(b).decode()} for r,b,p in verified}}
 (OUT/'public-index-fixtures.json').write_text(json.dumps(fixtures,separators=(',',':'))+'\n')
 print(json.dumps({'received':len(audits),'verified':report['verified_index_count'],'parse_errors':[a for a in audits if not a['verified']],'sample_locations':matches,'range_proposals':len(proposals)}))
if __name__=='__main__':run()
