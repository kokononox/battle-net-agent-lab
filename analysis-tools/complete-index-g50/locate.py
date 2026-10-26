"""Offline complete-coverage reconciliation and lookup of the three pinned samples."""
import base64,hashlib,json
from pathlib import Path
from index_parser import parse_index
from fetch_indices import verify
BASE=Path(__file__).resolve().parents[2];SRC=Path(__file__).resolve().parent;OUT=BASE/'reports/complete-index-g50'
def root(stage,relative):return BASE if (BASE/relative).exists() else BASE.parent/stage
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):return json.loads(p.read_text())
def main():
 g46=root('g46','reports/archive-index-g46/public-index-fixtures.json');g45=root('g45','analysis-tools/sample-download-g45/plan.review-only.json');g49=root('g49','reports/index-footer-g49/public-footer-fixtures.json')
 p=read(SRC/'plan.review-only.json');pre=read(OUT/'preflight.json');receipt=read(OUT/'fetch-evidence.json');new=read(OUT/'public-index-fixtures.json')['objects'];oldreceipt=read(g46/'reports/archive-index-g46/fetch-evidence.json');old=read(g46/'reports/archive-index-g46/public-index-fixtures.json')['objects']
 assert sha((SRC/'plan.review-only.json').read_bytes())==pre['plan_sha256']==receipt['plan_sha256']
 for name,digest in pre['source_hashes'].items():assert sha((SRC/name).read_bytes())==digest==receipt['source_hashes'][name]
 originalraw=(g46/'analysis-tools/archive-index-g46/index-plan.review-only.json').read_bytes();assert sha(originalraw)==pre['source_original_g46_plan_sha256']=='09535d9a900d6d0ea3ec93df2505458217679d7e89ea1785aab35faa3c73a441'
 assert sha((g49/'reports/index-footer-g49/fetch-evidence.json').read_bytes())==p['source_footer_receipt_sha256']==pre['source_footer_receipt_sha256']
 assert sha((g49/'reports/index-footer-g49/public-footer-fixtures.json').read_bytes())==p['source_public_footer_fixtures_sha256']==pre['source_public_footer_fixtures_sha256']
 original=json.loads(originalraw)['entries'];sample_raw=(g45/'analysis-tools/sample-download-g45/plan.review-only.json').read_bytes();assert sha(sample_raw)=='7c29f72b27d00e8f82304c2a6b528811ebd54d40a3f06c78cabfdaaeaab7da47';samples=json.loads(sample_raw)['entries']
 assert len(original)==len(oldreceipt['results'])==46 and len(old)==30 and len(new)==len(receipt['results'])==len(p['entries'])==16
 assert not set(old)&set(new) and set(old)|set(new)=={x['id'] for x in original}
 verified={};audits=[]
 for expected,r in zip(original,oldreceipt['results'],strict=True):
  assert all(expected[k]==r[k] for k in ['id','kind','archive_or_index_key','expected_bytes']) and expected['proposed_url']==r['url']
  if not r['received_and_sized']:continue
  x=old[r['id']];b=base64.b64decode(x['base64'],validate=True)
  assert x['key']==r['archive_or_index_key'] and x['kind']==r['kind'] and sha(b)==x['sha256']==r['sha256'] and len(b)==x['bytes']==r['bytes']==r['expected_bytes']
  parsed=parse_index(b,x['key'],x['kind']);verified[r['id']]=(expected,b,parsed,'G46')
 for expected,r in zip(p['entries'],receipt['results'],strict=True):
  assert all(expected[k]==r[k] for k in ['id','url','kind','archive_or_index_key','expected_bytes','expected_footer_sha256']) and r['http_status']==200 and r['verified'] and r['received_and_sized']
  orig=next(e for e in original if e['id']==expected['id']);assert orig['archive_or_index_key']==expected['archive_or_index_key'] and orig['proposed_url']==expected['url']
  x=new[r['id']];b=base64.b64decode(x['base64'],validate=True);assert sha(b)==x['sha256']==r['sha256'] and len(b)==r['expected_bytes']==x['bytes']==r['bytes'] and x['key']==r['archive_or_index_key'] and x['kind']==r['kind']
  parsed=verify(expected,b);verified[r['id']]=(orig,b,parsed,'G50')
 assert set(verified)=={e['id'] for e in original} and len({v[2]['index_key'] for v in verified.values()})==46
 found={s['sample_id']:[] for s in samples}
 for eid in sorted(verified,key=lambda x:int(x.split('_')[1])):
  e,b,parsed,stage=verified[eid];audits.append({'id':eid,'key':parsed['index_key'],'kind':e['kind'],'source':stage,'sha256':sha(b),'bytes':len(b),'records':parsed['entry_count'],'blocks_verified':len(parsed['blocks']),'verified':True})
  for item in parsed['entries']:
   for s in samples:
    if item['ekey']!=s['ekey']:continue
    match=dict(item,index_id=eid,index_key=parsed['index_key'],source=stage,index_sha256=sha(b),size_matches_sample=item['encoded_bytes']==s['encoded_bytes'],archive_payload_verified_in_g50=False,kind=e['kind'])
    if e['kind']=='archive_index':match.update(archive_url=e['proposed_url'][:-6],range_start=item['offset'],range_end=item['offset']+item['encoded_bytes']-1)
    found[s['sample_id']].append(match)
 locations=[{'sample_id':s['sample_id'],'ekey':s['ekey'],'ckey':s['ckey'],'expected_encoded_bytes':s['encoded_bytes'],'expected_decoded_bytes':s['decoded_bytes'],'locations':found[s['sample_id']]} for s in samples]
 catroot=root('g37','analysis-tools/download-broker-g37/catalog.deny-all.json');catalog_sha=sha((catroot/'analysis-tools/download-broker-g37/catalog.deny-all.json').read_bytes());assert catalog_sha=='ee2b6f3e115f58ff21414168185024ffa9f574863333ab869cbb861c52c0c8c5'
 report={'schema':'complete_46_index_lookup_g50_v1','current_fetch_count':16,'prior_index_count':30,'verified_coverage_count':len(verified),'expected_index_count':46,'all_46_current_snapshot_indexes_verified':True,'archive_index_count':sum(a['kind']=='archive_index' for a in audits),'loose_index_count':sum(a['kind']=='loose_file_index' for a in audits),'current_received_body_bytes':sum(r['bytes'] for r in receipt['results']),'combined_snapshot_bytes':sum(a['bytes'] for a in audits),'sample_locations':locations,'index_audits':audits,'scope':'Only pinned G43 bna snapshot CDN-config 45 archives plus one loose index; not all builds, patch archives, regions or products.','payload_or_archive_downloaded_in_g50':False,'range_requests_issued_in_g50':False,'runtime_approved_entries':0,'catalog_sha256':catalog_sha,'catalog_unchanged':True,'publisher_signature_or_anti_fingerprinting_proven':False,'source_hashes_match_preflight':True}
 (OUT/'complete-index-lookup.json').write_text(json.dumps(report,indent=2)+'\n')
 s=next(s for s in samples if s['sample_id']=='sample_3');options=[x for x in found[s['sample_id']] if x['kind']=='archive_index' and x['size_matches_sample']];proposals=[]
 if options:
  x=sorted(options,key=lambda x:(x['index_key'],x['range_start']))[0];proposals=[{'sample_id':s['sample_id'],'archive_url':x['archive_url'],'range_start':x['range_start'],'range_end':x['range_end'],'range_header':f"bytes={x['range_start']}-{x['range_end']}",'expected_encoded_bytes':s['encoded_bytes'],'expected_decoded_bytes':s['decoded_bytes'],'ekey':s['ekey'],'ckey':s['ckey'],'source_index_id':x['index_id'],'source_index_sha256':x['index_sha256'],'executed':False,'runtime_approved':False}]
 next_plan={'schema':'unexecuted_third_sample_range_g50_v1','executed':False,'max_requests':len(proposals),'expected_application_body_bytes':sum(x['expected_encoded_bytes'] for x in proposals),'max_application_body_read_with_oversize_detection':sum(x['expected_encoded_bytes']+1 for x in proposals),'not_a_total_wire_or_tls_byte_cap':True,'required_status':206,'require_exact_content_range_and_length':True,'reject_full_archive_200_before_body':True,'must_verify_blte_ekey_ckey_decoded_size_and_observed_sha256':True,'automatic_retries':0,'redirects_followed':False,'client_may_supply_offset_or_range':False,'runtime_approved_entries':0,'entries':proposals}
 (OUT/'next-third-sample-plan.unexecuted.json').write_text(json.dumps(next_plan,indent=2)+'\n')
 print(json.dumps({k:v for k,v in report.items() if k!='index_audits'}))
if __name__=='__main__':main()
