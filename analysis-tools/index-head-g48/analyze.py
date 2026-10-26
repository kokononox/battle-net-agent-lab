"""Offline header evidence reconciliation; no network, no policy changes."""
import base64,csv,hashlib,json
from pathlib import Path
import pandas as pd
BASE=Path(__file__).resolve().parents[2];OUT=BASE/'reports/index-head-g48';SRC=BASE/'analysis-tools/index-head-g48'
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 receipt=json.loads((OUT/'head-evidence.json').read_text());pre=json.loads((OUT/'preflight.json').read_text());plan=json.loads((SRC/'plan.review-only.json').read_text())
 assert sha((SRC/'head_indices.py').read_bytes())==receipt['source_sha256']==pre['source_sha256']
 assert sha((SRC/'plan.review-only.json').read_bytes())==receipt['plan_sha256']==pre['plan_sha256']
 root=BASE if (BASE/'reports/public-manifest-g43/configs.json').exists() else BASE.parent/'g43'
 configs=json.loads((root/'reports/public-manifest-g43/configs.json').read_text());cdn=next(x for x in configs['requests'] if x.get('kind')=='cdn')
 raw_path=root/'public-metadata/bna-us-cdn-config.bin'
 if raw_path.exists():raw=raw_path.read_bytes()
 else:
  fixtures=json.loads((root/'reports/public-manifest-g43/public-fixtures.json').read_text())
  raw=base64.b64decode(fixtures['objects']['bna-us-cdn-config.bin']['base64'],validate=True)
 assert sha(raw)==cdn['sha256']=='1d2da7b05e82643e2a1a876793f903aa4af70dc2e1c8c60f0fb5cc1ee9fadfad'
 assert hashlib.md5(raw).hexdigest()==cdn['content_key']=='c8743bdf1b6b4ba5dfdeb2e0d28bd1a4'
 pairs={}
 for line in raw.decode().splitlines():
  if ' = ' in line:
   k,v=line.split(' = ',1);pairs[k]=v
 keys=pairs['archives'].split();sizes=list(map(int,pairs['archives-index-size'].split()));assert len(keys)==len(sizes)==45
 original=dict(zip(keys,sizes,strict=True));rows=[]
 assert len(receipt['results'])==16 and len({r['id'] for r in receipt['results']})==16
 for r,e in zip(receipt['results'],plan['entries'],strict=True):
  assert all(r[k]==e[k] for k in ('id','url','original_expected_bytes'))
  key=r['url'].rsplit('/',1)[-1][:-6];assert original[key]==r['original_expected_bytes']
  rows.append({'id':r['id'],'http_status':r.get('http_status'),'original_expected_bytes':r['original_expected_bytes'],'advertised_content_length':r.get('advertised_content_length'),'head_length_usable_for_review':r.get('head_length_usable_for_review',False),'matches_original_expected':r.get('matches_original_expected'),'key':key,'url':r['url'],'original_expected_matches_pinned_cdn_config':True})
 df=pd.DataFrame(rows);usable=df['head_length_usable_for_review'].eq(True);mismatch=usable & df['matches_original_expected'].eq(False)
 summary={'observed_entries':len(df),'http_200_count':int(df['http_status'].eq(200).sum()),'usable_head_length_count':int(usable.sum()),'different_from_original_expected_count':int(mismatch.sum()),'same_as_original_expected_count':int((usable & df['matches_original_expected'].eq(True)).sum()),'original_size_sum':int(df['original_expected_bytes'].sum()),'head_advertised_size_sum':int(df.loc[usable,'advertised_content_length'].sum()),'response_body_read_calls':receipt['response_body_read_calls'],'all_original_expectations_match_pinned_cdn_config':bool(df['original_expected_matches_pinned_cdn_config'].all())}
 # Independent direct JSON path, not a second DataFrame calculation.
 assert summary['different_from_original_expected_count']==sum(r['head_length_usable_for_review'] and r['advertised_content_length']!=r['original_expected_bytes'] for r in receipt['results'])==16
 assert summary['http_200_count']==sum(r['http_status']==200 for r in receipt['results'])==16
 assert summary['head_advertised_size_sum']==sum(r['advertised_content_length'] for r in receipt['results'])
 assert summary['response_body_read_calls']==0
 catalog_root=BASE if (BASE/'analysis-tools/download-broker-g37/catalog.deny-all.json').exists() else BASE.parent/'g37'
 catalog_sha=sha((catalog_root/'analysis-tools/download-broker-g37/catalog.deny-all.json').read_bytes());assert catalog_sha=='ee2b6f3e115f58ff21414168185024ffa9f574863333ab869cbb861c52c0c8c5'
 evidence={'schema':'head_diagnostic_analysis_g48_v1','head_receipt_sha256':sha((OUT/'head-evidence.json').read_bytes()),'source_hashes_match_preflight':True,'cdn_config_content_md5_and_sha256_verified':True,'summary':summary,'profile_notes':['grain: one fixed index URL per HEAD observation','16 unique ids; no duplicates or null lengths','constant HTTP status and booleans are legitimate observed outcomes, not missing variance','HEAD measures current advertised length; not verified body length or historical GET header'],'comparison_plan':[{'grain':'one index URL','population':'16 G46 length-rejected indexes only','unit':'advertised bytes','finding':'Each current HEAD length differs from its prior pinned-config expectation.','disposition':'table','reason':'Protocol acceptance/evidence ledger, not a performance trend; per-key exact values matter and a chart supplies no additional decision evidence.'}],'cause_proven':False,'historical_g46_actual_length_recovered':False,'new_lengths_approved_for_runtime':False,'catalog_sha256':catalog_sha,'catalog_unchanged':True,'rows':rows}
 (OUT/'analysis-evidence.json').write_text(json.dumps(evidence,indent=2)+'\n');df.to_csv(OUT/'length-comparison.csv',index=False)
 # A future header-only Range proposal, not an executor or approval for full bodies.
 entries=[]
 for r in rows:
  n=r['advertised_content_length'];assert 28<n<=131072
  entries.append({'id':r['id'],'url':r['url'],'expected_index_key':r['key'],'method':'GET','range_header':f'bytes={n-28}-{n-1}','range_start':n-28,'range_end':n-1,'expected_response_body_bytes':28,'expected_content_range_total':n,'requested':False,'runtime_approved':False})
 next_plan={'schema':'unexecuted_index_footer_range_g48_v1','executed':False,'source_head_receipt_sha256':evidence['head_receipt_sha256'],'max_requests':16,'expected_application_body_bytes':448,'max_application_body_read_with_oversize_detection':464,'not_a_total_wire_byte_budget':True,'automatic_retries':0,'redirects_followed':False,'request_body_cookie_authorization_sent':False,'required_response_status':206,'reject_full_index_200_before_body':True,'require_exact_content_length_range_and_total':True,'must_verify_footer_md5_equals_original_index_key':True,'must_verify_footer_checksum_and_supported_fields':True,'must_derive_layout_size_from_count_and_compare_head_length':True,'footer_proof_is_not_block_or_toc_content_verification':True,'full_index_fetch_approved':False,'runtime_approved_entries':0,'entries':entries}
 (OUT/'next-footer-plan.unexecuted.json').write_text(json.dumps(next_plan,indent=2)+'\n')
 print(json.dumps(summary))
if __name__=='__main__':main()
