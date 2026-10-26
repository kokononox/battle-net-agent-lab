"""Offline review of public footer fixtures; prepares, never executes, next plan."""
import base64,hashlib,json,struct
from pathlib import Path
from footer import verify_footer
BASE=Path(__file__).resolve().parents[2];SRC=Path(__file__).resolve().parent;OUT=BASE/'reports/index-footer-g49'
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 r=json.loads((OUT/'fetch-evidence.json').read_text());pre=json.loads((OUT/'preflight.json').read_text());p=json.loads((SRC/'plan.review-only.json').read_text());f=json.loads((OUT/'public-footer-fixtures.json').read_text())['objects']
 assert sha((SRC/'plan.review-only.json').read_bytes())==r['plan_sha256']==pre['plan_sha256']
 for name,digest in pre['source_hashes'].items():assert sha((SRC/name).read_bytes())==digest==r['source_hashes'][name]
 assert p['source_head_receipt_sha256']==r['source_head_receipt_sha256']==pre['g48_head_receipt_sha256']
 assert len(r['results'])==len(p['entries'])==len(f)==16
 audits=[];entries=[]
 for e,row in zip(p['entries'],r['results'],strict=True):
  assert all(row[k]==e[k] for k in ['id','url','expected_index_key','range_header','expected_content_range_total'])
  assert row['http_status']==206 and row['verified'] and row['received_and_sized'] and row['error_code'] is None
  x=f[e['id']];b=base64.b64decode(x['base64'],validate=True);assert x['expected_index_key']==e['expected_index_key'] and len(b)==x['bytes']==row['bytes']==28 and sha(b)==x['sha256']==row['sha256']
  v=verify_footer(b,e['expected_index_key'],e['expected_content_range_total']);assert all(row[k]==value for k,value in v.items())
  # Second calculation through unpacking/footer fields, not verifier output.
  n=struct.unpack('<I',b[16:20])[0];blocks=(n+169)//170;derived=blocks*4120+28
  assert hashlib.md5(b).hexdigest()==e['expected_index_key'] and derived==e['expected_content_range_total'] and v['derived_index_bytes']==derived
  assert row['observed_content_length']==['28'] and row['observed_content_range']==[f"bytes {e['range_start']}-{e['range_end']}/{derived}"]
  audits.append({'id':e['id'],'footer_fixture_reverified':True,'record_count':n,'derived_index_bytes':derived,'whole_index_verified':False,'footer_sha256':sha(b)})
  entries.append({'id':e['id'],'kind':'archive_index','archive_or_index_key':e['expected_index_key'],'url':e['url'],'method':'GET','expected_bytes':derived,'expected_footer_sha256':sha(b),'source_footer_id':e['id'],'requested':False,'runtime_approved':False})
 catalogroot=BASE if (BASE/'analysis-tools/download-broker-g37/catalog.deny-all.json').exists() else BASE.parent/'g37'
 catalog_sha=sha((catalogroot/'analysis-tools/download-broker-g37/catalog.deny-all.json').read_bytes());assert catalog_sha=='ee2b6f3e115f58ff21414168185024ffa9f574863333ab869cbb861c52c0c8c5'
 evidence={'schema':'public_footer_review_g49_v1','source_hashes_match_preflight':True,'fixture_count':len(f),'received_footer_bytes':sum(x['bytes'] for x in f.values()),'verified_footer_count':len(audits),'independent_layout_calculation_matches':True,'footer_proven_index_size_sum':sum(x['derived_index_bytes'] for x in audits),'body_or_toc_verification_implied':False,'sample_3_location_known':False,'runtime_approved_entries':0,'production_catalog_sha256':catalog_sha,'catalog_unchanged':True,'audits':audits}
 (OUT/'offline-review.json').write_text(json.dumps(evidence,indent=2)+'\n')
 total=sum(e['expected_bytes'] for e in entries)
 next_plan={'schema':'unexecuted_footer_bound_full_index_plan_g49_v1','executed':False,'source_footer_receipt_sha256':sha((OUT/'fetch-evidence.json').read_bytes()),'source_public_footer_fixtures_sha256':sha((OUT/'public-footer-fixtures.json').read_bytes()),'max_requests':len(entries),'expected_application_body_bytes':total,'max_application_body_read_with_oversize_detection':total+len(entries),'not_a_total_wire_or_tls_byte_cap':True,'automatic_retries':0,'redirects_followed':False,'request_body_cookie_authorization_sent':False,'required_status':200,'range_requests_permitted':False,'must_match_observed_footer_bytes_or_sha256':True,'must_verify_index_key_footer_toc_every_block_sort_count_padding':True,'must_merge_with_30_g46_verified_indexes_only_after_validation':True,'must_not_claim_sample_3_absent_until_complete_46_index_coverage':True,'payload_or_archive_fetch_approved':False,'runtime_approved_entries':0,'entries':entries}
 (OUT/'next-full-index-plan.unexecuted.json').write_text(json.dumps(next_plan,indent=2)+'\n');print(json.dumps({k:v for k,v in evidence.items() if k!='audits'}))
if __name__=='__main__':main()
