"""Reproducible review of capped sanitized G26 evidence and official observations.
No network operations; does not produce executable allowlist entries.
"""
import argparse,hashlib,json
from pathlib import Path
import pandas as pd

def read(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def analyze(raw,derived):
 r=read(raw/'online-g26.json');rows=r['request_metadata'];df=pd.DataFrame(rows)
 requests=df[df['kind']=='http_request'];responses=df[df['kind']=='http_response']
 facts={'metadata_rows':len(df),'reporter_row_cap':256,'http_request_rows':len(requests),'distinct_path_hashes':requests['path_sha256'].nunique(),'all_sampled_http_requests_get':bool(requests['method'].eq('GET').all()),'all_sampled_http_request_bodies_empty':bool(requests['request_body_bytes'].eq(0).all()),'all_sampled_http_queries_absent':bool(requests['query_present'].eq(False).all()),'sampled_response_statuses':sorted(int(x) for x in responses['status'].unique()),'http_request_hosts':sorted(requests['host'].unique()),'http_request_ports':sorted(int(x) for x in requests['port'].unique()),'all_rows_have_raw_path':all('path' in row for row in rows),'https_payload_classified':r['https_payload_classified']}
 # Independent direct-filter check; do not deduplicate repeated event projections.
 direct=[row for row in rows if row['kind']=='http_request']
 assert len(direct)==facts['http_request_rows']
 assert len({row['path_sha256'] for row in direct})==facts['distinct_path_hashes']
 assert all(row['method']=='GET' and row['request_body_bytes']==0 and row['query_present'] is False for row in direct)
 assert len(rows)==256 and 'len(r[\'request_metadata\'])<256' in (raw/'Reporter.py').read_text()
 total_kinds=sum(v for k,v in r['proxy_event_counts'].items() if k.split(':')[0] in {'http_request','http_response','tls_transfer','tls_transfer_final'})
 facts['metadata_truncated_relative_to_event_counts']=total_kinds>len(rows)
 old=r['preflight'];head=read(raw/'official-installer-head-route.json');route=head['route']
 official=read(derived/'official-windows-links.json')
 advertised=[row['value'] for row in official['installer_attributes'] if row['attribute']=='href']
 assert route[0]['url'] in advertised
 assert route[-1]['status']==200 and route[-1]['url']==route[0]['location']
 assert all(step['method']=='HEAD' and not step['body_read'] for step in route)
 entry={'candidate_id':'official_windows_bootstrap','stage':'pre_isolation_manual_acquisition','source':'https://download.battle.net/en-us/?platform=windows','advertised_url':route[0]['url'],'versioned_url':route[-1]['url'],'head_advertised_bytes':int(route[-1]['content-length']),'fresh_sha256':None,'fresh_authenticode_verified':False,'historical_pin':{'source_commit':r['source_commit'],'bytes':old['bytes'],'sha256':old['sha256'],'signature_accepted_in_prior_vm':old['signature_accepted']},'runtime_allowlisted':False,'review_status':'pending','blockers':['host_outside_existing_two_host_gate','fresh_file_hash_and_signature_not_checked','not_proof_of_complete_install_payload','official_origin_not_privacy_proof']}
 candidates=[entry,{'candidate_id':'observed_cdn_payloads','host':'level3.blizzard.com','stage':'installation_payload','observed_protocol':'http','observed_port':80,'exact_paths_available':False,'object_payload_hashes_available':False,'response_bytes_include_http_headers':True,'runtime_allowlisted':False,'review_status':'pending','blockers':['paths_hashed_only','sample_capped','outbound_headers_not_recorded','no_artifact_payload_sha256','https_compatibility_unverified','range_206_compatibility_not_implemented_in_broker']},{'candidate_id':'observed_version_service','host':'us.version.battle.net','stage':'unknown_encrypted_installation_requests','observed_protocol':'tls','observed_port':443,'exact_paths_available':False,'runtime_allowlisted':False,'review_status':'pending','blockers':['https_payload_not_decrypted','request_fields_and_purpose_unknown','static_manifest_unavailable']},{'candidate_id':'negative_test_agent_versions','host':'us.version.battle.net','path':'/agent/versions','port':1119,'stage':'synthetic_negative_probe_not_observed_target_request','runtime_allowlisted':False,'review_status':'not_installation_evidence','blockers':['path_from_outside_job_denial_test_not_target_request_trace']}]
 result={'schema':'download_source_review_g38_v1','prior_run':r['run_id'],'prior_source_commit':r['source_commit'],'report_url':'https://github.com/kokononox/battle-net-agent-lab/blob/494752c2d647f5c83ac87b502b1e1c535cc7d468/reports/longer-client-observation-g26/online-g26.json','facts':facts,'official_head_observation':head,'candidates':candidates,'approved_new_runtime_resources':0,'catalog_updated':False,'installer_downloaded_in_review':False,'profile_notes':['event rows mix request,response,TLS projections','structural nulls are not missing measurements for the same event type','identical projected rows retained: may be distinct repeated events','metadata is capped; not full resource inventory','no raw path reconstruction from one-way hashes','response_bytes is wire bytes including headers, not object payload size'],'comparison_plan':[{'grain':'source evidence category','population':'current official bootstrap and prior sanitized installation observations','unit':'privacy approval evidence','finding':'exact bootstrap source identified; complete runtime resource manifest still unavailable','disposition':'prose','reason':'qualitative trust/completeness review, no meaningful quantitative chart'}],'source_sha256':{p.name:sha(p) for p in sorted(raw.iterdir()) if p.is_file()}}
 assert all(c['runtime_allowlisted'] is False for c in candidates)
 return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--raw',type=Path,required=True);p.add_argument('--derived',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 evidence=analyze(a.raw,a.derived);a.output.write_text(json.dumps(evidence,indent=2)+'\n')
 print('Official versioned bootstrap identified; no new runtime resources approved.')
 print('Source review complete; raw path/header/HTTPS gaps remain.')
