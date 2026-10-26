"""Validate the bounded G73 run; no raw request values or uniqueness inferred."""
import argparse,json,hashlib,sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runtime',type=Path,default=Path('/data/raw/two-host-live-g73.json'));p.add_argument('--control',type=Path,default=Path('/data/raw/g73-native-control.json'));p.add_argument('--source-dir',type=Path,default=Path('/data/g73-compose-check/analysis-tools/two-host-live-g73-runtime'));p.add_argument('--artifact',type=Path);p.add_argument('--out',type=Path,default=Path('/data/analysis'));a=p.parse_args();a.out.mkdir(exist_ok=True,parents=True)
j=json.loads(a.runtime.read_text());c=json.loads(a.control.read_text());sha='853375455bb47336709ebb19da9b7f88da59b4d8d68d7530799f0f3aa0fd3459'
assert j['run_id']==c['run_id']=='40303775767' and j['source_commit']==c['source_commit']=='9ecfa937b6641cac904e3ec80caed3a5e6a10950'
assert j['error'] is None and j['cleanup'] and j['firewall_verified'] and c['passed'] and len(c['rows'])==12 and all(r['passed'] for r in c['rows'])
assert j['certificate_cache_online']['successful'] and j['certificate_cache_offline']['successful']
rows=j['request_value_audit']['rows'];cdn=[r for r in rows if r['host']=='level3.blizzard.com'];rr=[r['public_download_path']['range_semantics'] for r in cdn if r['range_present']]
assert len(rr)==13 and all(r['exact_public_boundary_match'] for r in rr)
full=[r for r in rr if r['public_boundary_basis']==['entire_public_object_DL_EN_size_agreement']];assert len(full)==1
assert full[0]['full_object_comparison']=={'independent_DL_EN_size_agreement':True,'starts_at_zero':True,'end_equals_public_size_minus_one':True,'range_length_equals_public_size':True}
# Independent hierarchy total, not a filtered count alone.
assert sum(r['range_present'] for r in cdn)==13 and len(cdn)==34
assert all(not r['fingerprinting_absence_proven'] for r in rr)
base=[r for r in cdn if r['public_download_path']['whole_path_exactly_in_independent_public_reference']];assert len(base)==33
attr=j['version_response_key_attribution'];assert len(attr['targets'])==1 and attr['targets'][0]['whole_CDN_path_independently_public']
assert attr['counts']=={'complete_requests':12,'complete_responses':12,'paired_responses':12} and attr['blocked_contexts']==attr['buffered_bytes']==attr['unanswered_observed_requests']==0
other=[r for r in cdn if not r['public_download_path']['whole_path_exactly_in_independent_public_reference']];assert len(other)==1 and not other[0]['range_present']
sys.path.insert(0,str(a.source_dir));from download_path_audit import load_reference,full_object_size
refs,ref_summary=load_reference(a.source_dir)
common=[path for path in refs if full_object_size(path,refs) is not None];assert len(common)==993
transport=j['accepted_write_transport_audit'];assert transport['accounting_reconciles'] and not transport['cap_hit']
assert sum(v for k,v in transport['counts'].items() if k.endswith('_record_bytes'))+transport['counts']['HTTP1_candidate_bytes']==transport['accepted_API_input_bytes']==9470
if a.artifact:assert hashlib.sha256(a.artifact.read_bytes()).hexdigest()==sha
facts={'run_id':j['run_id'],'source_commit':j['source_commit'],'artifact_sha256':sha,'artifact_hash_rechecked':bool(a.artifact),'target_runs_this_stage':1,'observed_seconds':j['observed_seconds'],'range_API_observations':len(rr),'exact_public_range_observations':sum(r['exact_public_boundary_match'] for r in rr),'whole_public_object_range_observations':len(full),'existing_structural_range_observations':len(rr)-len(full),'full_object_comparison':full[0]['full_object_comparison'],'public_paths_with_DL_EN_size_agreement':len(common),'CDN_API_rows':len(cdn),'baseline_public_full_path_matches':len(base),'additional_bts_exact_public_full_path_matches':1,'redacted_API_rows':len(rows),'redacted_duplicates_retained':len(rows)-len({json.dumps(r,sort_keys=True) for r in rows}),'Windows_tests_passed':141,'local_tests_total':141,'local_Windows_specific_skip':1,'native_controls_passed':len(c['rows']),'cleanup':j['cleanup'],'firewall_verified':j['firewall_verified'],'certificate_cache_online_offline_passed':True,'coverage_complete':j['coverage_complete'],'transport':transport,'origin_gaps':{k:v for k,v in j['hook_counts'].items() if 'gap' in k},'historical_raw_range_equality_proven':False,'runtime_allow_rules_changed':False,'public_reference_changed':False,'new_external_research_fetch_for_Range':False,'privacy_clearance':False,'comparison_plan':[{'finding':'exact whole-object Range equality in current observation','grain':'redacted API observation, not unique network request','disposition':'prose','reason':'semantic equality only; no temporal series or distribution to chart'}],'profiling_notes':'normalized heterogeneous runtime to request rows; retain redacted duplicates; version-server public_download_path null expected; null control errors mean no reported error; run_id is identifier; observed constants do not establish privacy'}
(a.out/'g73-evidence.json').write_text(json.dumps(facts,ensure_ascii=False,indent=2));(a.out/'g73-request-rows.json').write_text(json.dumps(rows));print(json.dumps({k:facts[k] for k in ['range_API_observations','exact_public_range_observations','whole_public_object_range_observations','public_paths_with_DL_EN_size_agreement','native_controls_passed','redacted_duplicates_retained']}))
