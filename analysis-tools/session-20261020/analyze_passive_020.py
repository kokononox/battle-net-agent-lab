import json,hashlib
from pathlib import Path
p=Path('/data/raw/passive-network-020-user.json');r=json.loads(p.read_text());a=r['analysis'];flows=a['selected_process_tcp_flows']
http=[q for f in flows for q in f['readable_http_requests']]
sni=sorted(set(f['sni'] for f in flows if f.get('sni')))
e={'source_attachment':'d61e7b08-489d-496f-b4a8-c458aa51f0cc','sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'status':r['status'],'error_code':r['error_code'],'capture':r['capture'],'sampling':r['process_sampling'],'analysis_limits':a['limits_hit'],'parse_errors':a['parse_errors'],'flow_count':len(flows),'flow_process_indices':sorted(set(f['process_index'] for f in flows)),'visible_sni_domains':sni,'plaintext_requests':http,'connections':[{'ip':f['remote_address'],'port':f['remote_port'],'process_index':f['process_index'],'sni':f['sni'],'http_host':f['plaintext_http_host'],'dns_candidates_not_proof':f['dns_answer_domain_candidates_not_proof']} for f in flows], 'interpretation':{'ingest_name_suggests_telemetry_but_payload_not_read':True,'actual_battle_net_dns_candidate_only':True,'no_global_no_hardware_claim':True},'comparison_plan':[{'grain':'connection domain identification','unit':'categorical evidence','disposition':'table','reason':'Not a numeric comparison; maps visible names to endpoints and confidence.'}],'profiler_warning_resolution':'Input is one nested diagnostic object, not a row table. Flattened duplicate/null/constant fields and rate hint are artifacts; use native nested flow/request arrays without dropping rows.'}
# Independent raw text and nested-request checks, not profiler flattening.
assert e['flow_count']==p.read_text().count('"outgoing_captured_packets"')==12
assert len(http)==sum(f.get('plaintext_http_request_count',0) for f in flows)==2
assert all(q['method']=='GET' and q['host']=='level3.blizzard.com' and q['body_declared_bytes']==0 and not q['query_present'] and not q['credential_header_present'] and not q['hardware_literal_categories'] for q in http)
assert e['flow_process_indices']==[1]
assert set(sni)=={'breaking-news.support.blizzard.com','eu.account.battle.net','wow.ingest.gdp.blizzard.com','prod.depot.battle.net','oauth.battle.net'}
Path('/data/analysis/passive-020-evidence.json').write_text(json.dumps(e,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'status':e['status'],'flow_count':len(flows),'http_request_count':len(http),'sni_domains':sni,'all_flow_process_indices':e['flow_process_indices'],'checks':'passed'}))
