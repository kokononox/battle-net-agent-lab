"""Validate the uploaded T1.1 observation; no inferred TLS contents."""
import hashlib,json,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parent;SOURCE=Path('/data/raw/t11-user/level3-audit.json')
sys.path.insert(0,'/data/level3-request-audit-t1/app')
from request_audit import validate_audit,BLOCKED,TARGET,profile_ok

def main():
    d=json.loads(SOURCE.read_text());a=validate_audit(d['audit']);o=d['observation'];rs=a['requests']
    assert d['schema']=='level3-request-audit-1'
    processes={p['index']:p for p in o['processes']};assert len(processes)==len(o['processes'])
    target=[r for r in rs if r['host']==TARGET]
    numbers={'exported_requests':len(rs),'target_requests':len(target),
        'target_complete_requests':sum(r['body_complete'] for r in target),
        'target_nonzero_body_requests':sum(r['body_observed_bytes']>0 for r in target),
        'target_cpu_literal_matches':sum(r['cpu_literal_match'] is True for r in target),
        'target_credential_header_requests':sum(r['credential_header_present'] for r in target),
        'target_query_requests':sum(r['query_present'] for r in target),
        'parsed_requests_before_export_cap':len(rs),'method_counts':dict(Counter(r['method'] for r in target))}
    assert numbers==a['summary']
    # Independent raw predicate validates the headline without using summary/groupby.
    independent=0
    for r in d['audit']['requests']:
        if r['host']==TARGET:
            assert r['method']=='GET' and r['body_observed_bytes']==0 and r['body_declared_bytes']==0
            assert r['body_complete'] and not r['body_sample_truncated'] and not r['query_present']
            assert r['query_pairs']==0 and not r['credential_header_present'] and r['cpu_literal_match'] is False
            assert r['path_class']=='tpr' and r['layer']=='plaintext_winsock_input'
            independent+=1
    assert independent==26
    assert all(r['process_index'] in processes for r in rs)
    agent_indices=sorted({r['process_index'] for r in target})
    assert len(agent_indices)==1
    agent=processes[agent_indices[0]]
    assert agent['process_name']=='agent.exe' and agent['authenticode_valid'] and agent['blizzard_publisher']
    assert agent['sha256']=='b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5'
    unknown_tls=[dict(c,process_name=processes[c['process_index']]['process_name'],
        process_input_events=processes[c['process_index']]['input_events'])
        for c in o['public_tcp_destinations'] if c['remote_port']==443]
    distinct_tls={(c['process_index'],c['remote_address'],c['remote_port']) for c in unknown_tls}
    assert len(distinct_tls)==4 and all(c['process_name']=='battle.net.exe' and c['process_input_events']==0 for c in unknown_tls)
    request_headers=sorted({h for r in target for h in r['header_names']})
    assert request_headers==['accept','host','range'] and all(r['unknown_header_count']==0 and not r['user_agent_present'] for r in target)
    s=Counter((x['parse_status'],x['api_input_gap']) for x in a['streams'])
    events=o['events'];cpu_hits=[e for e in events if e['reference_cpu_literal_match'] is True]
    dns_checks={k:{'normalized_profile_matches':profile_ok(d[k]),'states':dict(Counter(d[k].values()))} for k in ('dns_before','dns_ready','dns_after')}
    assert all(v['normalized_profile_matches'] for v in dns_checks.values())
    evidence={'schema':'t11-user-content-analysis-1','input_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        'source_started_utc':d['started_utc'],'provenance':'user_uploaded_report_not_independently_signed',
        'ready':d['ready'],'status':d['status'],'error_code':d['error_code'],
        'user_final_state':d['user_final_state'],'user_download_behavior':d['user_download_behavior'],
        'download_progress_independently_measured':False,'initial_versions':d['initial_versions'],'final_versions':d['final_versions'],
        'hosts_changed_by_tool':d['hosts_changed_by_tool'],'hosts_hash_unchanged':d['hosts_hash_unchanged'],
        'dns_checks':dns_checks,'request_counts':numbers,'target_channel_count':len({r['channel'] for r in target}),
        'target_layers':dict(Counter(r['layer'] for r in target)),
        'target_path_classes':dict(Counter(r['path_class'] for r in target)),
        'target_header_names':request_headers,'target_unknown_header_total':sum(r['unknown_header_count'] for r in target),
        'target_user_agent_requests':sum(r['user_agent_present'] for r in target),
        'field_hints':{k:sorted({h for r in target for h in r[k]}) for k in ('query_field_hints','header_field_hints','body_field_hints')},
        'cpu_reference_available':a['cpu_reference_available'],'event_cpu_literal_hits':len(cpu_hits),
        'agent':{k:agent[k] for k in ('index','process_name','sha256','status','input_events','script_errors','authenticode_valid','blizzard_publisher')},
        'public_tcp_destinations':o['public_tcp_destinations'],'https_content_unobserved':unknown_tls,
        'https_unobserved_distinct_destinations':len(distinct_tls),
        'sampler_errors':o['sampler_errors'],'attach_failures':[{'process_index':p['index'],'process_name':p['process_name'],'error_code':p['error_code']} for p in o['processes'] if p['status']=='not_attached'],
        'base_limits_hit':o['limits_hit'],'audit_buffer_limit_hit':a['buffer_limit_hit'],
        'sampling_thread_stopped':o['sampling_thread_stopped'],
        'streams':{'total':len(a['streams']),'parse_states':[{'parse_status':k[0],'api_input_gap':k[1],'streams':v} for k,v in s.items()],
            'by_process':dict(Counter(str(x['process_index']) for x in a['streams']))},
        'input_events':len(events),'event_phase_counts':dict(Counter(e['phase'] for e in events)),
        'input_host_hints':dict(Counter(e['host_hint'] for e in events)),
        'event_first_last_elapsed_seconds':[min(e['elapsed_seconds'] for e in events),max(e['elapsed_seconds'] for e in events)],
        'requests_attributable_to_resume_instant':False,'received_bytes_measured':a['received_bytes_measured'],
        'zero_personal_data_proven':a['zero_personal_data_proven'],
        'coverage_notes':['Full paths and header values were intentionally not exported: encoded identifiers cannot be excluded.',
            'Four public TCP/443 destinations from battle.net.exe were sampled but that process had zero captured input events; contents and hostnames unknown.',
            'All streams say parsed_to_end, but this parser can silently omit requests with unsupported Host values; not proof that all streams yielded audited requests.',
            'Late attach, two attach failures, one sampler error, and unsupported APIs/protocols constrain coverage.',
            'Repeated sanitized metadata rows are expected; raw URLs are absent and rows must not be deduplicated as identical network requests.'],
        'comparison_plan':[{'disposition':'prose','grain':'captured target requests','finding':'26 plaintext GETs without body/query/credential headers; CPU literal absent','reason':'bounded diagnostic finding, no meaningful chart geometry'},
            {'disposition':'prose','grain':'sampled process/destination TCP tuples','finding':'four TLS destinations without captured contents','reason':'coverage boundary, not a comparable traffic-volume series'}]}
    (ROOT/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps({'target_requests':independent,'headers':request_headers,'unobserved_https_destinations':len(distinct_tls),'sampler_errors':o['sampler_errors'],'attach_failures':len(evidence['attach_failures']),'stream_states':evidence['streams']['parse_states']}))
if __name__=='__main__':main()
