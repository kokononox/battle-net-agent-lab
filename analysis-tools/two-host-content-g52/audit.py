"""Recount existing sanitized evidence, never invent plaintext or hostname attribution."""
import hashlib, json
from pathlib import Path
from collections import Counter
HOSTS = ('level3.blizzard.com', 'us.version.battle.net')

def audit(data, source_hash):
    if data.get('schema') != 'level3-request-audit-1':
        raise ValueError('source_schema')
    rows = data['audit']['requests']
    if not isinstance(rows, list):
        raise ValueError('request_rows')
    out = {'schema':'two-host-content-g52-1', 'evidence_kind':'historical_user_uploaded_sanitized_API_observation_not_new_live_capture',
           'source_sha256':source_hash, 'source_started_utc':data['started_utc'],
           'rows_retained_without_deduplication':len(rows), 'hosts':{},
           'fingerprinting_absence_proven':False, 'server_receipt_proven':False,
           'exact_RC_configuration_equivalence_verified':False,
           'full_paths_and_header_values_available':False}
    for host in HOSTS:
        selected = [r for r in rows if r['host'] == host]
        counts = dict(Counter(r['method'] for r in selected))
        # Independent direct iteration, not the selection's length or provided summary.
        independent = 0
        for row in rows:
            if row['host'] == host:
                independent += 1
        assert independent == len(selected) == sum(counts.values())
        out['hosts'][host] = {
            'captured_request_rows':independent, 'methods':counts,
            'nonzero_observed_body_rows':sum(r['body_observed_bytes'] > 0 for r in selected),
            'query_present_rows':sum(r['query_present'] is True for r in selected),
            'credential_header_rows':sum(r['credential_header_present'] is True for r in selected),
            'cpu_literal_match_rows':sum(r['cpu_literal_match'] is True for r in selected),
            'header_names':sorted({h for r in selected for h in r['header_names']}),
            'all_observed_bodies_complete':all(r['body_complete'] is True and r['body_sample_truncated'] is False for r in selected) if selected else None,
            'layers':dict(Counter(r['layer'] for r in selected)),
            'path_classes':dict(Counter(r['path_class'] for r in selected)),
            'disposition':'bounded_API_observation_values_redacted_not_privacy_clearance' if selected else 'unknown_no_exported_request_rows_not_evidence_of_no_traffic'}
    obs = data['observation']
    processes = {p['index']:p for p in obs['processes']}
    if len(processes) != len(obs['processes']):
        raise ValueError('duplicate_process_index')
    unknown = set()
    for flow in obs['public_tcp_destinations']:
        p = processes[flow['process_index']]
        if flow['remote_port'] == 443 and p['input_events'] == 0:
            unknown.add((flow['process_index'],flow['remote_address'],443))
    out['coverage'] = {'unobserved_443_process_destination_tuples':len(unknown),
        'these_443_hostnames_known':False, 'these_443_assigned_to_either_target':False,
        'sampler_errors':obs['sampler_errors'],
        'not_attached_processes':sum(p['status']=='not_attached' for p in obs['processes']),
        'parser_completeness_proven':False, 'received_bytes_measured':data['audit']['received_bytes_measured']}
    out['comparison_plan'] = [{'disposition':'prose','grain':'bounded API request rows',
        'reason':'Evidence coverage audit, not comparable traffic volumes; zero rows means unknown, not zero traffic.'}]
    return out

def main():
    source = Path('reports/level3-audit-t11-user.json')
    raw = source.read_bytes()
    result = audit(json.loads(raw), hashlib.sha256(raw).hexdigest())
    dest = Path('output/two-host-content-g52.json');dest.parent.mkdir(exist_ok=True)
    dest.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=True))
if __name__ == '__main__':main()
