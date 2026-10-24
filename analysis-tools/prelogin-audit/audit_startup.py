"""Offline audit of an existing birth-HTTP report. Never executes a target or sends traffic."""
import argparse
import base64
import collections
import hashlib
import json
import re
from pathlib import Path


def audit(report):
    if report.get('schema') != 'bnet-process-birth-http-tls-1':
        raise ValueError('Unsupported report schema')
    reference = report.get('reference', {}).get('cpu_model')
    if not isinstance(reference, str) or not reference.strip():
        raise ValueError('Missing nonempty reference CPU')
    needle = reference.encode('utf-8')
    processes = {p['pid']: p for p in report.get('processes', [])}
    rows = []
    for index, q in enumerate(report['requests']):
        body = base64.b64decode(q['body_sample_base64'], validate=True)
        if len(body) > q['body_observed_bytes']:
            raise ValueError('Sample larger than observed body')
        headers = q['headers']
        matches = []
        if needle in body:
            matches.append('body_sample')
        if needle in q['target'].encode('latin1'):
            matches.append('target')
        if any(needle in value.encode('latin1') for _, value in headers):
            matches.append('header_value')
        ua = [value for key, value in headers if key.lower() == 'user-agent']
        proc = processes.get(q['pid'], {})
        rows.append({
            'index': index,
            'host': q['host'],
            'method': q['method'],
            'process_name': proc.get('process_name'),
            'process_sha256': q.get('process_sha256'),
            'body_observed_bytes': q['body_observed_bytes'],
            'body_complete': q['body_complete'],
            'body_sample_truncated': q['body_sample_truncated'],
            'reference_cpu_literal_locations': matches,
            'os_label_in_sample': b'Windows Server 2022' in body,
            'user_agent_present': bool(ua),
            'user_agent_os_label_present': any('Windows' in value for value in ua),
            'user_agent_software_version_hint': any(re.search(r'/[0-9]+\.[0-9]+', value) for value in ua),
            'query_keys': sorted(set(re.findall(r'[?&]([^=&]+)=', q['target']))),
            'header_names': sorted(set(key.lower() for key, _ in headers)),
        })
    per_host = []
    for host in sorted({row['host'] for row in rows}):
        group = [row for row in rows if row['host'] == host]
        per_host.append({
            'host': host,
            'request_count': len(group),
            'methods': dict(collections.Counter(row['method'] for row in group)),
            'nonempty_body_request_count': sum(row['body_observed_bytes'] > 0 for row in group),
            'reference_cpu_literal_request_indices': [row['index'] for row in group if row['reference_cpu_literal_locations']],
            'software_version_user_agent_observed': any(row['user_agent_software_version_hint'] for row in group),
            'os_label_in_user_agent_observed': any(row['user_agent_os_label_present'] for row in group),
        })
    return {
        'audit_schema': 'prelogin-destination-audit-1',
        'source_commit': report.get('source_commit'),
        'run_id': report.get('run_id'),
        'scope': report.get('scope'),
        'request_count': len(rows),
        'by_host': per_host,
        'cpu_literal_hits': [row for row in rows if row['reference_cpu_literal_locations']],
        'verdict': {
            'reference_cpu_observed_in_outgoing_pre_tls_request': any(row['reference_cpu_literal_locations'] for row in rows),
            'telemetry_domain_is_exclusive_hardware_destination': 'not_established',
            'server_application_receipt_or_storage': 'not_established',
            'all_users_all_versions': 'not_established',
        },
        'limits': [
            'Literal search only: encoded/compressed/binary representations and different identifiers may be missed.',
            'HTTP/1 plaintext and SSPI input coverage are not all-network coverage; OpenSSL/HTTP2/QUIC and unobserved processes are not covered.',
            'A complete sampled body is not proof every request was captured.',
            'Target/header search uses original redacted report; redacted secret values cannot be audited.',
            'Matching software version User-Agent is metadata, not a hardware serial or unique device identity.',
            'Local EncryptMessage success is not network-send completion or server acceptance.',
        ],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('report', type=Path)
    p.add_argument('output', type=Path)
    args = p.parse_args()
    raw = args.report.read_bytes()
    result = audit(json.loads(raw))
    result['input_sha256'] = hashlib.sha256(raw).hexdigest()
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print('Offline audit complete; no network or target execution.')


if __name__ == '__main__':
    main()
