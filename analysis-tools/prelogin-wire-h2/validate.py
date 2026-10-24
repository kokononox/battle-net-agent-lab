"""Strict allowlist, no bytes/headers/URLs/IDs/paths accepted in public evidence."""
import json
from pathlib import Path
import re
import sys

TOP=set('schema source_commit run_id status error_code selftest bootstrap_pin_match target_launched processes requests parse_states network_linked_hardware_requests request_count capture collector_errors dropped_events collector_fatal limits'.split())
STATES={'not_started','native_gate','native_gate_failed_no_installer','observation_complete','target_stopped','collector_incomplete','stopped'}
PARSE={'incomplete_headers','unsupported_request_boundary','invalid_headers','invalid_host','transfer_encoding_unsupported','invalid_length','body_limit','incomplete_body','complete','request_limit','context_has_failed_or_incomplete_encryption','concurrent_context','context_limit'}
ISSUES={'snapshot_truncated','short_ethernet','unsupported_link','short_ip','ip_bounds','ip_fragments_unsupported','short_ip6','ip6_bounds','ipv6_extension_unsupported','short_tcp','tcp_bounds','tcp_overlap_conflict'}
NAMES={'agent.exe','battle.net.exe','battle.net launcher.exe','battle.net-setup.exe','battle.net helper.exe','blizzarderror.exe','other'}
LIMITS={'server_storage_proven':False,'all_network_paths_covered':False,'raw_values_exported':False,'login_performed':False,'game_download_requested':False,'install_action_requested':False,'tls_validation_changed':False,'sspi_http1_only':True,'async_completion_supported':False,'circular_capture_can_drop_early_packets':True}


def number(v,maximum=2**31):
    if type(v) is not int or not 0<=v<=maximum:raise ValueError('number')


def boolean(v):
    if type(v) is not bool:raise ValueError('boolean')


def counts(d,keys):
    if type(d) is not dict or not set(d)<=keys:raise ValueError('counter_keys')
    for v in d.values():number(v)


def validate(r):
    if type(r) is not dict or set(r)!=TOP or r['schema']!='bnet-prelogin-wire-h2-1':raise ValueError('schema')
    if type(r['source_commit']) is not str or not re.fullmatch('[a-f0-9]{40}',r['source_commit']):raise ValueError('source')
    if type(r['run_id']) is not str or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('run')
    if r['status'] not in STATES or r['error_code'] not in (None,'native_gate_failed','bootstrap_pin_mismatch_refused','bounded_h2_failed'):raise ValueError('status')
    for k in ('target_launched','collector_fatal'):boolean(r[k])
    if r['bootstrap_pin_match'] is not None:boolean(r['bootstrap_pin_match'])
    if r['limits']!=LIMITS or any(type(v) is not bool for v in r['limits'].values()):raise ValueError('limits')
    for k in ('network_linked_hardware_requests','request_count','collector_errors','dropped_events'):number(r[k])
    counts(r['parse_states'],PARSE)
    if type(r['processes']) is not list or len(r['processes'])>9:raise ValueError('processes')
    for p in r['processes']:
        if type(p) is not dict or set(p)!={'name','sha256','instrumented_before_resume','script_errors'} or p['name'] not in NAMES:raise ValueError('process')
        if p['sha256'] is not None and (type(p['sha256']) is not str or not re.fullmatch('[a-f0-9]{64}',p['sha256'])):raise ValueError('image_hash')
        boolean(p['instrumented_before_resume']);number(p['script_errors'])
    if type(r['requests']) is not list or len(r['requests'])>256:raise ValueError('requests')
    keys=set('destination method tls_record_count hardware_payload_verified hardware_field_count cpu_reference_match socket_send_linked packet_bytes_linked http_response_status server_storage_proven'.split())
    for row in r['requests']:
        if type(row) is not dict or set(row)!=keys or row['destination'] not in ('telemetry-in.battle.net','ingest.gdp.blizzard.com','example.com','other') or row['method'] not in ('GET','POST','HEAD','PUT','PATCH','DELETE','OPTIONS'):raise ValueError('request_schema')
        for k in ('hardware_payload_verified','cpu_reference_match','socket_send_linked','packet_bytes_linked','server_storage_proven'):boolean(row[k])
        for k in ('tls_record_count','hardware_field_count'):number(row[k],2048)
        if row['server_storage_proven']:raise ValueError('storage_claim')
        code=row['http_response_status']
        if code is not None and (type(code) is not int or not 100<=code<=599):raise ValueError('response')
        if row['packet_bytes_linked'] and not row['socket_send_linked']:raise ValueError('ladder')
        if code is not None and not row['packet_bytes_linked']:raise ValueError('response_ladder')
    if r['request_count']!=len(r['requests']) or r['network_linked_hardware_requests']!=sum(x['hardware_payload_verified'] and x['packet_bytes_linked'] for x in r['requests']):raise ValueError('crossfoot')
    c=r['capture']
    if c is not None:
        if type(c) is not dict or set(c)!=set('start_code stop_code convert_code packets issues'.split()):raise ValueError('capture')
        for k in ('start_code','stop_code','convert_code'):
            if c[k] is not None and (type(c[k]) is not int or not -2**31<=c[k]<=2**32):raise ValueError('capture_code')
        number(c['packets']);counts(c['issues'],ISSUES)
    s=r['selftest']
    if s is not None:
        keys=set('passed root_child_instrumented negative_encryption_observed linked_probe_requests http_responses_linked collector_errors dropped_events stage error_type fixture_exit_code packets successful_encryptions successful_decryptions socket_events'.split())
        if type(s) is not dict or set(s)!=keys:raise ValueError('selftest')
        for k in ('passed','root_child_instrumented','negative_encryption_observed'):boolean(s[k])
        for k in ('linked_probe_requests','http_responses_linked','collector_errors','dropped_events','packets','successful_encryptions','successful_decryptions','socket_events'):number(s[k])
        if s['stage'] not in ('compile','capture','spawn_fixture','wait_fixture','analyze','complete') or s['error_type'] not in (None,'OSError','RuntimeError','TimeoutExpired','ValueError','Exception'):raise ValueError('gate_status')
        if s['fixture_exit_code'] is not None and (type(s['fixture_exit_code']) is not int or not 0<=s['fixture_exit_code']<2**32):raise ValueError('fixture_exit')
        if s['passed'] and not (s['root_child_instrumented'] and s['negative_encryption_observed'] and s['linked_probe_requests']==2 and s['http_responses_linked']==2 and not s['collector_errors'] and not s['dropped_events']):raise ValueError('false_gate_pass')
    if r['target_launched'] and not (s and s['passed'] and r['bootstrap_pin_match']):raise ValueError('ungated_launch')
    if r['network_linked_hardware_requests'] and (r['collector_errors'] or r['dropped_events'] or r['collector_fatal'] or not r['target_launched']):raise ValueError('incomplete_verdict')
    return r


def load(raw):
    if len(raw)>256*1024:raise ValueError('size')
    def pairs(items):
        out={}
        for k,v in items:
            if k in out:raise ValueError('duplicate_key')
            out[k]=v
        return out
    return validate(json.loads(raw,object_pairs_hook=pairs))


if __name__=='__main__':
    src,dst=map(Path,sys.argv[1:]);r=load(src.read_bytes());dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text(json.dumps(r,indent=2)+'\n')
