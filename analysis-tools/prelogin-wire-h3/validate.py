"""Exact allowlist. No raw payload, addresses, UUIDs, host identifiers or TLS bytes."""
import json
from pathlib import Path
import re
import sys
BOOLS={'root_child_instrumented','bitness_confirmed','negative_encryption_observed','passed','collector_fatal'}
COUNTS={'linked_probe_requests','http_responses_linked','collector_errors','dropped_events','completed_operations','pending_socket_events','unlinked_immediate_socket_events','packet_count'}
APIS={'EncryptMessage','DecryptMessage','send','recv','WSASend','WSARecv','WSAGetOverlappedResult','connect','WSAConnect','closesocket','other','BindIoCompletionCallback','CreateThreadpoolIo'}
REASONS={'bounded','buffer_count','data_layout','stream_layout','socket_limit','context_limit','accepted_bounds','pending_limit','overlapped_reuse','callback_unsupported','completion_unmatched','memory_access','missing_export','other','callback_limit','completion_race','completion_ambiguous','callback_origin'}
WITNESS={'large_recv','multibuffer_recv','pending_recv','false_completion_checked','async_recv','async_send','bound_callback_recv','threadpool_recv','large_actual_recv'}
CHECKS={'large_recv','multibuffer_recv','async_recv','async_send','async_bound_recv','async_tp_recv','large_actual_recv'}
def require(x):
    if not x:raise ValueError('non_allowlisted_or_inconsistent_summary')
def count(x):require(type(x) is int and 0<=x<=10000000)
def validate(r):
    require(type(r) is dict and set(r)=={'schema','source_commit','run_id','target_launched','game_download_requested','raw_values_exported','tls_validation_changed','scope','async_scope','diagnostic_counters_partial','socket_chunking_supported','iocp_supported','callback_supported','all_network_paths_covered','passed','fixtures'})
    require(r['schema']=='bnet-h3-owned-fixtures-6' and type(r['source_commit']) is str and re.fullmatch('[0-9a-f]{40}',r['source_commit']) and type(r['run_id']) is str and re.fullmatch('[0-9]{1,20}',r['run_id']))
    for k in ('target_launched','game_download_requested','raw_values_exported','tls_validation_changed','iocp_supported','callback_supported','all_network_paths_covered'):require(r[k] is False)
    require(r['diagnostic_counters_partial'] is True and r['socket_chunking_supported'] is True)
    require(r['scope']=='owned_loopback_and_example_com_only' and r['async_scope']=='event_and_registered_win32_callbacks_only')
    require(type(r['passed']) is bool and type(r['fixtures']) is list and len(r['fixtures'])==2)
    require([x['architecture'] for x in r['fixtures']]==['x64','x86'])
    for f in r['fixtures']:
        require(set(f)==BOOLS|COUNTS|{'architecture','stage','error_type','fixture_exit_code','diagnostics','observations','capture_issues','witness','hook_checks'})
        for k in BOOLS:require(type(f[k]) is bool)
        for k in COUNTS:count(f[k])
        require(f['stage'] in ('compile','capture','spawn','wait','analyze','complete'))
        require(f['error_type'] in (None,'OSError','RuntimeError','TimeoutExpired','ValueError','Exception'))
        require(f['fixture_exit_code'] is None or type(f['fixture_exit_code']) is int and 0<=f['fixture_exit_code']<=4294967295)
        for k,keys in [('witness',WITNESS),('hook_checks',CHECKS)]:
            require(type(f[k]) is dict and set(f[k])==keys and all(type(v) is bool for v in f[k].values()))
        require(type(f['diagnostics']) is dict and len(f['diagnostics'])<=200)
        for k,v in f['diagnostics'].items():
            parts=k.split('|');require(len(parts)==3 and parts[0] in APIS and parts[1] in ('enter','leave','install','completion','other') and parts[2] in REASONS);count(v)
        require(sum(f['diagnostics'].values())<=f['collector_errors'])
        require(type(f['observations']) is dict and len(f['observations'])<=100)
        for k,v in f['observations'].items():
            parts=k.split('|');require(len(parts)==3 and parts[0] in {'send','recv','WSASend','WSARecv','GetQueuedCompletionStatus','GetQueuedCompletionStatusEx','GetOverlappedResult','GetOverlappedResultEx','NtRemoveIoCompletion','NtRemoveIoCompletionEx','BindIoCompletionCallback','CreateThreadpoolIo'} and parts[1] in {'submission','reuse','completion_call','registration'} and parts[2] in {'pending','non_pending_error','unknown_error','immediate','synchronous','true','false'});count(v)

        require(type(f['capture_issues']) is dict and len(f['capture_issues'])<=32)
        for k,v in f['capture_issues'].items():
            require(k in {'snapshot_truncated','short_ethernet','unsupported_link','short_ip','ip_bounds','ip_fragments_unsupported','short_ip6','ip6_bounds','ipv6_extension_unsupported','short_tcp','tcp_bounds','tcp_overlap_conflict'});count(v)
        computed=bool(f['fixture_exit_code']==0 and f['stage']=='complete' and f['error_type'] is None and f['root_child_instrumented'] and f['bitness_confirmed'] and f['negative_encryption_observed'] and all(f['witness'].values()) and all(f['hook_checks'].values()) and f['linked_probe_requests']==2 and f['http_responses_linked']==2 and f['completed_operations']>=4 and not f['collector_errors'] and not f['dropped_events'] and not f['collector_fatal'])
        require(f['passed']==computed)
    require(r['passed']==all(f['passed'] for f in r['fixtures']))
    return r
if __name__=='__main__':
    data=json.loads(Path(sys.argv[1]).read_text());validate(data)
    dest=Path(sys.argv[2]);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(json.dumps(data,indent=2)+'\n');print('allowlisted owned-fixture summary only')
