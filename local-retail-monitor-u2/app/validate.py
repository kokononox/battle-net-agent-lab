"""Strict local-share report whitelist. Never serialize arbitrary body/header/path values."""
import ipaddress
import json
from pathlib import Path
import re
import sys

def exact(d,keys):
    if type(d) is not dict or set(d)!=set(keys.split()):raise ValueError('report_schema')
def integer(x,high=2**40):
    if type(x) is not int or not 0<=x<=high:raise ValueError('integer')
def boolean(x):
    if type(x) is not bool:raise ValueError('boolean')
def host(x):
    from core import hostname
    if x is not None and (not isinstance(x,str) or hostname(x)!=x):raise ValueError('host')
def version(v):
    exact(v,'status retail_versions')
    if v['status'] not in ('not_found','too_large','read','unreadable_or_unrecognized'):raise ValueError('version_status')
    if type(v['retail_versions']) is not list or len(v['retail_versions'])>32:raise ValueError('versions')
    for x in v['retail_versions']:
        if not re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,10}',x):raise ValueError('version')
def validate(r):
    exact(r,'schema version started_utc mode experiment selftest initial_versions final_versions user_preconditions_confirmed ready_was_announced user_final_state status error_code hosts observation limits cpu_reference_available')
    if r['schema']!='local-retail-privacy-observer-2' or r['version']!='U2':raise ValueError('schema')
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T[0-9:.]+\+00:00',r['started_utc']):raise ValueError('date')
    if r['mode'] not in ('observe_only','block_telemetry','block_one_extra'):raise ValueError('mode')
    from hosts_guard import TARGET,EXTRA_TARGETS,trial_targets
    experiment=r['experiment']
    exact(experiment,'baseline_target selected_extra_target blocked_targets resolution_after_apply resolution_before_restore dependency_result_user_reported control_caveat schedule_index window_seconds window_end_reason')
    if experiment['baseline_target']!=TARGET:raise ValueError('baseline_target')
    extra=experiment['selected_extra_target']
    if extra is not None and extra not in EXTRA_TARGETS:raise ValueError('extra_target')
    expected=[] if r['mode']=='observe_only' else list(trial_targets(extra))
    if (r['mode']=='block_one_extra')!=(extra is not None):raise ValueError('trial_mode')
    if experiment['blocked_targets']!=expected:raise ValueError('trial_targets')
    if experiment['control_caveat']!='progress_and_cache_differ_between_runs':raise ValueError('trial_caveat')
    if experiment['dependency_result_user_reported'] not in ('not_recorded','reported_progress','reported_stall','reported_error','unknown'):raise ValueError('trial_result')
    if experiment['window_end_reason'] not in ('not_started','time_limit','user_q','user_stopped_schedule'):raise ValueError('window_end')
    index=experiment['schedule_index']
    if index is None:
        if experiment['window_seconds'] is not None:raise ValueError('schedule_window')
    else:
        integer(index,7)
        if index<1 or experiment['window_seconds']!=120:raise ValueError('schedule_window')
        from monitor import schedule_plan
        if extra!=schedule_plan()[index-1] or r['mode']=='observe_only':raise ValueError('schedule_target')
    for key in ('resolution_after_apply','resolution_before_restore'):
        states=experiment[key]
        if type(states) is not dict or (states and set(states)!=set(expected)):raise ValueError('trial_resolution')
        if any(s not in ('loopback_only','public_only','other_or_failed','timeout') for s in states.values()):raise ValueError('trial_resolution')
    if r['ready_was_announced'] and r['mode']!='observe_only' and (
        set(experiment['resolution_after_apply'])!=set(expected) or
        any(s!='loopback_only' for s in experiment['resolution_after_apply'].values())):raise ValueError('unblocked_trial_ready')
    for k in ('user_preconditions_confirmed','ready_was_announced','cpu_reference_available'):boolean(r[k])
    if r['user_final_state'] not in ('not_recorded','reported_finished','reported_paused','reported_error_or_stopped','unknown'):raise ValueError('user_state')
    if r['status'] not in ('not_started','waiting_for_agent','observing','observation_ended','interrupted','stopped'):raise ValueError('status')
    if r['error_code'] is not None and not re.fullmatch('[a-z0-9_]{1,100}',r['error_code']):raise ValueError('error')
    s=r['selftest'];exact(s,'passed loopback_only send_observed wsasend_observed sspi_negative_input_observed fixture_excluded_from_real_report worker_exited script_errors error_code')
    for k in set(s)-{'script_errors','error_code'}:boolean(s[k])
    integer(s['script_errors'])
    if s['error_code'] is not None and not re.fullmatch('[a-z0-9_]{1,100}',s['error_code']):raise ValueError('selftest_error')
    if not s['passed'] or not all(s[k] for k in ('loopback_only','send_observed','wsasend_observed','sspi_negative_input_observed','fixture_excluded_from_real_report','worker_exited')) or s['script_errors']:raise ValueError('selftest_false_pass')
    version(r['initial_versions'])
    if r['final_versions'] is not None:version(r['final_versions'])
    h=r['hosts'];exact(h,'changed_by_tool restored restore_status resolution_after_apply resolution_at_end')
    boolean(h['changed_by_tool']);boolean(h['restored'])
    if h['restore_status'] not in ('not_needed','already_original','restored_exactly','needs_manual_attention_journal_kept'):raise ValueError('restore_status')
    for k in ('resolution_after_apply','resolution_at_end'):
        if h[k] not in ('not_tested','public_only','loopback_only','other_or_failed','timeout'):raise ValueError('resolution')
    if r['mode']=='observe_only' and h['changed_by_tool']:raise ValueError('observe_mutated_hosts')
    if r['ready_was_announced'] and r['mode']!='observe_only' and (not h['changed_by_tool'] or h['resolution_after_apply']!='loopback_only'):raise ValueError('unblocked_ready')
    from monitor import LIMITS
    if r['limits']!=LIMITS:raise ValueError('limits')
    o=r['observation']
    if o is None:
        if r['ready_was_announced']:raise ValueError('ready_without_observation')
        return r
    exact(o,'processes events aggregate_inputs public_tcp_destinations sampler_errors limits_hit sampling_thread_stopped')
    if type(o['processes']) is not list or len(o['processes'])>64:raise ValueError('processes')
    indices=set()
    from core import NAMES,APIS,HOOKS
    for p in o['processes']:
        exact(p,'index pid process_name sha256 authenticode_valid blizzard_publisher status hook_ready installed_hooks script_errors input_events hook_limit_hit late_attach error_code')
        integer(p['index'],64);integer(p['pid'],2**32-1);indices.add(p['index'])
        if p['process_name'] not in NAMES:raise ValueError('name')
        if p['sha256'] is not None and not re.fullmatch('[a-f0-9]{64}',p['sha256']):raise ValueError('image_hash')
        for k in ('authenticode_valid','blizzard_publisher','hook_ready','hook_limit_hit','late_attach'):boolean(p[k])
        for k in ('script_errors','input_events'):integer(p[k])
        if p['status'] not in ('checking','attached','not_attached'):raise ValueError('process_status')
        if p['error_code'] is not None and not re.fullmatch('[a-z_]{1,80}',p['error_code']):raise ValueError('process_error')
        if type(p['installed_hooks']) is not list or not set(p['installed_hooks'])<=HOOKS:raise ValueError('hooks')
        if p['status']=='attached' and not (p['authenticode_valid'] and p['blizzard_publisher'] and p['sha256'] and p['hook_ready']):raise ValueError('unverified_attach')
    if len(indices)!=len(o['processes']):raise ValueError('duplicate_process')
    if type(o['events']) is not list or len(o['events'])>2048:raise ValueError('events')
    from body_meta import FIELD_ALIASES,FORMATS
    for e in o['events']:
        exact(e,'elapsed_seconds phase process_index api host_hint host_evidence declared_bytes observed_prefix_bytes truncated return_code accepted_bytes local_api_success reference_cpu_literal_match format field_name_hints')
        if type(e['elapsed_seconds']) not in (int,float) or not 0<=e['elapsed_seconds']<=10**6:raise ValueError('time')
        if e['phase'] not in ('before_user_update','user_update_window') or e['process_index'] not in indices or e['api'] not in APIS:raise ValueError('event_source')
        host(e['host_hint'])
        if e['host_evidence'] not in ('same_buffer_header','channel_history_hint','unavailable'):raise ValueError('host_evidence')
        integer(e['declared_bytes'],16777216);integer(e['observed_prefix_bytes'],16384)
        if type(e['return_code']) is not int or not -2**31<=e['return_code']<2**31:raise ValueError('return')
        if e['accepted_bytes'] is not None:integer(e['accepted_bytes'],16777216)
        boolean(e['truncated']);boolean(e['local_api_success'])
        if e['reference_cpu_literal_match'] is not None:boolean(e['reference_cpu_literal_match'])
        if e['format'] not in FORMATS or type(e['field_name_hints']) is not list or not set(e['field_name_hints'])<=set(FIELD_ALIASES.values()):raise ValueError('format')
    if type(o['aggregate_inputs']) is not list or len(o['aggregate_inputs'])>10000:raise ValueError('aggregates')
    for a in o['aggregate_inputs']:
        exact(a,'host_hint api local_api_success cpu_literal_match input_events');host(a['host_hint'])
        if a['api'] not in APIS:raise ValueError('api')
        boolean(a['local_api_success']);boolean(a['cpu_literal_match']);integer(a['input_events'])
    if type(o['public_tcp_destinations']) is not list or len(o['public_tcp_destinations'])>1024:raise ValueError('flows')
    for f in o['public_tcp_destinations']:
        exact(f,'process_index remote_address remote_port sample_observations')
        if f['process_index'] not in indices or not ipaddress.ip_address(f['remote_address']).is_global:raise ValueError('flow_source')
        integer(f['remote_port'],65535);integer(f['sample_observations'])
    integer(o['sampler_errors']);boolean(o['sampling_thread_stopped'])
    exact(o['limits_hit'],'event_detail flows processes hooks')
    for v in o['limits_hit'].values():boolean(v)
    return r
if __name__=='__main__':
    p=Path(sys.argv[1]);r=json.loads(p.read_text(encoding='utf-8'));validate(r);print('VALID')
