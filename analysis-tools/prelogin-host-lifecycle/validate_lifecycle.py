"""Fail-closed export schema. Only equality, counters, fixed labels and code provenance."""
import json,re,sys
from pathlib import Path
TOP={'schema','source_commit','run_id','status','error_code','first_native_gate_passed','same_machine','configuration_preserved','second_start_clean_processes','comparison','phases','second_diagnostics','storage_scans','limits'}
PHASE={'launched','completed','bootstrap_pin_match','instrumented_processes','collector_errors','dropped_events','collector_fatal','request_count','hardware_requests','wire_linked_hardware_requests','host_id_observations','host_id_unique','invalid_host_id_events','all_processes_instrumented','language_status'}
LIMITS={'raw_values_exported':False,'identifier_hashes_exported':False,'login_performed':False,'game_download_requested':False,'install_action_requested':False,'tls_validation_changed':False,'reboot_tested':False,'reinstall_tested':False,'clean_machine_comparison_tested':False,'account_linkage_proven':False,'game_file_marking_proven':False,'server_storage_proven':False,'configuration_storage_location_proven':False,'persistent_hardware_id_proven':False}
BOOL={'launched','completed','bootstrap_pin_match','collector_fatal','all_processes_instrumented'}
def validate(r):
    if type(r) is not dict or set(r)!=TOP or r['schema']!='bnet-host-lifecycle-6':raise ValueError('schema')
    if type(r['source_commit']) is not str or not re.fullmatch('[a-f0-9]{40}',r['source_commit']):raise ValueError('source')
    if type(r['run_id']) is not str or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('run')
    if r['status'] not in ('stopped','inconclusive','same_host_id_after_process_restart','changed_host_id_after_process_restart'):raise ValueError('status')
    if r['error_code'] not in (None,'bounded_lifecycle_failed','first_phase_ineligible','second_phase_ineligible'):raise ValueError('error')
    for k in ('first_native_gate_passed','same_machine','configuration_preserved','second_start_clean_processes'):
        if type(r[k]) is not bool:raise ValueError('boolean')
    if r['limits']!=LIMITS or any(type(v) is not bool for v in r['limits'].values()):raise ValueError('limits')
    if r['comparison'] is not None and type(r['comparison']) is not bool:raise ValueError('comparison')
    if type(r['phases']) is not list or len(r['phases'])>2:raise ValueError('phases')
    for p in r['phases']:
        if type(p) is not dict or set(p)!=PHASE:raise ValueError('phase_schema')
        for k in BOOL:
            if type(p[k]) is not bool:raise ValueError('phase_boolean')
        for k in PHASE-BOOL-{'language_status'}:
            if type(p[k]) is not int or not 0<=p[k]<=100000:raise ValueError('counter')
        # Fixed language states, not GUI text or exception content.
        if p['language_status'] not in ('not_observed','continued','not_language_page','other'):raise ValueError('language')
        if not p['wire_linked_hardware_requests']<=p['hardware_requests']<=p['request_count']:raise ValueError('requests')
        if p['host_id_unique']>p['host_id_observations']:raise ValueError('unique')
        if (p['collector_errors'] or p['dropped_events'] or p['collector_fatal']) and p['wire_linked_hardware_requests']:raise ValueError('incomplete_wire_claim')
    from storage_scan import validate as validate_storage
    if type(r['storage_scans']) is not list or len(r['storage_scans'])>2:raise ValueError('storage_scans')
    for i,scan in enumerate(r['storage_scans']):
        validate_storage(scan)
        if scan['phase']!=('after_first','after_second')[i]:raise ValueError('storage_scan_order')
    from phase_diagnostics import validate_debug
    validate_debug(r['second_diagnostics'])
    ds=r['second_diagnostics']['processes']
    if len(r['phases'])==2:
        p=r['phases'][1]
        if len(ds)!=p['instrumented_processes'] or sum(x['script_errors'] for x in ds)!=p['collector_errors']:raise ValueError('debug_crossfoot')
        if p['all_processes_instrumented']!=(bool(ds) and all(x['instrumented_before_resume'] for x in ds)):raise ValueError('debug_instrumentation')
    elif ds:raise ValueError('debug_without_second_phase')
    if r['comparison'] is not None:
        if any(not p['approved'] for p in r['second_diagnostics']['helper_decisions']):raise ValueError('failed_helper_policy')
        if r['second_diagnostics']['refused_image'] is not None or r['second_diagnostics']['refusal_reason'] is not None:raise ValueError('refused_child_comparison')
        if r['second_diagnostics']['stage']!='complete' or r['second_diagnostics']['error_type'] is not None:raise ValueError('second_diagnostic_gate')
        from identity_compare import eligible
        if len(r['phases'])!=2 or not all(eligible(p) for p in r['phases']) or not all(r[k] for k in ('first_native_gate_passed','same_machine','configuration_preserved','second_start_clean_processes')):raise ValueError('comparison_gate')
        expected='same_host_id_after_process_restart' if r['comparison'] else 'changed_host_id_after_process_restart'
        if r['status']!=expected or r['error_code'] is not None:raise ValueError('verdict')
    elif r['status'] not in ('stopped','inconclusive'):raise ValueError('unproven_verdict')
    return r

def load(raw):
    if len(raw)>16384:raise ValueError('size')
    def pairs(items):
        d={}
        for k,v in items:
            if k in d:raise ValueError('duplicate')
            d[k]=v
        return d
    return validate(json.loads(raw,object_pairs_hook=pairs))
if __name__=='__main__':
    src,dst=map(Path,sys.argv[1:]);r=load(src.read_bytes());dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text(json.dumps(r,indent=2)+'\n')
