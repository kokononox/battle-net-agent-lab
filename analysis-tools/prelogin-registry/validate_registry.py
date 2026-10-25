"""Strict public allowlist: no identifiers, identifier hashes, arbitrary names or paths."""
import json,re,sys
from pathlib import Path
from registry_events import APIS
PIN='b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5'
PROBE={'architecture','passed','exit_code','instrumented','bitness_confirmed','read_a','read_w','get_w','write_w','size_only_not_uuid','errors','limits'}
PHASE={'ready_processes','installed_apis','errors','limits','records','phase','wire_linked_hardware_requests','all_processes_registry_ready','wire_collector_clean'}
RECORD={'api','operation','status','value_type','caller_rva','process_sha256','valid_uuid','equals_wire_host_id'}
LIMITS=dict(raw_values_exported=False,identifier_hashes_exported=False,target_registry_modified_by_observer=False,login_performed=False,install_action_requested=False,game_download_requested=False,tls_validation_changed=False,provider_assignment_causality_proven=False,reboot_tested=False,reinstall_tested=False,global_install_uniqueness_proven=False,server_storage_proven=False)
def blank(source,run):return dict(schema='bnet-registry-trace-1',source_commit=source,run_id=run,status='stopped',native_gate=[],baseline_before_target=None,baseline_after_target=None,target_launched=False,lifecycle_comparison=None,phases=[],registry_read_equals_wire_host_id=False,successful_matching_write_observed=False,limits=dict(LIMITS))
def boolean(x):
    if type(x) is not bool:raise ValueError('boolean')
def number(x,maximum=100000):
    if type(x) is not int or not 0<=x<=maximum:raise ValueError('number')
def validate(r):
    if type(r) is not dict or set(r)!=set(blank('','')) or r['schema']!='bnet-registry-trace-1':raise ValueError('schema')
    if not isinstance(r['source_commit'],str) or not re.fullmatch('[a-f0-9]{40}',r['source_commit']):raise ValueError('source')
    if not isinstance(r['run_id'],str) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('run')
    if r['status'] not in ('stopped','native_gate_failed_no_target','baseline_failed_no_target','inconclusive','observation_complete'):raise ValueError('status')
    if r['limits']!=LIMITS or any(type(v) is not bool for v in r['limits'].values()):raise ValueError('limits')
    for k in ('target_launched','registry_read_equals_wire_host_id','successful_matching_write_observed'):boolean(r[k])
    if r['lifecycle_comparison'] is not None:boolean(r['lifecycle_comparison'])
    for b in ('baseline_before_target','baseline_after_target'):
        x=r[b]
        if x is None:continue
        if type(x) is not dict or set(x)!={'status','value_present','valid_uuid'}:raise ValueError('baseline')
        for k in ('value_present','valid_uuid'):boolean(x[k])
        if x['status'] not in ('absent','present','error') or x['value_present']!=(x['status']=='present') or (x['valid_uuid'] and not x['value_present']):raise ValueError('baseline_status')
    if type(r['native_gate']) is not list or len(r['native_gate'])>2:raise ValueError('gate')
    for i,x in enumerate(r['native_gate']):
        if type(x) is not dict or set(x)!=PROBE or x['architecture']!=('x64','x86')[i]:raise ValueError('probe')
        for k in PROBE-{'architecture','exit_code','errors','limits'}:boolean(x[k])
        for k in ('errors','limits'):number(x[k])
        if x['exit_code'] is not None:number(x['exit_code'],0xffffffff)
        if x['passed'] and not(x['exit_code']==0 and x['errors']==x['limits']==0 and all(x[k] for k in PROBE-{'architecture','exit_code','errors','limits'})):raise ValueError('probe_gate')
    if type(r['phases']) is not list or len(r['phases'])>2:raise ValueError('phases')
    for i,p in enumerate(r['phases']):
        if type(p) is not dict or set(p)!=PHASE or p['phase']!=('first','second')[i]:raise ValueError('phase')
        for k in ('ready_processes','errors','limits','wire_linked_hardware_requests'):number(p[k])
        for k in ('all_processes_registry_ready','wire_collector_clean'):boolean(p[k])
        if type(p['installed_apis']) is not list or len(p['installed_apis'])>len(APIS) or not set(p['installed_apis'])<=APIS:raise ValueError('apis')
        if type(p['records']) is not list or len(p['records'])>2048:raise ValueError('records')
        for x in p['records']:
            if type(x) is not dict or set(x)!=RECORD:raise ValueError('record')
            if x['api'] not in APIS or x['operation'] not in ('read','write'):raise ValueError('operation')
            if x['operation']!=('write' if x['api'].startswith('RegSetValueEx') else 'read'):raise ValueError('api_operation')
            number(x['status'],65535)
            for k in ('value_type','caller_rva'):
                if x[k] is not None:number(x[k],0xffffffff)
            if not isinstance(x['process_sha256'],str) or not re.fullmatch('[a-f0-9]{64}',x['process_sha256']):raise ValueError('image_hash')
            for k in ('valid_uuid','equals_wire_host_id'):boolean(x[k])
            if x['valid_uuid'] and not(x['status']==0 and x['value_type']==1):raise ValueError('uuid')
            if x['equals_wire_host_id'] and not x['valid_uuid']:raise ValueError('equality')
    clean=r['status']=='observation_complete'
    if clean:
        if len(r['native_gate'])!=2 or not all(x['passed'] for x in r['native_gate']) or len(r['phases'])!=2 or r['lifecycle_comparison'] is None or not r['target_launched']:raise ValueError('gate_missing')
        if r['baseline_before_target'] is None or r['baseline_before_target']['status']=='error':raise ValueError('baseline_missing')
        if not all(p['errors']==p['limits']==0 and p['ready_processes']>0 and p['all_processes_registry_ready'] and p['wire_collector_clean'] and p['wire_linked_hardware_requests']>0 for p in r['phases']):raise ValueError('collector')
        eq=all(any(x['operation']=='read' and x['status']==0 and x['equals_wire_host_id'] and x['process_sha256']==PIN for x in p['records']) for p in r['phases'])
        wr=any(x['operation']=='write' and x['status']==0 and x['equals_wire_host_id'] for p in r['phases'] for x in p['records'])
        if r['registry_read_equals_wire_host_id']!=eq or r['successful_matching_write_observed']!=wr:raise ValueError('claims')
    elif r['registry_read_equals_wire_host_id'] or r['successful_matching_write_observed']:raise ValueError('partial_claim')
    return r

def load(raw):
    if len(raw)>262144:raise ValueError('size')
    def pairs(items):
        d={}
        for k,v in items:
            if k in d:raise ValueError('duplicate')
            d[k]=v
        return d
    return validate(json.loads(raw,object_pairs_hook=pairs))
if __name__=='__main__':
    src,dst=map(Path,sys.argv[1:]);r=load(src.read_bytes());dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text(json.dumps(r,indent=2)+'\n')
