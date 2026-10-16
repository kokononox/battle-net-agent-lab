"""Pinned Agent 9824 publication/lock byte receipts; no executable execution.
A narrow static path audit, NOT a writer, runtime trace, or storage guarantee.
"""
import argparse,json
from pathlib import Path
import agent_activation_audit as base
import agent_static_audit as identity
import patch_audit as a
import source_binding as binding

ANCHORS={
 'control_object_output':(0x71c620,'8d4f38'),
 'control_output_argument':(0x71c652,'51ff77045250ff37'),
 'control_wrapper_forward_output':(0x71e0bd,'ff7518'),
 'bulk_mode2_reject':(0x71bb99,'837b2c02'),
 'bulk_mode4_reject':(0x71bbac,'837b2c04'),
 'bulk_outer_lock_object':(0x71bbb6,'8d43708bc88985e0feffff'),
 'bulk_bucket_lock_array':(0x71bbdd,'8d83200600008d04b050'),
 'bulk_bucket_lock_count':(0x71bbff,'4683fe10'),
 'bulk_publish_args':(0x71bdfe,'ff76048bcbff3657'),
 'publish_output_local':(0x71c11e,'8365fc008d45fc'),
 'publish_table_object':(0x71c133,'6bc7508d8b94000000052001000003c35057'),
 'publish_result_test':(0x71c14c,'85f6'),
 'header_sequence_store':(0x71c178,'8b4b388b45fc8984b91001000033c0'),
 'cache_sequence_store_before_bind':(0x71e958,'8b008944fb0c'),
 'bind_result_test':(0x71e984,'85f6'),
 'refresh_mode_skips':(0x71c55b,'837e2c02'),
 'refresh_header_sequence_read':(0x71c56d,'8b55088b46388b8c9010010000'),
 'refresh_cached_sequence_compare':(0x71ec9b,'8b44cb0c898dccfcffff3bc7'),
 'refresh_equal_zero':(0x71eca9,'33c0'),
 'refresh_backward_error':(0x71eccc,'33c083c41c40'),
 'lock_mode_dispatch':(0x722362,'803900'),
 'wait_infinite_handle':(0x72219d,'6affff7104'),
 'wait_abandoned_compare':(0x7221ac,'3d80000000'),
 'wait_failure_false':(0x7221fe,'32c0c3'),
 'wait_success_or_abandoned_true':(0x72221c,'b001c3'),
 'unlock_mode_dispatch':(0x7223f6,'803900'),
 'bulk_unlock_array':(0x71b8a2,'8b07052006000003c650'),
 'bulk_unlock_count':(0x71b8b1,'83c6045983fe40'),
 'helper_output_before_rename':(0x71f27a,'8b8dd4fbffff50ff750c8901'),
 'helper_error_accumulator_init':(0x71f26b,'33ff'),
 'helper_error_accumulator_set':(0x71f305,'8bf8'),
 'helper_return_accumulator':(0x71f342,'8bc75f'),
}
CALLS={
 'open_control_wrapper':(0x71c65a,0x71e0a2),
 'open_control_bind':(0x71e0d3,0x71e0dd),
 'bulk_outer_lock':(0x71bbc1,0x722362),
 'bulk_bucket_lock':(0x71bbe7,0x8660ec),
 'bulk_refresh':(0x71bbf0,0x71c555),
 'bulk_publish':(0x71be06,0x71c119),
 'bulk_unlock_all':(0x71be47,0x71b87a),
 'bulk_outer_unlock':(0x71be59,0x7223f6),
 'unlock_array_element':(0x71b8ac,0x86610a),
 'publish_orchestrator':(0x71c145,0x71e887),
 'orchestrator_flush':(0x71e93c,0x71f1f1),
 'orchestrator_bind':(0x71e97d,0x72b84f),
 'refresh_by_sequence':(0x71c58d,0x71ec75),
 'refresh_filename_builder':(0x71ecde,0x71f0d3),
 'local_outer_enter':(0x72236f,0x773690),
 'named_outer_release':(0x7223ff,0x86dda5),
 'local_outer_leave':(0x72240a,0x7736d0),
}
# Expected opcode and exact destination are checked, not just nearby bytes.
BRANCHES={
 'publish_only_on_zero':(0x71c14e,'74',0x71c178),
 'publish_error_bypasses_store':(0x71c176,'eb',0x71c187),
 'helper_error_bypasses_cache_bind':(0x71e948,'75',0x71e9ac),
 'bind_zero_returns':(0x71e986,'74',0x71e9ac),
 'cached_equal_no_open':(0x71eca7,'75',0x71ecb0),
 'cached_not_greater_open':(0x71ecb1,'76',0x71ecd7),
 'named_lock_dispatch':(0x722365,'0f85',0x72219d),
 'named_wait_object_success':(0x7221aa,'74',0x72221c),
 'named_wait_abandoned_logged':(0x7221b1,'74',0x722201),
 'local_unlock_dispatch':(0x7223f9,'74',0x722406),
 'rename_success_returns_accumulator':(0x71f2bb,'0f84',0x71f342),
 'bulk_acquire_loop':(0x71bc03,'72',0x71bbdd),
 'bulk_release_loop':(0x71b8b8,'72',0x71b8a2),
}
IAT_CALLS={
 'bucket_enter':(0x8660f2,0x8fb3b0,'AcquireSRWLockExclusive'),
 'bucket_leave':(0x866110,0x8fb3a8,'ReleaseSRWLockExclusive'),
 'named_wait':(0x7221a2,0x8fb254,'WaitForSingleObject'),
 'named_release':(0x86ddad,0x8fb56c,'ReleaseMutex'),
 'local_enter':(0x773696,0x8fb358,'EnterCriticalSection'),
 'local_leave':(0x7736d6,0x8fb35c,'LeaveCriticalSection'),
}

def branch_target(pe,va,opcode):
    a.require(opcode in ('74','75','76','72','eb','0f84','0f85'),'publication_branch_opcode_config')
    op=bytes.fromhex(opcode);width=4 if len(op)==2 else 1
    raw=pe.read(va,len(op)+width)
    a.require(raw[:len(op)]==op,'publication_branch_opcode')
    return va+len(raw)+int.from_bytes(raw[len(op):],'little',signed=True)

def verify(pe):
    anchors={};calls={};branches={};apis={};imports=pe.imports()
    for name,(va,h) in ANCHORS.items():
        want=bytes.fromhex(h);a.require(pe.read(va,len(want))==want,'publication_anchor_'+name);anchors[name]=hex(va)
    for name,(va,target) in CALLS.items():
        a.require(pe.relcall(va)==target,'publication_call_'+name);calls[name]={'call':hex(va),'target':hex(target)}
    for name,(va,opcode,target) in BRANCHES.items():
        a.require(branch_target(pe,va,opcode)==target,'publication_branch_'+name);branches[name]={'instruction':hex(va),'opcode':opcode,'target':hex(target)}
    for name,(va,iat,symbol) in IAT_CALLS.items():
        a.require(pe.read(va,6)==b'\xff\x15'+iat.to_bytes(4,'little'),'publication_iat_opcode_'+name)
        entry=imports.get(iat);a.require(entry is not None and entry['name']==symbol and entry['dll'].lower()=='kernel32.dll','publication_iat_symbol_'+name)
        apis[name]={'call':hex(va),'iat':hex(iat),**entry}
    return {'anchors':anchors,'direct_calls':calls,'conditional_or_jump_edges':branches,'import_calls':apis}

def analyze(raw):
    a.require(isinstance(raw,bytes) and len(raw)<=8*1024**2,'publication_agent_size')
    a.require(a.sha256(raw)==identity.AGENT_SHA256,'publication_pinned_agent_sha256')
    previous=base.analyze(raw);evidence=verify(base.PE(raw))
    return {'format':'agent-9824-publication-static-1','agent_sha256':identity.AGENT_SHA256,
      'status':'bounded_publication_paths_verified','prerequisite_mapping_audit_passed':previous['status']=='bounded_static_paths_verified',
      'binary_executed':False,'network_requests':0,'game_or_lab_written':False,'evidence':evidence,
      'activation_contract_complete':False,'installation_ready':False,
      'limitations':['Byte/branch receipts are not a whole-program CFG or runtime trace',
       'Outer lock mode is runtime-dependent; no proof a particular installation selects named mutex mode',
       'No process-shared SRW lock claim, no Windows execution or power-loss proof',
       'No full payload/extension layout, .build.info writer, or complete-build activation proof',
       'No real user shmem in fixture; no live installation observed']}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--agent',required=True,type=Path);args=p.parse_args()
    w=binding.Watch();raw=w.read(args.agent,8*1024**2);got=analyze(raw);w.check();print(json.dumps(got,indent=2))
if __name__=='__main__':main()
