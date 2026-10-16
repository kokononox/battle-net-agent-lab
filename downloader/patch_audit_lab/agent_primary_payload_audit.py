"""Pinned static receipts for primary arrays, rollback and path normalization.
Never executes the PE. Static geometry is not a Windows/activation test.
"""
import argparse,json
from pathlib import Path
import agent_activation_audit as base
import agent_binding_extension_audit as prior
import agent_static_audit as identity
import agent_publication_audit as edges
import patch_audit as a
import source_binding as binding
ANCHORS={
 'bound_primary_pointer':(0x71e280,'89378b860c01000003c6894704'),
 'path_string_output':(0x71c32b,'8d460c50ff7508'),
 'object_control_output':(0x7120c9,'8d4748'),
 'primary_pointer_consumer':(0x7114f3,'8b464c8bc88945d0'),
 'consumer_rebuild_arrays':(0x71169b,'ff75d48b4dd0ff75f0'),
 'rebuild_capacity':(0x722c3c,'b842040000'),
 'rebuild_mark_zero':(0x722c6b,'832600'),
 'rebuild_fence_one':(0x722c8d,'0faef0c70601000000'),
 'append_array_a':(0x722def,'6b430405'),
 'append_array_a_base':(0x722df7,'83c02003c3'),
 'append_array_b_base':(0x722e0c,'056a15000003c3'),
 'append_increment_count':(0x722e1e,'ff4304'),
 'reset_leaves_word_c':(0x722e28,'33c0890189410489410889411089411489411889411cc3'),
 'recovery_only_two':(0x722e42,'833e02'),
 'recovery_index':(0x722e4a,'6b460805'),
 'recovery_b_base':(0x722e53,'056a15000003c6'),
 'recovery_a_base':(0x722e6c,'83c02003c6'),
 'recovery_state_one':(0x722e77,'0faef0c70601000000'),
 'save_index':(0x722e9e,'894308'),
 'save_old_b':(0x722eac,'89431003f3895314'),
 'save_old_a':(0x722ebf,'894318ff751489531c'),
 'before_writes_state_two':(0x722ec8,'0faef06a05c70302000000560faef0'),
 'after_writes_state_one':(0x722eed,'0faef0c703010000000faef0'),
 'read_big_endian_loop':(0x722f20,'0fb6041f0fa4ce0899c1e1080bf20bc847'),
 'write_big_endian_loop':(0x7100e7,'88160facc208c1e8084e83e901'),
 'normalize_drive_shape':(0x863ae0,'807e013a751a807e022f7514'),
 'normalize_drive_lowercase':(0x863aec,'8d51bf8d412080fa190fb6c90fb6c00f46c8880e'),
}
CALLS={
 'index_path_init':(0x71c332,0x712bc9),
 'control_binding_wrapper':(0x71e0d3,0x71e0dd),
 'absolute_normalizer':(0x67a5e4,0x86398b),
 'control_output_init':(0x7120fc,0x71e0a2),
 'primary_consumer_state':(0x7114fb,0x71db05),
 'primary_consumer_rebuild':(0x7116a4,0x722bd6),
 'build_first_pass':(0x722c37,0x722ca3),
 'build_second_pass':(0x722c84,0x722ca3),
 'append_write_a':(0x722dfd,0x7100d0),
 'append_write_b':(0x722e16,0x7100d0),
 'recover_write_b':(0x722e5b,0x7100d0),
 'recover_write_a':(0x722e72,0x7100d0),
 'save_read_b':(0x722ea4,0x722f00),
 'save_read_a':(0x722eb7,0x722f00),
 'update_write_a':(0x722ed7,0x7100d0),
 'update_write_b':(0x722ee5,0x7100d0),
 'caller_recover':(0x722b29,0x722e3f),
 'path_rooted_predicate':(0x712be6,0x8637d1),
 'path_absolute_normalizer_wrapper':(0x712bf8,0x67a5d6),
 'path_relative_cwd':(0x712c08,0x69834c),
 'path_relative_join_wrapper':(0x712c57,0x50045e),
 'path_assign':(0x712c7b,0x86a429),
 'path_join':(0x50046f,0x86367d),
 'join_normalizer':(0x863702,0x86398b),
}

BRANCHES={
 'recovery_not_two_skip':(0x722e45,'75',0x722e86),
 'caller_not_two_skip':(0x722b25,'75',0x722b34),
 'path_not_rooted_use_cwd':(0x712bee,'74',0x712c01),
}
IAT_CALLS={'current_directory':(0x86493e,0x8fb508,'GetCurrentDirectoryW')}

def verify(pe):
    result={k:{} for k in ('anchors','direct_calls','branch_edges','import_calls')}
    for name,(va,h) in ANCHORS.items():
        want=bytes.fromhex(h);a.require(pe.read(va,len(want))==want,'primary_anchor_'+name);result['anchors'][name]=hex(va)
    for name,(va,target) in CALLS.items():
        a.require(pe.relcall(va)==target,'primary_call_'+name);result['direct_calls'][name]={'call':hex(va),'target':hex(target)}
    for name,(va,op,target) in BRANCHES.items():
        a.require(edges.branch_target(pe,va,op)==target,'primary_branch_'+name);result['branch_edges'][name]={'instruction':hex(va),'target':hex(target)}
    imports=pe.imports()
    for name,(va,iat,symbol) in IAT_CALLS.items():
        a.require(pe.read(va,6)==b'\xff\x15'+iat.to_bytes(4,'little'),'primary_iat_opcode_'+name)
        entry=imports.get(iat);a.require(entry is not None and entry['name']==symbol and entry['dll'].lower()=='kernel32.dll','primary_iat_symbol_'+name)
        result['import_calls'][name]={'call':hex(va),'iat':hex(iat),**entry}
    return result

def analyze(raw):
    a.require(isinstance(raw,bytes) and len(raw)<=8*1024**2,'primary_agent_size')
    a.require(a.sha256(raw)==identity.AGENT_SHA256,'primary_pinned_agent_sha256')
    previous=prior.analyze(raw)
    return {'format':'agent-9824-primary-static-1','agent_sha256':identity.AGENT_SHA256,
      'status':'bounded_primary_paths_verified','prerequisite_binding_extension_passed':previous['status']=='bounded_binding_extension_paths_verified',
      'evidence':verify(base.PE(raw)),'agent_executed':False,'network_requests':0,
      'game_or_lab_written':False,'actual_user_shmem_tested':False,
      'allocation_semantics_complete':False,'activation_contract_complete':False,'installation_ready':False,
      'limitations':['No actual installation snapshot or Windows test',
        'Path normalizer statically traced, not a complete compatible port or actual name binding',
        'State 1 alone is not health; state 2 recovery stores are not a durable transaction proof',
        'Array names A/B intentionally avoid overclaiming complete allocation semantics',
        '.build.info writer, full target closure and power-loss behavior remain unproved']}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--agent',required=True,type=Path);args=p.parse_args()
    w=binding.Watch();raw=w.read(args.agent,8*1024**2);got=analyze(raw);w.check();print(json.dumps(got,indent=2))
if __name__=='__main__':main()
