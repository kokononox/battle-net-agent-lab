"""Pinned control name, guard-mode and extension-directory receipts; static only."""
import argparse,json
from pathlib import Path
import agent_activation_audit as base
import agent_publication_audit as previous
import agent_static_audit as identity
import patch_audit as a
import source_binding as binding
ANCHORS={
 'mode5_compare':(0x71c6e0,'837f2c05'),
 'mode4_compare':(0x71c6e9,'837f2c04'),
 'other_mode_named':(0x71c6ed,'8885e8feffff'),
 'mode45_local':(0x71c6f5,'c685e8feffff00'),
 'name_from_control':(0x71c6fc,'8d410850ffb5e8feffff8d77708bce'),
 'guard_arg_low_byte':(0x72237d,'8a4508c6412001880184c0'),
 'guard_name_forward':(0x72238a,'ff750c'),
 'create_not_initial_owner':(0x7222b5,'ff75ec8d45dc5350'),
 'open_fallback_rights':(0x7222d3,'ff75ec536800001000'),
 'fallback_access_denied':(0x7222ce,'83f905'),
 'fallback_not_found':(0x7222ed,'83f902'),
 'fallback_retry_limit':(0x7222f9,'83f805'),
 'name_literal_Global_backslash':(0x71e034,'c745f4476c6f6266c745f8616cc645fa5c'),
 'name_limit_including_prefix':(0x71e045,'8d41078945fc3dff000000'),
 'name_copy_prefix':(0x71e087,'a55066a5a4'),
 'name_terminator':(0x71e091,'8b45fc83c40c5fc6041800'),
 'v5_extra_flag_clear_low':(0x71deed,'83e0fe'),
 'v5_declared_header_154':(0x71def0,'be54010000b95802000089b5a8fdffff'),
 'v5_copy_size_cmov':(0x71df00,'0f45f1'),
 'v5_header_copy_size_argument':(0x71df8d,'5651'),
 'v5_directory_initial_zero':(0x71ded3,'b858020000508d85a4fdffff6a0050'),
 'extension_base_sum':(0x71dfbd,'8b820c010000ff3203820801000050'),
 'extension_flag_gate':(0x71dfd9,'8b4804d1e9f6c101'),
 'extension_requested_gate':(0x71dfe3,'f6400801'),
 'extension_slot_zero':(0x71dfe9,'33c9410fbcc1'),
 'extension_size_array':(0x71dfef,'c784825801000028020000'),
 'extension_offset_array':(0x71dffa,'89b482d8010000'),
 'extension_bitmap':(0x71e001,'8d8628020000098a54010000'),
 'diagnostic_flag2':(0x71dc59,'8b985001000057f6c302'),
 'diagnostic_bitmap0':(0x71dc65,'f6805401000001'),
 'diagnostic_extension_pointer':(0x71dc76,'8b8c82d801000003ca'),
 'diagnostic_known_states':(0x71db05,'33c04039017407833902740232c0c3'),
}
CALLS={
 'guard_init':(0x71c711,0x722378),
 'guard_create':(0x72238d,0x72221f),
 'v4_name_builder':(0x71de28,0x71e01f),
 'v5_name_builder':(0x71df36,0x71e01f),
 'name_copy':(0x71e08c,0x879790),
 'v5_extension_builder':(0x71df76,0x71dfb6),
 'extension_base_align':(0x71dfcc,0x71dd00),
 'extension_final_align':(0x71e010,0x71dd00),
 'extension_diagnostic_state':(0x71dc7f,0x71db05),
}
BRANCHES={
 'mode5_local':(0x71c6e7,'74',0x71c6f5),
 'mode_not4_named':(0x71c6f3,'75',0x71c6fc),
 'guard_false_local':(0x722388,'74',0x722398),
 'name_bounded':(0x71e050,'76',0x71e075),
 'create_access_denied_only':(0x7222d1,'75',0x72232c),
 'extension_no_flag':(0x71dfe1,'74',0x71e01a),
 'extension_no_request':(0x71dfe7,'74',0x71e01a),
}
IAT_CALLS={
 'create_mutex':(0x7222bd,0x8fb438,'CreateMutexW'),
 'open_mutex':(0x7222dc,0x8fb43c,'OpenMutexW'),
}

def verify(pe):
    # Same verifier machinery as previous checkpoint, with this profile passed
    # explicitly; no monkeypatch/global mutation and no Agent execution.
    result={k:{} for k in ('anchors','direct_calls','conditional_or_jump_edges','import_calls')}
    for name,(va,h) in ANCHORS.items():
        want=bytes.fromhex(h);a.require(pe.read(va,len(want))==want,'binding_extension_anchor_'+name);result['anchors'][name]=hex(va)
    for name,(va,target) in CALLS.items():
        a.require(pe.relcall(va)==target,'binding_extension_call_'+name);result['direct_calls'][name]={'call':hex(va),'target':hex(target)}
    for name,(va,op,target) in BRANCHES.items():
        a.require(previous.branch_target(pe,va,op)==target,'binding_extension_branch_'+name);result['conditional_or_jump_edges'][name]={'instruction':hex(va),'opcode':op,'target':hex(target)}
    imports=pe.imports()
    for name,(va,iat,symbol) in IAT_CALLS.items():
        a.require(pe.read(va,6)==b'\xff\x15'+iat.to_bytes(4,'little'),'binding_extension_iat_opcode_'+name)
        entry=imports.get(iat);a.require(entry is not None and entry['name']==symbol and entry['dll'].lower()=='kernel32.dll','binding_extension_iat_symbol_'+name)
        result['import_calls'][name]={'call':hex(va),'iat':hex(iat),**entry}
    return result

def analyze(raw):
    a.require(isinstance(raw,bytes) and len(raw)<=8*1024**2,'binding_extension_agent_size')
    a.require(a.sha256(raw)==identity.AGENT_SHA256,'binding_extension_pinned_agent_sha256')
    prior=previous.analyze(raw)
    return {'format':'agent-9824-binding-extension-static-1','agent_sha256':identity.AGENT_SHA256,
      'status':'bounded_binding_extension_paths_verified','prerequisite_publication_audit_passed':prior['status']=='bounded_publication_paths_verified',
      'evidence':verify(base.PE(raw)),'binary_executed':False,'network_requests':0,'game_or_lab_written':False,
      'actual_installation_binding_proven':False,'activation_contract_complete':False,'installation_ready':False,
      'correction':'v5 declared header field stays 0x154; constructor copy length may be 0x258',
      'limitations':['Raw name-input canonicalization and actual installation mode not established',
       'Static path is not Windows mutex interoperability or runtime trace',
       'Only extension slot0 descriptor geometry identified, not full extension/payload semantics',
       'No actual user shmem, .build.info writer or power-loss proof']}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--agent',required=True,type=Path);args=p.parse_args()
    w=binding.Watch();raw=w.read(args.agent,8*1024**2);got=analyze(raw);w.check();print(json.dumps(got,indent=2))
if __name__=='__main__':main()
