"""Static evidence: canonical storage name + GetComputerNameW -> seed MD5.
ASCII model only; static Windows API evidence is not a Windows runtime test.
"""
import argparse,json
from pathlib import Path
import patch_audit as a
import source_binding as binding
import agent_activation_audit as base
import agent_archive_prefix_audit as prior
import agent_static_audit as identity
ANCHORS={
 'seed_name_null_empty_fallback':(0x712af6,'8b450c85c056578b7d08be08bc8f00'),
 'seed_name_select_nonnull':(0x712b05,'680c0300000f45f0'),
 'computer_string_strlen':(0x712b35,'8d8df0fcffff8d51018a014184c075f92bca'),
 'first_update_pointer_length':(0x712b47,'8d85f0fcffff5150'),
 'name_string_strlen':(0x712b5a,'8bce8d51018a014184c075f92bca'),
 'second_update_pointer_length':(0x712b68,'5156'),
 'computer_buffer_char_capacity':(0x86d00d,'c745d810000000'),
 'computer_empty_on_nonzero_output_capacity':(0x86cffd,'837d0c00568b75087603c60600'),
 'computer_success_gate':(0x86d01f,'85c07507'),
 'ascii_output_threshold':(0x86ef53,'8b4d0881f980000000'),
 'ascii_output_byte_unchanged':(0x86f032,'8b450c880833c0'),
 'md5_initial_state':(0x864548,'c7410801234567c7410c89abcdefc74110fedcba98c7411476543210'),
 'md5_first_round_constant_rotation':(0x86e428,'0578a46ad723fb33fa03560403c7c1c007'),
 'md5_padding_80':(0x8644ab,'c644321880'),
 'md5_append_bit_length':(0x864512,'0fa4c103ff75f8c1e003894650894e54'),
 'md5_digest_four_native_dwords':(0x86452c,'8b038d5b048904b94783ff047cf2'),
 'canonical_name_selected_for_seed':(0x710b73,'f6460c018d461075028b0050'),
}
CALLS={
 'storage_path_to_canonical_name':(0x711452,0x712bc9),
 'archive_keys_request_seed':(0x710b83,0x712ae3),
 'seed_get_computer_wrapper':(0x712b22,0x70ee15),
 'computer_wrapper':(0x70ee20,0x86cfed),
 'computer_ascii_conversion_wrapper':(0x86d032,0x864681),
 'seed_md5_init':(0x712b30,0x864541),
 'seed_md5_computer_first':(0x712b55,0x8643ef),
 'seed_md5_canonical_name_second':(0x712b70,0x8643ef),
 'seed_md5_finalize':(0x712b82,0x864497),
 'seed_into_reserved_keys':(0x710bda,0x712a6d),
 'md5_update_transform_partial':(0x864444,0x86e40b),
 'md5_update_transform_blocks':(0x864464,0x86e40b),
 'md5_final_transform':(0x864522,0x86e40b),
}
IAT={'computer_name':(0x86d019,0x8fb55c,'GetComputerNameW')}

def verify(pe):
    result={'anchors':{},'calls':{},'import_calls':{}}
    for name,(va,h) in ANCHORS.items():
        a.require(pe.read(va,len(bytes.fromhex(h)))==bytes.fromhex(h),'name_seed_anchor_'+name);result['anchors'][name]={'va':hex(va),'bytes':h}
    for name,(va,target) in CALLS.items():
        a.require(pe.relcall(va)==target,'name_seed_call_'+name);result['calls'][name]={'va':hex(va),'target':hex(target)}
    imports=pe.imports()
    for name,(va,iat,symbol) in IAT.items():
        a.require(pe.read(va,6)==b'\xff\x15'+iat.to_bytes(4,'little'),'name_seed_iat_opcode')
        got=imports.get(iat);a.require(got is not None and got['name']==symbol and got['dll'].lower()=='kernel32.dll','name_seed_iat_symbol');result['import_calls'][name]={'va':hex(va),'iat':hex(iat),**got}
    return result

def analyze(raw):
    a.require(isinstance(raw,bytes) and len(raw)<=8*1024**2 and a.sha256(raw)==identity.AGENT_SHA256,'name_seed_pinned_agent_identity');prior.analyze(raw)
    return {'format':'agent-name-seed-static-1','agent_sha256':identity.AGENT_SHA256,'evidence':verify(base.PE(raw)),'ascii_success_path_formula':'MD5(computer_name_ASCII || canonical_storage_name_ASCII), no delimiter or terminating NUL','computer_api':'GetComputerNameW','windows_api_executed':False,'windows_agent_process_executed':False,'actual_installation_binding_proven':False,'installation_ready':False,'limitations':['Non-ASCII names, API failure and live Windows cwd are not reproduced','Input is the canonical storage name passed to the reviewed class, not a guessed root of a WoW installation','Pure-fragment harness results are recorded separately, not a Windows Agent test']}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--agent',type=Path,required=True);args=p.parse_args();w=binding.Watch();raw=w.read(args.agent,8*1024**2);got=analyze(raw);w.check();print(json.dumps(got,indent=2))
if __name__=='__main__':main()
