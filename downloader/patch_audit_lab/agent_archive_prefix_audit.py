"""Pinned static prefix writer/key-generator evidence; not Agent execution."""
import argparse,json
from pathlib import Path
import patch_audit as a
import agent_activation_audit as base
import agent_static_audit as identity
import agent_storage_paths_audit as prior
ANCHORS={
 'bind_prefix_callback':(0x70112d,'68aa147000'),
 'callback_store':(0x711474,'8b451c894638'),
 'callback_context':(0x71147a,'8b452089463c'),
 'archive_callback_invoke':(0x711b78,'8b43388d8d60feffff51ff7508ff733cffd0'),
 'writer_key_argument':(0x7014c2,'8b7d10'),
 'writer_archive_segment':(0x7014d8,'8b450cb900000040f7e1'),
 'writer_slot_stride':(0x7014fd,'6bcb1e'),
 'writer_flag_one':(0x701517,'6a01'),
 'writer_key_and_record_strides':(0x701541,'83c71083c21e'),
 'writer_sixteen_slots':(0x70154e,'83fb10'),
 'writer_480_bytes':(0x70155f,'68e0010000'),
 'generator_seed_copy':(0x712a8d,'a5a5a5a5'),
 'generator_capacity_threshold':(0x712a91,'3d000100007608'),
 'generator_archive_high':(0x712a98,'8bc2c1e808884302'),
 'generator_archive_low_and_trial_zero':(0x712aa0,'885301c60300'),
 'generator_bucket_mode_one':(0x712aaa,'6a0153'),
 'generator_trial_update':(0x712abb,'8a45fffec08845ff88033cff'),
 'generator_sixteen_full_keys':(0x712ad0,'83c310894df883f910'),
 'bucket_xor_first_nine':(0x712baa,'0fb6043233c84283fa09'),
 'bucket_fold_mode_and_mask':(0x712bb6,'8bc1c1e80433c10fb64d0c03c183e00f'),
 'copy_nine_byte_prefixes':(0x710bec,'83c31083c009a5a5a4'),
 'register_slot_number':(0x7125a1,'6a00506a0156ff75dc'),
 'register_span30':(0x712579,'c745e81e000000'),
 'register_bucket_slot':(0x712315,'6bc750'),
 'reader_accepts_flags_zero_one':(0x713cd3,'8a461484c074043c017547'),
}
CALLS={
 'storage_init':(0x701148,0x711445),
 'archive_make_keys':(0x711a72,0x710b6a),
 'derive_seed':(0x710b83,0x712ae3),
 'generate_keys':(0x710bda,0x712a6d),
 'generator_bucket':(0x712aad,0x712b9f),
 'register_reserved_rows':(0x711b6b,0x71252a),
 'prefix_construct_header':(0x70152f,0x713d2a),
 'prefix_write':(0x701571,0x70dfcc),
 'other_path_construct_header':(0x7068fe,0x713d2a),
}

def verify(pe):
    result={'anchors':{},'calls':{}}
    for name,(va,h) in ANCHORS.items():
        a.require(pe.read(va,len(bytes.fromhex(h)))==bytes.fromhex(h),'archive_prefix_anchor_'+name);result['anchors'][name]={'va':hex(va),'bytes':h}
    for name,(va,target) in CALLS.items():
        a.require(pe.relcall(va)==target,'archive_prefix_call_'+name);result['calls'][name]={'va':hex(va),'target':hex(target)}
    return result

def analyze(raw):
    a.require(a.sha256(raw)==identity.AGENT_SHA256,'archive_prefix_agent_identity');prior.analyze(raw)
    return {'format':'agent-9824-archive-prefix-static-1','agent_sha256':identity.AGENT_SHA256,'evidence':verify(base.PE(raw)),'agent_executed':False,'prefix_records':16,'prefix_bytes':480,'record_size':30,'flag':1,'seed_identity_proven':False,'installation_ready':False,'limitations':['The 16-byte seed is explicit research input; the Windows path/name derivation is not reproduced','Static byte anchors are not an Agent runtime or Windows acceptance test']}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--agent',required=True,type=Path);args=p.parse_args();w=__import__('source_binding').Watch();raw=w.read(args.agent,8*1024**2);got=analyze(raw);w.check();print(json.dumps(got,indent=2))
if __name__=='__main__':main()
