"""Pinned Agent static evidence for allocation and 30-byte span checksums."""
import argparse,json,struct
from pathlib import Path
import agent_activation_audit as base
import agent_primary_payload_audit as prior
import agent_static_audit as identity
import synthetic_casc_format as fmt
import patch_audit as a
import source_binding as binding
ANCHORS={
 'allocate_request_zero':(0x722a06,'397d08'),
 'allocate_count':(0x722a1d,'8b4304'),
 'allocate_scan_length_a':(0x722a2c,'8d4b20'),
 'allocate_compare_length':(0x722a45,'3bc3'),
 'allocate_read_b_base':(0x722a72,'8d866a15000003c3'),
 'allocate_boundary_mask':(0x722a9e,'81e1ffffff3f0bcf'),
 'allocate_prefix_threshold':(0x722aac,'3de0010000'),
 'allocate_boundary_code':(0x722ab9,'6a10'),
 'allocate_update_arithmetic':(0x722acd,'2bc61bd752508bc60345fc137df8'),
 'allocate_no_fit_code':(0x722afb,'6a0e'),
 'reserve_archive_segment':(0x722b13,'b900000040f7e1'),
 'reserve_prefix_480':(0x722b39,'05e0010000'),
 'reserve_remaining_length':(0x722bc2,'2bd01bf1'),
 'span_hash_seed_length':(0x713b9a,'6871e96b3d6a1656'),
 'span_hash_little_endian':(0x713baf,'88440e16c1e808413bcf'),
 'span_offset_plus30':(0x713bc0,'8d4b1e8bc183e00f'),
 'span_checksum_table_xor':(0x713bc8,'8b148550d69b0033d1'),
 'span_fold26':(0x713bbe,'6a1a'),
 'span_fold_by_offset':(0x713bf4,'8a028d0c1383e10330440d10'),
 'span_checksum_write':(0x713c0c,'8d0c1383e1038a440d1032440dfc8802'),
 'span_construct_reverse_key':(0x713d4f,'8a04394188064e83f910'),
 'span_construct_size_le':(0x713d62,'8b4608d3e883c10888443a104783f920'),
 'span_construct_flags':(0x713d74,'8a4518884214c6421500'),
 'span_verify_hash_seed_length':(0x713cb0,'6871e96b3d6a1656'),
 'span_verify_checksum_table':(0x713c7c,'8b048550d69b0033c13bd0'),
}
CALLS={
 'allocate_recover':(0x7229f6,0x722e3f),
 'allocate_update':(0x722ae0,0x722e88),
 'reserve_update':(0x722bcd,0x722e88),
 'caller_allocate':(0x71004c,0x7229e3),
 'caller_make_archive':(0x710067,0x711a50),
 'caller_allocate_retry':(0x71007c,0x7229e3),
 'archive_reserve_prefix':(0x711b27,0x722b05),
 'span_construct_checksum':(0x713d84,0x713b90),
 'span_writer_hash':(0x713ba2,0x72345c),
 'span_reader_hash':(0x713cb8,0x72345c),
 'span_reader_checksum':(0x713ca4,0x713c27),
 'span_construct_caller':(0x712de5,0x713d2a),
}
BRANCHES={
 'allocate_state_one_gate':(0x7229fe,'0f85',0x722afb),
 'allocate_first_fit':(0x722a47,'73',0x722a5c),
 'allocate_exhausted':(0x722a67,'0f84',0x722afb),
 'allocate_not_boundary':(0x722aa6,'75',0x722ac8),
 'allocate_small_boundary':(0x722ab1,'72',0x722ac8),
 'caller_code16_gate':(0x710056,'75',0x710083),
}

def branch_target(pe,va,opcode):
    a.require(opcode in ('73','75','72','0f84','0f85'),'storage_branch_opcode_config')
    op=bytes.fromhex(opcode);width=4 if len(op)==2 else 1
    raw=pe.read(va,len(op)+width);a.require(raw[:len(op)]==op,'storage_branch_opcode')
    return va+len(raw)+int.from_bytes(raw[len(op):],'little',signed=True)

def verify(pe):
    out={'anchors':{},'direct_calls':{},'branch_edges':{}}
    for name,(va,h) in ANCHORS.items():
        want=bytes.fromhex(h);a.require(pe.read(va,len(want))==want,'storage_anchor_'+name);out['anchors'][name]=hex(va)
    for name,(va,target) in CALLS.items():
        a.require(pe.relcall(va)==target,'storage_call_'+name);out['direct_calls'][name]={'call':hex(va),'target':hex(target)}
    for name,(va,op,target) in BRANCHES.items():
        a.require(branch_target(pe,va,op)==target,'storage_branch_'+name);out['branch_edges'][name]={'instruction':hex(va),'target':hex(target)}
    a.require(struct.unpack('<16I',pe.read(0x9bd650,64))==fmt.TABLE,'storage_span_checksum_table')
    out['checksum_table']={'va':'0x9bd650','dwords':16,'exact_match':True}
    return out

def analyze(raw):
    a.require(isinstance(raw,bytes) and len(raw)<=8*1024**2,'storage_agent_size')
    a.require(a.sha256(raw)==identity.AGENT_SHA256,'storage_pinned_agent_sha256');prior.analyze(raw)
    return {'format':'agent-9824-storage-paths-1','agent_sha256':identity.AGENT_SHA256,'status':'bounded_allocator_and_span_paths_verified','evidence':verify(base.PE(raw)),'agent_executed':False,'allocator_model_is_agent_execution':False,'network_requests':0,'game_or_lab_written':False,'installation_ready':False,'limitations':['Static paths do not prove Windows execution or power-loss recovery','Index v7 compatibility is tested against pinned CascLib, not the Agent writer','Archive prefix content, full closure, real activation and .build.info writer remain unproved']}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--agent',required=True,type=Path);args=p.parse_args();w=binding.Watch();raw=w.read(args.agent,8*1024**2);got=analyze(raw);w.check();print(json.dumps(got,indent=2))
if __name__=='__main__':main()
