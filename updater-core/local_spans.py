"""Read-only 30-byte archive-header research profile, no native Agent or writer.
Reference: project synthetic_casc_format.py at 7916903f5378f72a28f745fd30fe3ae11670451a.
Synthetic vectors do not qualify the general live-installation backend.
"""
from release_core import need
from lookup3 import hashlittle2
from local_blte import verify_blte
SPAN_TABLE=(0x049396B8,0x72A82A9B,0xEE626CCA,0x9917754F,0x15DE40B1,0xF5A8A9B6,0x421EAC7E,0xA9D55C9A,0x317FD40C,0x04FAF80D,0x3D6BE971,0x52933CFD,0x27F64B7D,0xC6F5C11B,0xD5757E3A,0x6C388745)
def span_checksum_b(header26,archive,offset):
 need(type(header26)is bytes and len(header26)==26 and type(archive)is int and 0<=archive<1024 and type(offset)is int and 0<=offset<1<<30,'span_location_profile');off=offset|((archive&3)<<30);encoded=(SPAN_TABLE[(off+30)&15]^(off+30))&0xffffffff;folded=bytearray(4)
 for i,v in enumerate(header26):folded[(i+off)&3]^=v
 enc=encoded.to_bytes(4,'little');return bytes(folded[(j+26+off)&3]^enc[(j+26+off)&3] for j in range(4))
def verify_span(raw,spec):
 need(type(raw)is bytes and len(raw)==spec['encoded_size']+30==spec['index_span'] and len(raw)<=4*1024**2+30,'span_geometry');need(type(spec['offset'])is int and 0<=spec['offset'] and spec['offset']+len(raw)<=1<<30,'span_segment_bounds')
 need(raw[:16]==bytes.fromhex(spec['ekey'])[::-1] and int.from_bytes(raw[16:20],'little')==len(raw),'span_header_identity_or_size');need(raw[20:22]==bytes(2),'unsupported_span_flags');need(int.from_bytes(raw[22:26],'little')==hashlittle2(raw[:22],0x3D6BE971)[0],'span_checksum_a');need(raw[26:30]==span_checksum_b(raw[:26],spec['archive_id'],spec['offset']),'span_checksum_b')
 proof=verify_blte(raw[30:],spec);return dict(proof,archive_header_bytes=30,archive_header_full_ekey_verified=True,archive_header_size_verified=True,archive_header_checksum_a_verified=True,archive_header_checksum_b_verified=True,raw_archive_header_exported=False,header_profile='pinned_agent_9824_research_profile_NOT_universal_backend')
