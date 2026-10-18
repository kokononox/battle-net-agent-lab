"""Read-only primary V8 metadata adapter, based on reviewed existing bind research.
No qword-to-archive interpretation, native Agent execution, file opening or writer.
"""
import struct
from release_core import need
from lookup3 import hashlittle2
REFERENCE='https://github.com/kokononox/battle-net-agent-lab/blob/7916903f5378f72a28f745fd30fe3ae11670451a/downloader/patch_audit_lab/agent_bind_contract.py'
def align(n,m):return (n+m-1)&-m
def primary_records(raw,bucket):
 need(type(raw)is bytes and 40<=len(raw)<=1024**2 and type(bucket)is int and 0<=bucket<16,'v8_bounds');n,h=struct.unpack_from('<II',raw);need(n==16 and hashlittle2(raw[8:24])[0]==h,'v8_header_checksum');v,b,flags,sw,ow,kw,bits,maxoff=struct.unpack_from('<HBBBBBBQ',raw,8);need((v,b,flags,sw,ow,kw,bits)==(8,bucket,0,8,8,16,30) and raw[24:32]==bytes(8),'v8_unsupported_header');size,checksum=struct.unpack_from('<II',raw,32);need(size%32==0 and size//32<=20000 and 40+size<=len(raw),'v8_primary_bounds');rows=[raw[i:i+32] for i in range(40,40+size,32)];hi=lo=0
 for r in rows:hi,lo=hashlittle2(r,hi,lo)
 need(hi==checksum,'v8_primary_checksum');keys=[r[:16] for r in rows];need(all(k!=bytes(16) for k in keys) and keys==sorted(keys) and len(set(keys))==len(keys),'v8_primary_keys');tail=align(40+size,4096);need(len(raw)==align(tail+0x7800,0x20000) and not any(raw[40+size:]),'v8_nonempty_or_unknown_tail')
 records=[{'key':r[:16],'opaque_qword0':struct.unpack_from('<Q',r,16)[0],'opaque_qword1':struct.unpack_from('<Q',r,24)[0]} for r in rows]
 return records,{'header_checksum_verified':True,'primary_checksum_verified':True,'primary_records':len(rows),'header_max_offset_opaque':maxoff,'native_fixture_header_max_offset_match':maxoff==0x4000000000,'opaque_qwords_not_interpreted_as_archive_locations':True,'native_agent_executed':False,'active_generation_proven':False,'empty_tail_verified':True}
