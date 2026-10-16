"""Experimental CASC v7 continuous-index layout for generated fixtures only.

Not an installation writer. Span checksum-B follows community Agent-8020 recipe,
not a verified contract for Agent 9824. Full keys must come from separate metadata.
"""
import hashlib
import struct
import patch_audit as a
import refs_source_check as blte

class FormatError(ValueError):pass
def need(ok,code):
    if not ok:raise FormatError(code)
MASK=0xffffffff

def rot(x,n):return ((x<<n)|(x>>(32-n)))&MASK

def hashlittle2(data,pc=0,pb=0):
    need(isinstance(data,bytes) and len(data)<=16*1024**2,'hash_input_limit')
    need(type(pc)is int and type(pb)is int and 0<=pc<=MASK and 0<=pb<=MASK,'hash_seed')
    aa=bb=cc=(0xdeadbeef+len(data)+pc)&MASK;cc=(cc+pb)&MASK;at=0
    while len(data)-at>12:
        x,y,z=struct.unpack_from('<III',data,at);aa=(aa+x)&MASK;bb=(bb+y)&MASK;cc=(cc+z)&MASK
        aa=((aa-cc)^rot(cc,4))&MASK;cc=(cc+bb)&MASK
        bb=((bb-aa)^rot(aa,6))&MASK;aa=(aa+cc)&MASK
        cc=((cc-bb)^rot(bb,8))&MASK;bb=(bb+aa)&MASK
        aa=((aa-cc)^rot(cc,16))&MASK;cc=(cc+bb)&MASK
        bb=((bb-aa)^rot(aa,19))&MASK;aa=(aa+cc)&MASK
        cc=((cc-bb)^rot(bb,4))&MASK;bb=(bb+aa)&MASK;at+=12
    tail=data[at:]
    if not tail:return cc,bb
    aa=(aa+int.from_bytes(tail[:4],'little'))&MASK
    bb=(bb+int.from_bytes(tail[4:8],'little'))&MASK
    cc=(cc+int.from_bytes(tail[8:12],'little'))&MASK
    cc=((cc^bb)-rot(bb,14))&MASK;aa=((aa^cc)-rot(cc,11))&MASK
    bb=((bb^aa)-rot(aa,25))&MASK;cc=((cc^bb)-rot(bb,16))&MASK
    aa=((aa^cc)-rot(cc,4))&MASK;bb=((bb^aa)-rot(aa,14))&MASK
    cc=((cc^bb)-rot(bb,24))&MASK
    return cc,bb

def bucket(ekey):
    a.key(ekey);v=0
    for x in bytes.fromhex(ekey)[:9]:v^=x
    return (v&15)^(v>>4)

def location(archive,offset):
    need(type(archive)is int and 0<=archive<1024 and type(offset)is int and 0<=offset<1<<30,'location_bounds')
    return ((archive<<30)|offset).to_bytes(5,'big')

def unlocation(raw):
    need(isinstance(raw,bytes) and len(raw)==5,'location_width');v=int.from_bytes(raw,'big');return v>>30,v&((1<<30)-1)

TABLE=(0x049396B8,0x72A82A9B,0xEE626CCA,0x9917754F,0x15DE40B1,0xF5A8A9B6,0x421EAC7E,0xA9D55C9A,0x317FD40C,0x04FAF80D,0x3D6BE971,0x52933CFD,0x27F64B7D,0xC6F5C11B,0xD5757E3A,0x6C388745)

def checksum_b(header26,archive,offset):
    need(len(header26)==26,'span_header_width');location(archive,offset)
    off=offset|((archive&3)<<30);encoded=(TABLE[(off+30)&15]^(off+30))&MASK
    folded=bytearray(4)
    for i,v in enumerate(header26):folded[(i+off)&3]^=v
    enc=encoded.to_bytes(4,'little')
    return bytes(folded[(j+26+off)&3]^enc[(j+26+off)&3] for j in range(4))

def make_span(encoded,ekey,decoded_size,archive,offset):
    need(isinstance(encoded,bytes) and 0<len(encoded)<=1024**2,'synthetic_encoded_limit')
    blte.decode_source(encoded,ekey,decoded_size);location(archive,offset)
    need(offset+30+len(encoded)<=1<<30,'span_crosses_segment')
    header=bytes.fromhex(ekey)[::-1]+struct.pack('<I',30+len(encoded))+bytes(2)
    header+=struct.pack('<I',hashlittle2(header,0x3D6BE971)[0])
    header+=checksum_b(header,archive,offset)
    return header+encoded

def read_span(raw,ekey,decoded_size,ckey,archive,offset):
    need(isinstance(raw,bytes) and 30<len(raw)<=1024**2+30,'span_size')
    need(raw[:16]==bytes.fromhex(a.key(ekey))[::-1] and int.from_bytes(raw[16:20],'little')==len(raw),'span_identity_or_size')
    need(raw[20:22]==bytes(2),'span_flags')
    need(int.from_bytes(raw[22:26],'little')==hashlittle2(raw[:22],0x3D6BE971)[0],'span_checksum_a')
    need(raw[26:30]==checksum_b(raw[:26],archive,offset),'span_checksum_b')
    decoded,proof=blte.decode_source(raw[30:],ekey,decoded_size)
    need(a.md5(decoded)==a.key(ckey),'span_decoded_ckey')
    return decoded,proof

def make_index(rows,which):
    need(type(which)is int and 0<=which<16 and 0<len(rows)<=1024,'index_bucket_or_count')
    ordered=sorted(rows,key=lambda v:bytes.fromhex(v['ekey'])[:9]);prefixes=[];entries=[]
    for row in ordered:
        need(bucket(row['ekey'])==which,'wrong_bucket')
        prefix=bytes.fromhex(row['ekey'])[:9];prefixes.append(prefix)
        need(type(row['span'])is int and 30<row['span']<=1024**2+30,'index_span')
        entries.append(prefix+location(row['archive'],row['offset'])+struct.pack('<I',row['span']))
    need(len(set(prefixes))==len(prefixes),'prefix_collision_rejected_not_identity')
    header=struct.pack('<HBBBBBBQ',7,which,0,4,5,9,30,0x4000000000)
    high=low=0
    for entry in entries:high,low=hashlittle2(entry,high,low)
    body=b''.join(entries)
    return struct.pack('<II',16,hashlittle2(header)[0])+header+bytes(8)+struct.pack('<II',len(body),high)+body

def read_index(raw,which):
    need(isinstance(raw,bytes) and 58<=len(raw)<=1024**2,'index_size')
    n,h=struct.unpack_from('<II',raw);need(n==16 and hashlittle2(raw[8:24])[0]==h,'index_header_checksum')
    need(raw[8:24]==struct.pack('<HBBBBBBQ',7,which,0,4,5,9,30,0x4000000000) and raw[24:32]==bytes(8),'index_header_layout')
    size,checksum=struct.unpack_from('<II',raw,32);need(size>0 and size%18==0 and len(raw)==40+size,'index_entry_size')
    high=low=0;rows=[];previous=None
    for at in range(40,len(raw),18):
        entry=raw[at:at+18];high,low=hashlittle2(entry,high,low);prefix=entry[:9]
        need(previous is None or previous<prefix,'index_prefix_order_or_collision')
        # Prefix bucket can be checked independently of the unknown seven suffix bytes.
        need(bucket(prefix.hex()+'00'*7)==which,'index_bucket_membership')
        archive,offset=unlocation(entry[9:14]);span=int.from_bytes(entry[14:18],'little')
        need(30<span<=1024**2+30 and offset+span<=1<<30,'index_location_or_span')
        rows.append({'prefix':prefix.hex(),'archive':archive,'offset':offset,'span':span});previous=prefix
    need(high==checksum,'index_entries_checksum')
    return rows
