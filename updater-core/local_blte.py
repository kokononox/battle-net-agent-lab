"""Pure bounded N/Z BLTE identity verification; no filesystem or network access.
Extracted from tested one-object probe. Library limits are not read permission.
"""
import hashlib,struct,zlib
from release_core import need
def verify_blte(raw,spec):
    need(type(raw)is bytes and 9<=len(raw)<=4*1024**2 and len(raw)==spec['encoded_size'] and raw[:4]==b'BLTE' and len(raw)>=9,'blte_size_or_magic')
    hs=int.from_bytes(raw[4:8],'big');ek=spec['ekey'].lower();ds=spec['decoded_size'];need(0<ds<=16*1024**2,'decoded_budget')
    if hs:
        need(12<=hs<=len(raw) and raw[8]==15,'blte_header')
        n=int.from_bytes(raw[9:12],'big');need(0<n<=65536 and hs==12+24*n,'blte_table')
        need(hashlib.md5(raw[:hs]).hexdigest()==ek,'full_ekey_not_verified')
        rows=[]
        for j in range(n):
            at=12+24*j;cs,sz=struct.unpack_from('>II',raw,at);need(cs>0 and 0<sz<=ds,'chunk_geometry');rows.append((cs,sz,raw[at+8:at+24]))
        need(hs+sum(r[0] for r in rows)==len(raw) and sum(r[1] for r in rows)==ds,'chunk_totals')
    else:
        need(hashlib.md5(raw).hexdigest()==ek,'full_ekey_not_verified');rows=[(len(raw)-8,ds,None)];hs=8
    decoded=[];pos=hs
    for cs,sz,ch in rows:
        block=raw[pos:pos+cs];pos+=cs
        need(ch is None or hashlib.md5(block).digest()==ch,'chunk_checksum')
        if block[:1]==b'N':value=block[1:]
        elif block[:1]==b'Z':
            z=zlib.decompressobj();value=z.decompress(block[1:],sz+1)
            need(len(value)<=sz and z.eof and not z.unconsumed_tail and not z.unused_data,'zlib_budget_or_geometry')
        else:need(False,'unsupported_blte_mode_no_fallback')
        need(len(value)==sz,'decoded_chunk_size');decoded.append(value)
    data=b''.join(decoded);need(len(data)==ds and hashlib.md5(data).hexdigest()==spec['ckey'].lower(),'full_ckey_not_verified')
    return {'full_ekey_verified':True,'blte_chunk_checksums_verified':True,'full_ckey_verified':True,'decoded_bytes':len(data),'decoded_sha256':hashlib.sha256(data).hexdigest(),'blte_chunks':len(rows)}
