"""Pinned Agent 9824 static evidence + observed Retail patch-index parser.

No executable is run. No network, game writes, API calls or patch authorization.
Only observed index-envelope + block 1/8 variant supported, fail closed otherwise.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import patch_audit as a
import source_binding as b

AGENT_SHA256='b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5'
INDEX_CKEY='a7de5f58d102d41749397bc197744b63'
MAX_INDEX=4*1024**2

def envelope(raw):
    a.require(19<=len(raw)<=MAX_INDEX,'index_size_limit')
    hs,field1,total=struct.unpack_from('<III',raw)
    extlen=struct.unpack_from('<H',raw,12)[0]
    a.require(total==len(raw) and 19<=hs<=len(raw) and extlen>=1 and 14+extlen+4<=hs,'index_envelope')
    # Agent first reads a one-byte short string length within this extension.
    a.require(raw[14]<=16 and raw[14]+1<=extlen,'index_extension')
    count=struct.unpack_from('<I',raw,14+extlen)[0];p=18+extlen
    a.require(0<count<=32 and p+8*count==hs,'index_directory')
    out=[];off=hs;seen=set()
    for i in range(count):
        ident,size=struct.unpack_from('<II',raw,p+i*8)
        a.require(ident not in seen and size>0 and off+size<=len(raw),'index_block_bounds')
        seen.add(ident);out.append((ident,raw[off:off+size]));off+=size
    a.require(off==len(raw),'index_trailing_data')
    return out,{'header_bytes':hs,'header_u32_field_1_uninterpreted':field1,'total_bytes':total,
                'extension_hex':raw[14:14+extlen].hex(),'block_directory':[{'id':i,'bytes':len(v)} for i,v in out]}

def records(raw):
    blocks,report=envelope(raw)
    a.require([i for i,_ in blocks]==[1,8],'unobserved_index_block_set')
    blob_block=blocks[0][1]
    a.require(len(blob_block)>=4 and int.from_bytes(blob_block[:4],'little')==len(blob_block)-4,'index_blob_bounds')
    blob=blob_block[4:]
    # Observed blob is NUL + 'n' + NUL. General eSpec semantics not claimed.
    a.require(blob==b'\0n\0','unobserved_index_blob')
    block=blocks[1][1];a.require(len(block)>=14,'index_block8_header')
    version,keylen,hs,n,field=struct.unpack_from('<BBHII',block)
    a.require((version,keylen,hs,block[12:14])==(3,16,14,b'\x01\x02'),'unobserved_index_block8_variant')
    # 3x16-byte keys, 3xLE32 numbers and a one-byte blob offset.
    width=61
    a.require(0<n<=100000 and hs+n*width==len(block),'index_block8_record_bounds')
    rows=[]
    for i in range(n):
        at=hs+i*width
        aa=block[at:at+16].hex();sa=struct.unpack_from('<I',block,at+16)[0]
        bb=block[at+20:at+36].hex();sb,sc=struct.unpack_from('<II',block,at+36)
        spec=block[at+44];cc=block[at+45:at+61].hex()
        a.require(spec<len(blob) and b'\0' in blob[spec:],'index_spec_offset')
        rows.append({'key_a':aa,'u32_a':sa,'key_b':bb,'u32_b':sb,'u32_c':sc,'blob_offset':spec,'key_c':cc})
    report['block8']={'version':version,'key_bytes':keylen,'header_bytes':hs,'records':n,'record_bytes':width,
                      'flags':2,'header_u32_field_uninterpreted':field,'blob_hex':blob.hex()}
    return rows,report

def pe_evidence(raw):
    a.require(a.sha256(raw)==AGENT_SHA256,'pinned_agent_sha256')
    pe=struct.unpack_from('<I',raw,0x3c)[0];a.require(raw[pe:pe+4]==b'PE\0\0','pe_header')
    op=pe+24;sections=[];image=struct.unpack_from('<I',raw,op+28)[0]
    a.require(struct.unpack_from('<H',raw,pe+4)[0]==0x14c and struct.unpack_from('<H',raw,op)[0]==0x10b,'pinned_pe32')
    sh=op+struct.unpack_from('<H',raw,pe+20)[0]
    for i in range(struct.unpack_from('<H',raw,pe+6)[0]):
        at=sh+i*40;vs,rva,sz,off=struct.unpack_from('<IIII',raw,at+8)
        a.require(off+sz<=len(raw),'pe_section_bounds')
        sections.append({'name':raw[at:at+8].rstrip(b'\0').decode('ascii'),'va':image+rva,'offset':off,'size':sz})
    def slice_va(va,size):
        for s in sections:
            if s['va']<=va and va+size<=s['va']+s['size']:
                off=s['offset']+va-s['va'];return raw[off:off+size]
        raise a.AuditError('va_not_file_backed')
    checks={
      'sign_byte_and_magnitude_mask':(0x6e3c4f,bytes.fromhex('8a59078ac3247f')),
      'conditional_magnitude_negation':(0x6e3ccd,bytes.fromhex('84db7907f7df83d600f7de')),
      'header_read_at_8':(0x6e3d3c,bytes.fromhex('8d4108')),
      'header_read_at_16':(0x6e3d6a,bytes.fromhex('83c010')),
      'header_read_at_24':(0x6e3d9c,bytes.fromhex('83c018')),
      'patch_index_minimum_14_bytes':(0x68c3e7,bytes.fromhex('837f080e')),
      'little_endian_u32_reader':(0x6b7f82,bytes.fromhex('8b51088b0283c204895108c3')),
      'block_dispatch_subtract_1':(0x68c483,bytes.fromhex('8d42ff83f809')),
      'block8_header_reads':(0x68ce40,bytes.fromhex('e849b10200')),
    }
    for label,(va,expected) in checks.items():a.require(slice_va(va,len(expected))==expected,'code_anchor_'+label)
    targets=struct.unpack('<10I',slice_va(0x68c538,40))
    a.require(targets[7]==0x68c4c4,'block8_dispatch_target')
    return {'sha256':AGENT_SHA256,'image_base':hex(image),'machine':'i386 PE32',
      'code_anchors_verified':{k:hex(v[0]) for k,v in checks.items()},
      'patch_index_block8_dispatch_va':'0x68c4c4','patch_index_block8_handler_va':'0x68ce1e',
      'zbsdiff_sign_magnitude_reader_va':'0x6e3c46','zbsdiff_header_reader_va':'0x6e3ce1',
      'binary_executed':False,'authenticode_trust_verified':False}

def analyze(agent,index,options):
    pe=pe_evidence(agent);a.require(a.md5(index)==INDEX_CKEY,'pinned_retail_index_ckey')
    rows,report=records(index)
    source_keys={o.source_ekey for o in options}
    pa_tuples={(o.source_ekey,o.source_size,o.patch_key,o.patch_size) for o in options}
    grouped={}
    for row in rows:
        t=(row['key_a'],row['u32_a'],row['key_b'],row['u32_b']);grouped.setdefault(t,[]).append(row)
    row_tuples=set(grouped);matched_sources={r['key_a'] for r in rows}&source_keys
    # Independent direct-membership path, not the set intersection calculation.
    lookup={row['key_a']:True for row in rows}
    direct_source_count=sum(1 for key in source_keys if lookup.get(key,False))
    a.require(direct_source_count==len(matched_sources),'source_coverage_reconciliation')
    sample=next((o for o in options if o.patch_key=='a56b3fe67a775fe9f4e86d6cbb688b5d'),None)
    matched_sample=grouped.get((sample.source_ekey,sample.source_size,sample.patch_key,sample.patch_size),[]) if sample else []
    report.update({'pa_patch_options':len(options),'pa_unique_sources':len(source_keys),
      'pa_unique_sources_present_as_index_key_a':len(matched_sources),
      'pa_options_with_exact_source_size_patch_size_tuple':sum((o.source_ekey,o.source_size,o.patch_key,o.patch_size) in row_tuples for o in options),
      'unique_index_tuples_matched_to_pa':len(row_tuples&pa_tuples),
      'index_key_a_unique':len(lookup),'duplicate_complete_rows':len(rows)-len({tuple(r.values()) for r in rows}),
      'sample_index_records':matched_sample,'key_c_semantics_proven':False,
      'ordinal_semantics_proven':False,'patch_execution_policy_proven':False})
    return {'format':'agent-9824-static-audit-1','pe':pe,'retail_patch_index':report,
      'network_requests_during_analysis':0,'source_game_payload_read':False,'game_modified':False,'lab_modified':False,
      'retail_patch_applied':False,'casc_writer_implemented':False,'installation_ready':False,
      'interpretation':'Index structural parsing and PA tuple correspondence, not a demonstrated updater.'}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--agent',required=True);p.add_argument('--index',required=True);p.add_argument('--output',required=True);args=p.parse_args()
    options,_,_=b.load_metadata(Path(__file__).resolve().parent/'pinned_metadata',b.Watch())
    watch=b.Watch();agent=watch.read(Path(args.agent),8*1024**2);index=watch.read(Path(args.index),MAX_INDEX)
    result=analyze(agent,index,options);watch.check()
    with Path(args.output).open('x',encoding='utf-8') as f:json.dump(result,f,indent=2)
    print('Pinned static analysis completed. Binary not executed.')

if __name__=='__main__':main()
