"""Read-only, hash-pinned BIOS metadata audit. Never loads/executes the PE.
Requires pefile and protobuf. Upstream v30.1 layout is a hypothesis for protobuf_blz.
"""
import argparse, hashlib, json, os, struct, sys
from pathlib import Path
sys.path.insert(0, os.environ.get('RE_TOOLS', '/data/re-tools'))
import pefile
from google.protobuf import descriptor_pb2
SHA='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a'

def analyze(path):
    blob=Path(path).read_bytes()
    assert hashlib.sha256(blob).hexdigest()==SHA, 'Wrong input build'
    pe=pefile.PE(data=blob, fast_load=True)
    pe.parse_data_directories(directories=[5])
    base=pe.OPTIONAL_HEADER.ImageBase
    data=lambda r,n: pe.get_data(r,n)
    u32=lambda r: struct.unpack('<I',data(r,4))[0]
    u64=lambda r: struct.unpack('<Q',data(r,8))[0]
    ptr=lambda r:u64(r)-base
    relocs=sorted(e.rva for b in pe.DIRECTORY_ENTRY_BASERELOC for e in b.entries if e.type==10)
    refs={}
    for r in relocs: refs.setdefault(u64(r)-base,[]).append(r)
    reg=0x47cebb0
    desc_rva=ptr(reg+8);desc_size=u32(reg+4)
    raw_desc=data(desc_rva,desc_size)
    fd=descriptor_pb2.FileDescriptorProto();fd.ParseFromString(raw_desc)
    msg=next(m for m in fd.message_type if m.name=='ClientEngineLogV2')
    mi=next(i for i,m in enumerate(fd.message_type) if m.name==msg.name)
    schemas=ptr(reg+0x30);offsets=ptr(reg+0x40);prototype=ptr(ptr(reg+0x38)+8*mi)
    oi,hi,si,obj_size=struct.unpack('<iiiI',data(schemas+16*mi,16))
    # Discover candidate ClassData via relocation-backed prototype references and cycle.
    matches=[]
    for c in refs.get(prototype,[]):
        try:
            t=ptr(c+8)
            if ptr(t+32)==c and ptr(c+0x48)==reg: matches.append((c,t))
        except (struct.error,pefile.PEFormatError): pass
    assert len(matches)==1,matches
    class_rva,table=matches[0]
    names=['has_bits_offset','extension_offset','max_field_number','fast_idx_mask','flags','lookup_table_offset','skipmap32','field_entries_offset','num_field_entries','num_aux_entries','aux_offset','class_data_va','post_loop_handler_va','fallback_va']
    h=dict(zip(names,struct.unpack('<HHIBBHIIHHI4xQQQ',data(table,56))))
    fields=[]
    for j,f in enumerate(msg.field):
        fields.append({'name':f.name,'number':f.number,'descriptor_type':f.type,
                       'migration_offset':u32(offsets+4*(oi+8+j)),
                       'migration_hasbit_index':u32(offsets+4*(hi+j))})
    fields.sort(key=lambda x:x['number'])
    for j,f in enumerate(fields):
        r=table+h['field_entries_offset']+12*j
        off,has_idx,aux,typ=struct.unpack('<IiHH',data(r,12))
        f.update(entry_index=j,entry_rva=hex(r),entry_bytes=data(r,12).hex(),
                 parse_offset=off,parse_has_idx=has_idx,aux_idx=aux,type_card=hex(typ))
    mismatches=[f['name'] for f in fields if f['parse_offset']!=f['migration_offset'] or f['parse_has_idx']!=h['has_bits_offset']*8+f['migration_hasbit_index']]
    literals=[]
    for s in ['HARDWARE\\DESCRIPTION\\System\\BIOS','BIOSVersion','BIOSVendor','BIOSReleaseDate','BaseBoardProduct','BaseBoardManufacturer','BaseBoardVersion','BiosMinorRelease','HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0']:
        needle=(s+'\0').encode('utf-16le');start=0;hits=[]
        while True:
            off=blob.find(needle,start)
            if off<0:break
            r=pe.get_rva_from_offset(off)
            hits.append({'rva':hex(r),'file_offset':hex(off),'relocated_absolute_refs_to_exact_start':[hex(x) for x in refs.get(r,[])]})
            start=off+2
        literals.append({'literal':s,'encoding':'UTF-16LE NUL-terminated','occurrences':hits})
    allocation,tag,alignment=struct.unpack('<IbB',data(class_rva+0x28,6))
    roles={'merge_candidate':ptr(class_rva+0x20),'creator_candidate':ptr(class_rva+0x30),'parse_fallback_candidate':h['fallback_va']-base}
    role_details={}
    for k,r in roles.items():
        sec=pe.get_section_by_rva(r)
        role_details[k]={'rva':hex(r),'first_16_bytes':data(r,16).hex(),'section':sec.Name.rstrip(b'\0').decode(),'executable_section':bool(sec.Characteristics&0x20000000),'body_semantics_verified':False}
    return {'source_sha256':SHA,'analysis_kind':'offline static metadata; input never executed',
        'layout_model':'Candidate upstream protobuf v30.1 layout, not proven fork ABI identity',
        'message':fd.package+'.'+msg.name,'descriptor':{'rva':hex(desc_rva),'size':desc_size,'sha256':hashlib.sha256(raw_desc).hexdigest()},
        'registration_rva':hex(reg),'migration_schema_rva':hex(schemas+16*mi),'offset_array_rva':hex(offsets),
        'prototype_rva':hex(prototype),'class_data_rva':hex(class_rva),'parse_table_rva':hex(table),
        'class_data_bytes':data(class_rva,0x68).hex(),'parse_header_bytes':data(table,56).hex(),
        'parse_header':h,'candidate_object_size':obj_size,
        'message_creator_candidate':{'allocation_size':allocation,'tag':tag,'alignment':alignment,'interpretation':'tag -1 matches function-based construction, NOT serialization'},
        'role_candidates':role_details,
        'geometry':{'fast_entry_count_candidate':h['fast_idx_mask']//8+1,'fast_table_end':56+(h['fast_idx_mask']//8+1)*16,'lookup_offset':h['lookup_table_offset'],'field_entries_end':h['field_entries_offset']+12*len(fields),'aux_offset':h['aux_offset']},
        'field_count':len(fields),'offset_and_presence_mismatches':mismatches,'fields':fields,
        'bios_fields':[f for f in fields if f['name'] in ['motherboardBiosVendorName','motherboardBiosReleaseDate','motherboardBiosVersion']],
        'registry_literals':literals,
        'claims':{'parse_table_corroborates_layout':not mismatches,'hardware_read_executed_proven':False,'hardware_population_proven':False,'serialization_of_hardware_proven':False,'runtime_send_proven':False,'destination_or_port_3724_binding_proven':False},
        'limitations':['Exact-start relocation references are not an exhaustive use/call graph.','Field entries describe parsing/deserialization, not a hardware collector or sender.','Presence of registry literals proves neither an executed registry read nor assignment to these fields.','Code-pointer roles depend on a candidate upstream layout; function bodies were not semantically recovered.','No inference that hardware is absent from or present on TCP/3724 can be made from these metadata.']}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('input');p.add_argument('--out',default='evidence.json');a=p.parse_args()
    result=analyze(a.input);Path(a.out).write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps({'fields':result['field_count'],'mismatches':result['offset_and_presence_mismatches'],'class_data':result['class_data_rva'],'parse_table':result['parse_table_rva'],'bios_fields':[x['name'] for x in result['bios_fields']]}))
