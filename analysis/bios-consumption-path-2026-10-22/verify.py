"""Independent PE byte checks: manual section mapping, no pefile/analyze import.
Mutation tests check that changed metadata and overclaims are rejected.
"""
import argparse,copy,hashlib,json,struct
from pathlib import Path
from google.protobuf import descriptor_pb2
SHA='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a'

def validate(blob,e):
    assert hashlib.sha256(blob).hexdigest()==SHA==e['source_sha256']
    assert blob[:2]==b'MZ';pe=struct.unpack_from('<I',blob,0x3c)[0];assert blob[pe:pe+4]==b'PE\0\0'
    n=struct.unpack_from('<H',blob,pe+6)[0];sz=struct.unpack_from('<H',blob,pe+20)[0];opt=pe+24
    assert struct.unpack_from('<H',blob,opt)[0]==0x20b
    base=struct.unpack_from('<Q',blob,opt+24)[0]
    sections=[]
    for i in range(n):
        s=opt+sz+i*40
        virtual_size,rva,raw_size,raw=struct.unpack_from('<IIII',blob,s+8)
        sections.append((rva,raw_size,raw))
    def read(r,l):
        for va,size,off in sections:
            if va<=r and r+l<=va+size:return blob[off+r-va:off+r-va+l]
        raise AssertionError('Not raw-backed')
    u32=lambda r:struct.unpack('<I',read(r,4))[0]
    ptr=lambda r:struct.unpack('<Q',read(r,8))[0]-base
    reg=0x47cebb0;c=0x47cf7e0;t=0x47cec08
    assert e['registration_rva']==hex(reg) and e['class_data_rva']==hex(c) and e['parse_table_rva']==hex(t)
    assert ptr(c)==0x4856510 and ptr(c+8)==t and ptr(t+32)==c and ptr(c+0x48)==reg
    assert read(c,0x68).hex()==e['class_data_bytes'] and read(t,56).hex()==e['parse_header_bytes']
    fd=descriptor_pb2.FileDescriptorProto();raw_desc=read(ptr(reg+8),u32(reg+4));fd.ParseFromString(raw_desc)
    assert hashlib.sha256(raw_desc).hexdigest()==e['descriptor']['sha256']
    idx=next(i for i,m in enumerate(fd.message_type) if m.name=='ClientEngineLogV2');m=fd.message_type[idx]
    oi,hi,_,size=struct.unpack('<iiiI',read(ptr(reg+0x30)+16*idx,16));offsets=ptr(reg+0x40)
    assert size==376==e['candidate_object_size']
    assert u32(c+0x28)==size and read(c+0x2c,2)==b'\xff\x08'
    h=struct.unpack('<HHIBBHIIHHI4xQQQ',read(t,56));has_base=h[0]*8
    assert h[0]==16 and h[2]==max(f.number for f in m.field)==198 and h[8]==len(m.field)==98
    assert 56+(h[3]//8+1)*16==h[5]==568
    assert h[7]+12*h[8]==1780 and h[10]==1784 and h[9]==4
    original={f.number:(j,f) for j,f in enumerate(m.field)}
    assert len(e['fields'])==98 and e['field_count']==98 and not e['offset_and_presence_mismatches']
    for k,num in enumerate(sorted(original)):
        j,f=original[num];r=t+h[7]+12*k
        off,has_idx,aux,typ=struct.unpack('<IiHH',read(r,12));entry=e['fields'][k]
        assert (entry['number'],entry['name'],entry['descriptor_type'])==(num,f.name,f.type)
        assert off==u32(offsets+4*(oi+8+j))==entry['parse_offset']==entry['migration_offset']
        assert has_idx==has_base+u32(offsets+4*(hi+j))==entry['parse_has_idx']
        assert entry['migration_hasbit_index']==has_idx-has_base
        assert entry['entry_rva']==hex(r) and entry['entry_bytes']==read(r,12).hex()
        assert entry['aux_idx']==aux and entry['type_card']==hex(typ)
    expected=[(194,'motherboardBiosVendorName',96,135),(195,'motherboardBiosReleaseDate',104,136),(196,'motherboardBiosVersion',112,137)]
    assert [(f['number'],f['name'],f['parse_offset'],f['parse_has_idx']) for f in e['bios_fields']]==expected
    for f in e['bios_fields']:assert f in e['fields']
    for literal in e['registry_literals']:
        assert literal['occurrences']
        for hit in literal['occurrences']:
            needle=(literal['literal']+'\0').encode('utf-16le')
            assert read(int(hit['rva'],16),len(needle))==needle
            off=int(hit['file_offset'],16);assert blob[off:off+len(needle)]==needle
    assert e['claims']['parse_table_corroborates_layout'] is True
    for k,v in e['claims'].items():
        if k!='parse_table_corroborates_layout':assert v is False, 'Unjustified runtime claim'
    assert all(v['body_semantics_verified'] is False for v in e['role_candidates'].values())
    return True

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('input');p.add_argument('--evidence',default='evidence.json');p.add_argument('--out',default='QA.json');a=p.parse_args()
    blob=Path(a.input).read_bytes();e=json.loads(Path(a.evidence).read_text());validate(blob,e)
    tests=[]
    def rejects(label,mutate):
        altered=copy.deepcopy(e);mutate(altered)
        try:validate(blob,altered)
        except AssertionError: tests.append({'test':label,'passed':True});return
        raise AssertionError('Mutation accepted: '+label)
    rejects('BIOS field offset corruption',lambda d:d['fields'][95].update(parse_offset=120))
    rejects('ClassData cycle relabeling',lambda d:d.update(class_data_rva='0x47cf7f0'))
    rejects('Unsupported hardware population claim',lambda d:d['claims'].update(hardware_population_proven=True))
    rejects('Unsupported hardware serialization claim',lambda d:d['claims'].update(serialization_of_hardware_proven=True))
    rejects('Unsupported TCP/3724 binding claim',lambda d:d['claims'].update(destination_or_port_3724_binding_proven=True))
    result={'status':'PASS','binary_hash_pinned':True,'manual_pe_mapping':True,'field_entries_checked':98,'bios_fields_checked':3,'cycle_and_table_geometry_checked':True,'mutation_tests':tests,'scope':'Checks static structure and conservative claims, NOT runtime behavior or ABI equivalence.'}
    Path(a.out).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
