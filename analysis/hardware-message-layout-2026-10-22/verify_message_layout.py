"""Raw PE + protobuf checks of a layout report, not runtime/ABI equivalence proof."""
from pathlib import Path
import argparse,struct,hashlib,json
from google.protobuf import descriptor_pb2
p=argparse.ArgumentParser();p.add_argument('--input',type=Path,default=Path('/data/raw/wow-retail-20261022/Wow.exe'));p.add_argument('--out',type=Path,default=Path(__file__).parent);p.add_argument('--report',type=Path);a=p.parse_args();w=a.out;b=a.input.read_bytes();sha=hashlib.sha256(b).hexdigest();assert sha=='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a'
u16=lambda o:struct.unpack_from('<H',b,o)[0];u32=lambda o:struct.unpack_from('<I',b,o)[0]
nt=u32(0x3c);assert b[:2]==b'MZ' and b[nt:nt+4]==b'PE\0\0';opt=nt+24;assert u16(opt)==0x20b;base=struct.unpack_from('<Q',b,opt+24)[0]
sections=[]
for j in range(u16(nt+6)):
 o=opt+u16(nt+20)+40*j;sections.append((u32(o+12),u32(o+16),u32(o+20),u32(o+36)))
def raw(r,n):
 for va,size,off,flags in sections:
  if va<=r and r+n<=va+size:return b[off+r-va:off+r-va+n]
 raise AssertionError(f'No file-backed bytes at {r:x}')
def dword(r):return struct.unpack('<I',raw(r,4))[0]
def qword(r):return struct.unpack('<Q',raw(r,8))[0]
report=json.loads((a.report or w/'message-layout.json').read_text());assert report['source_sha256']==sha
assert not any(report[k] for k in ('input_executed_emulated_or_patched','collector_identified','selected_message_serializer_identified','selected_message_network_binding_proven'))
expected={'ClientSystemSpec':(0x47c7dc0,1,0x4855470,12,88,5),'ClientEngineLogV2':(0x47cebb0,0,0x4856510,98,376,10)};checked=0
for m in report['messages']:
 name=m['message'].split('.')[-1];reg,index,inst,n,size,run=expected[name];assert int(m['registration_rva'],16)==reg and int(m['default_instance_rva'],16)==inst
 desc=qword(reg+8)-base;length=dword(reg+4);assert int(m['descriptor_rva'],16)==desc and m['descriptor_size']==length
 blob=raw(desc,length);assert hashlib.sha256(blob).hexdigest()==m['descriptor_sha256'];fd=descriptor_pb2.FileDescriptorProto();fd.ParseFromString(blob);msg=fd.message_type[index];assert msg.name==name and len(msg.field)==n
 schemas=qword(reg+0x30)-base;oi,hi,si,sz=struct.unpack('<iiiI',raw(schemas+16*index,16));assert sz==size==m['candidate_object_size'] and oi==m['schema_offsets_index'] and hi==m['schema_hasbit_indices_index'] and si==-1
 offsets=qword(reg+0x40)-base;assert qword((qword(reg+0x38)-base)+8*index)-base==inst;hasbits=dword(offsets+4*oi);assert hasbits==0x10
 assert len(m['fields'])==n
 for j,(f,fr) in enumerate(zip(msg.field,m['fields'])):
  assert fr['field_index']==j and fr['field_name']==f.name and fr['field_number']==f.number
  assert fr['protobuf_type']==descriptor_pb2.FieldDescriptorProto.Type.Name(f.type)
  cell=offsets+4*(oi+8+j);off=dword(cell);bitcell=offsets+4*(hi+j);bit=dword(bitcell)
  assert int(fr['field_offset_table_cell_rva'],16)==cell and int(fr['candidate_object_offset'],16)==off and int(fr['hasbit_table_cell_rva'],16)==bitcell and fr['candidate_hasbit_index']==bit
  wordoff=hasbits+4*(bit//32);mask=1<<(bit%32);assert int(fr['candidate_presence_word_offset'],16)==wordoff and int(fr['candidate_presence_mask'],16)==mask
  assert fr['default_template_presence_bit_set']==bool(dword(inst+wordoff)&mask) and not fr['default_template_presence_bit_set']
  assert fr['runtime_population_observed'] is False and raw(inst+off,fr['candidate_storage_bytes']).hex()==fr['default_template_field_bytes']
  # Independently decode the reported wire-tag varint.
  value=0
  for k,x in enumerate(bytes.fromhex(fr['protobuf_unpacked_tag_varint_hex'])):value|=(x&127)<<(7*k)
  assert value==((f.number<<3)|fr['protobuf_wire_type']);checked+=1
 vt=qword(inst)-base;assert vt==int(m['vtable_candidate_rva'],16);assert len(m['contiguous_executable_pointer_run'])==run
 for j,slot in enumerate(m['contiguous_executable_pointer_run']):assert qword(vt+8*j)-base==int(slot['target_rva'],16) and raw(int(slot['target_rva'],16),16).hex()==slot['target_first_16_bytes']
 nextvalue=qword(vt+8*run)-base;assert not any(va<=nextvalue<va+sz and flags&0x20000000 for va,sz,fo,flags in sections)
scan=json.loads((w/'message-reference-candidates.json').read_text())
assert scan['source_sha256']==sha and len(scan['target_rvas'])==9
for sec in scan['executable_sections_scanned']:
 assert hashlib.sha256(raw(int(sec['rva'],16),sec['raw_size'])).hexdigest()==sec['sha256']
assert scan['candidates']==len(scan['references'])==0
qa={'status':'pass_for_byte_and_report_checks_only','source_sha256':sha,'messages_checked':2,'field_layout_rows_checked':checked,'object_size_candidates':[88,376],'contiguous_executable_pointer_runs':[5,10],'default_templates_have_no_selected_presence_bits_set':True,'runtime_empty_payload_inferred':False,'ABI_proven_identical_to_upstream_protobuf':False,'exact_target_RIP_relative_candidate_count':0,'target_addresses_scanned':9,'collector_identified':False,'serializer_for_selected_message_identified':False,'network_destination_or_port_for_selected_message_proven':False,'native_input_execution_emulation_patch':False,'limits':'Validates file-derived structural consistency, not executed code, live object contents, serializer method identity or transport.'}
if not a.report:(w/'QA.json').write_text(json.dumps(qa,indent=2)+'\n')
print('Verified',checked,'layout rows; no runtime inference.')
