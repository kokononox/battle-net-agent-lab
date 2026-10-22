"""Static protobuf-layout candidate mapping; never executes input code."""
from pathlib import Path
import argparse,sys,os,hashlib,struct,json
sys.path.insert(0,os.environ.get('RE_TOOLS','/data/re-tools'))
import pefile
from google.protobuf import descriptor_pb2
p=argparse.ArgumentParser();p.add_argument('--input',type=Path,default=Path('/data/raw/wow-retail-20261022/Wow.exe'));p.add_argument('--out',type=Path,default=Path(__file__).parent);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
b=a.input.read_bytes();sha=hashlib.sha256(b).hexdigest();assert sha=='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a';pe=pefile.PE(data=b,fast_load=True);base=pe.OPTIONAL_HEADER.ImageBase
u32=lambda r:struct.unpack('<I',pe.get_data(r,4))[0]
u64=lambda r:struct.unpack('<Q',pe.get_data(r,8))[0]
configs=[('ClientSystemSpec',0x47c7dc0,1,0x4855470),('ClientEngineLogV2',0x47cebb0,0,0x4856510)]
# protobuf wire representation is distinct from C++ field storage.
wire={1:1,2:5,3:0,4:0,5:0,6:1,7:5,8:0,9:2,10:3,11:2,12:2,13:0,14:0,15:5,16:1,17:0,18:0}
storage={1:8,2:4,3:8,4:8,5:4,6:8,7:4,8:1,9:8,11:8,12:8,13:4,14:4,15:4,16:8,17:4,18:8}
def varint(x):
 bs=[]
 while x>=128:bs.append((x&127)|128);x>>=7
 return bytes(bs+[x]).hex()
results=[];allfields=[]
for name,reg,index,expectedinstance in configs:
 descriptor=u64(reg+8)-base;length=u32(reg+4);raw=pe.get_data(descriptor,length);fd=descriptor_pb2.FileDescriptorProto();fd.ParseFromString(raw);msg=fd.message_type[index];assert msg.name==name and not msg.oneof_decl
 schemas=u64(reg+0x30)-base;instances=u64(reg+0x38)-base;offsets=u64(reg+0x40)-base
 oi,hi,si,obj=struct.unpack('<iiiI',pe.get_data(schemas+index*16,16));assert si==-1
 instance=u64(instances+8*index)-base;assert instance==expectedinstance
 special=[u32(offsets+(oi+j)*4) for j in range(8)];hasbits=special[0];assert hasbits==0x10
 fields=[]
 for j,f in enumerate(msg.field):
  assert f.label!=descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED and f.type!=10 and not f.HasField('oneof_index')
  cell=offsets+(oi+8+j)*4;offset=u32(cell);bitcell=offsets+(hi+j)*4;bit=u32(bitcell);sz=storage[f.type]
  # All selected field offsets have no high/low tag bits; no tagged-offset decoding needed here.
  assert 0<=offset<obj and offset+sz<=obj and 0<=bit<len(msg.field)
  presentword=u32(instance+hasbits+4*(bit//32));defaultbytes=pe.get_data(instance+offset,sz)
  row={'message':name,'field_index':j,'field_name':f.name,'field_number':f.number,'protobuf_type':descriptor_pb2.FieldDescriptorProto.Type.Name(f.type),'optional':f.label==1,'type_name':f.type_name,'field_offset_table_cell_rva':hex(cell),'candidate_object_offset':hex(offset),'candidate_storage_bytes':sz,'hasbit_table_cell_rva':hex(bitcell),'candidate_hasbit_index':bit,'candidate_presence_word_offset':hex(hasbits+4*(bit//32)),'candidate_presence_mask':hex(1<<(bit%32)),'default_template_presence_bit_set':bool(presentword&(1<<(bit%32))),'default_template_field_bytes':defaultbytes.hex(),'protobuf_wire_type':wire[f.type],'protobuf_unpacked_tag_varint_hex':varint((f.number<<3)|wire[f.type]),'runtime_population_observed':False}
  fields.append(row);allfields.append(row)
 assert len({f['candidate_hasbit_index'] for f in fields})==len(fields)
 intervals=sorted((int(f['candidate_object_offset'],16),int(f['candidate_object_offset'],16)+f['candidate_storage_bytes']) for f in fields)
 assert all(e<=ns for (s,e),(ns,ne) in zip(intervals,intervals[1:]))
 vtable=u64(instance)-base;vslots=[]
 for j in range(32):
  value=u64(vtable+8*j);sec=pe.get_section_by_rva(value-base) if value>=base else None
  if not sec or not sec.Characteristics&0x20000000:break
  vslots.append({'slot_index':j,'slot_rva':hex(vtable+8*j),'target_rva':hex(value-base),'target_first_16_bytes':pe.get_data(value-base,16).hex(),'method_role_known':False})
 results.append({'message':fd.package+'.'+name,'descriptor_file':fd.name,'descriptor_rva':hex(descriptor),'descriptor_size':length,'descriptor_sha256':hashlib.sha256(raw).hexdigest(),'registration_rva':hex(reg),'migration_schema_rva':hex(schemas+index*16),'schema_offsets_index':oi,'schema_hasbit_indices_index':hi,'schema_inlined_string_indices_index':si,'candidate_object_size':obj,'offset_array_rva':hex(offsets),'special_offsets_raw':special,'default_instance_rva':hex(instance),'vtable_candidate_rva':hex(vtable),'contiguous_executable_pointer_run':vslots,'contiguous_pointer_run_is_not_proven_vtable_extent':True,'first_non_executable_pointer_slot_rva':hex(vtable+8*len(vslots)),'field_count':len(fields),'fields':fields,'default_instance_is_not_a_live_sample':True})
result={'source_sha256':sha,'layout_model':'Upstream protobuf v30.1 DescriptorTable/MigrationSchema/ReflectionSchema; shipped protobuf_blz fork ABI not independently confirmed. Strong consistency checks are not symbol/runtime proof.','source_reference':['https://raw.githubusercontent.com/protocolbuffers/protobuf/v30.1/src/google/protobuf/generated_message_reflection.h','https://raw.githubusercontent.com/protocolbuffers/protobuf/v30.1/src/google/protobuf/generated_message_reflection.cc'],'messages':results,'input_executed_emulated_or_patched':False,'collector_identified':False,'selected_message_serializer_identified':False,'selected_message_network_binding_proven':False,'field_offsets_are_file_derived_layout_candidates_not_hook_addresses':True}
(a.out/'message-layout.json').write_text(json.dumps(result,indent=2)+'\n')
print('Mapped',len(allfields),'candidate field layouts across',len(results),'messages.')
for m in results:
 print(m['message'],'size',m['candidate_object_size'],'fields',m['field_count'],'contiguous pointer run',len(m['contiguous_executable_pointer_run']),'template presence bits',sum(f['default_template_presence_bit_set'] for f in m['fields']))
 for f in m['fields']:
  if f['field_name'] in ['engine_log','cpu_vendor','cpu_brand','motherboardBiosVersion','motherboardBiosReleaseDate']:print(f['field_name'],f['candidate_object_offset'],'hasbit',f['candidate_hasbit_index'],'wiretag',f['protobuf_unpacked_tag_varint_hex'])
