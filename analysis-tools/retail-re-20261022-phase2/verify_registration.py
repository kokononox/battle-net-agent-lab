"""Independent raw-PE pointer checks; intentionally does not use pefile/capstone."""
from pathlib import Path
import argparse,struct,json,hashlib
from google.protobuf import descriptor_pb2

def verify(binary,report,prior):
 b=binary.read_bytes();x=json.loads(report.read_text());old=json.loads(prior.read_text())
 assert hashlib.sha256(b).hexdigest()==x['source_sha256']==old['source_sha256']
 u16=lambda o:struct.unpack_from('<H',b,o)[0]
 u32=lambda o:struct.unpack_from('<I',b,o)[0]
 u64=lambda o:struct.unpack_from('<Q',b,o)[0]
 assert b[:2]==b'MZ';nt=u32(0x3c);assert b[nt:nt+4]==b'PE\0\0';opt=nt+24;assert u16(opt)==0x20b
 base=u64(opt+24);sections=[]
 for i in range(u16(nt+6)):
  o=opt+u16(nt+20)+i*40;sections.append((u32(o+12),u32(o+16),u32(o+20)))
 def off(r,n=1):
  for va,size,raw in sections:
   if va<=r and r+n<=va+size:return raw+r-va
  raise AssertionError('Not file-backed RVA')
 def ptr(r):return u64(off(r,8))-base
 def cstr(r):return b[off(r):off(r)+200].split(b'\0')[0].decode('ascii')
 rr=u32(opt+112+5*8);rs=u32(opt+116+5*8);o=off(rr,rs);end=o+rs;relocs=set()
 while o<end:
  page=u32(o);size=u32(o+4);assert size>=8 and size%2==0 and o+size<=end
  for q in range(o+8,o+size,2):
   v=u16(q)
   if v>>12==10:relocs.add(page+(v&4095))
  o+=size
 assert len(relocs)==x['dir64_relocations_read']
 checks=[]
 for m in x['messages']:
  selected=next(s for s in old['selected_messages'] if s['message']==m['message'])
  a=int(selected['offset'],16);z=int(selected['end_offset_exclusive'],16);fd=descriptor_pb2.FileDescriptorProto();fd.ParseFromString(b[a:z])
  table=int(m['registration_table_candidate']['rva'],16);slot=int(m['relocation_backed_descriptor_pointer']['rva'],16)
  assert slot==table+8 and slot in relocs
  assert off(ptr(slot))==a and u32(off(table+4,4))==z-a
  assert cstr(ptr(table+16))==fd.name
  assert u32(off(table+44,4))==len(fd.message_type)
  idx=m['selected_message_index'];assert fd.package+'.'+fd.message_type[idx].name==m['message']
  array=ptr(table+56);inst=ptr(array+idx*8);assert hex(inst)==m['default_instance_candidate']['rva']
  assert hex(ptr(inst))==m['vtable_candidate']['rva']
  deps=ptr(table+32)
  for i,d in enumerate(m['dependency_tables']):
   t=ptr(deps+8*i);assert hex(t)==d['table']['rva'];assert cstr(ptr(t+16))==d['filename']
  for e in m['executable_vtable_entry_candidates']:
   assert hex(ptr(int(e['slot']['rva'],16)))==e['target']['rva']
  for e in m['table_exact_incoming_relocation_slots']:
   r=int(e['rva'],16);assert r in relocs and ptr(r)==table
  checks.append({'message':m['message'],'descriptor_pointer_size_filename_count_and_instance_chain':'pass'})
 spec=next(m for m in x['messages'] if m['message'].endswith('.ClientSystemSpec'))
 engine=next(m for m in x['messages'] if m['message'].endswith('.ClientEngineLogV2'))
 assert any(d['table']['rva']==engine['registration_table_candidate']['rva'] for d in spec['dependency_tables'])
 for lit in x['transport_literal_evidence']:
  for hit in lit['occurrences']:
   a=int(hit['file_offset'],16);assert b[a:a+len(lit['literal'])+1]==lit['literal'].encode()+b'\0'
   assert off(int(hit['location']['rva'],16))==a
 for k in ['input_code_executed','hardware_population_proven','selected_message_to_serializer_proven','selected_message_to_http_proven','selected_message_to_realm_3724_proven','absence_of_hardware_on_3724_proven']:assert x[k] is False
 return {'status':'pass','method':'Independent struct-based PE section and DIR64 parser; protobuf decoder for descriptor semantics. No pefile/capstone used in verification.','source_sha256':x['source_sha256'],'dir64_relocations':len(relocs),'messages':checks,'spec_dependency_matches_engine_registration':True,'exact_transport_literals_checked':len(x['transport_literal_evidence']),'runtime_behavior_tested':False,'scope':'Verifies bytes, pointer arithmetic and conservative report flags; does not independently prove inferred C++ layout roles or runtime activity.'}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,default=Path('/data/raw/wow-retail-20261022/Wow.exe'));p.add_argument('--report',type=Path,default=Path('/data/analysis/wow-retail-20261022-phase2/registration-path.json'));p.add_argument('--prior',type=Path,default=Path('/data/analysis/wow-retail-20261022/descriptor-trace.json'));p.add_argument('--output',type=Path,default=Path('/data/analysis/wow-retail-20261022-phase2/QA.json'));a=p.parse_args();r=verify(a.binary,a.report,a.prior);a.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
