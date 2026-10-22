"""Read-only PE metadata tracing. Does not load, emulate or execute input code."""
from pathlib import Path
import argparse,hashlib,json,struct,collections,math,sys,re
sys.path.insert(0,'/data/re-tools')
import pefile
from google.protobuf import descriptor_pb2

def entropy(b):
 c=collections.Counter(b);n=len(b)
 return -sum((x/n)*math.log2(x/n) for x in c.values()) if n else 0

def analyze(input_dir, prior_dir, output_dir):
 b=(input_dir/'Wow.exe').read_bytes(); digest=hashlib.sha256(b).hexdigest()
 assert digest=='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a','Unexpected build'
 pe=pefile.PE(data=b);base=pe.OPTIONAL_HEADER.ImageBase
 prior=json.loads((prior_dir/'descriptor-trace.json').read_text());assert prior['source_sha256']==digest
 def data(r,n):
  s=pe.get_section_by_rva(r)
  if not s:return b''
  delta=r-s.VirtualAddress
  if delta<0 or delta+n>s.SizeOfRawData:return b''
  off=s.PointerToRawData+delta
  return b[off:off+n]
 def u64(r):
  x=data(r,8);assert len(x)==8;return struct.unpack('<Q',x)[0]
 def ptr(r):return u64(r)-base
 def loc(r):
  s=pe.get_section_by_rva(r)
  return {'rva':hex(r),'section':s.Name.decode().rstrip('\0') if s else None,'executable_section':bool(s and s.Characteristics&0x20000000),'backed_by_file':bool(s and 0<=r-s.VirtualAddress<s.SizeOfRawData)}
 def cstring(r):return data(r,200).split(b'\0')[0].decode('ascii')
 incoming=collections.defaultdict(list);reloc_count=0
 for block in pe.DIRECTORY_ENTRY_BASERELOC:
  for e in block.entries:
   if e.type==10 and len(data(e.rva,8))==8:
    incoming[ptr(e.rva)].append(e.rva);reloc_count+=1
 traces=[]
 for selected in prior['selected_messages']:
  a=int(selected['offset'],16);z=int(selected['end_offset_exclusive'],16)
  fd=descriptor_pb2.FileDescriptorProto();fd.ParseFromString(b[a:z]);schema_rva=pe.get_rva_from_offset(a)
  assert len(incoming[schema_rva])==1
  slot=incoming[schema_rva][0];table=slot-8
  # DescriptorTable-layout hypothesis, checked independently against serialized data.
  header=data(table,8);size=struct.unpack_from('<I',header,4)[0]
  assert size==z-a
  filename=cstring(ptr(table+16));assert filename==fd.name
  deps,nmsg=struct.unpack('<II',data(table+40,8));assert nmsg==len(fd.message_type)
  dependency_array=ptr(table+32)
  dependency_tables=[]
  for dep_index in range(deps):
   dep=ptr(dependency_array+8*dep_index)
   dependency_tables.append({'table':loc(dep),'filename':cstring(ptr(dep+16))})
  instances=ptr(table+56)
  index=next(i for i,m in enumerate(fd.message_type) if fd.package+'.'+m.name==selected['message'])
  instance=ptr(instances+8*index);vtable=ptr(instance)
  assert not loc(instance)['executable_section'];assert not loc(vtable)['executable_section']
  entries=[]
  for k in range(16):
   slot_rva=vtable+8*k
   target=ptr(slot_rva);l=loc(target)
   if l['executable_section']:
    entries.append({'slot_index':k,'slot':loc(slot_rva),'target':l,'target_4096_bytes_entropy':entropy(data(target,4096)),'runtime_role':'unresolved; vtable candidate does not identify a hardware collector or sender'})
  traces.append({'message':selected['message'],'descriptor_filename':fd.name,'serialized_descriptor':{'location':loc(schema_rva),'size':size,'sha256':hashlib.sha256(b[a:z]).hexdigest()},'relocation_backed_descriptor_pointer':loc(slot),'registration_table_candidate':loc(table),'layout_checks':{'descriptor_size_matches':True,'filename_matches':True,'top_level_message_count_matches':True,'message_count':nmsg,'dependency_count':deps},'dependency_tables':dependency_tables,'default_instance_array_candidate':loc(instances),'selected_message_index':index,'default_instance_candidate':loc(instance),'vtable_candidate':loc(vtable),'vtable_scan_scope':'First 16 pointer-sized slots only; exact vtable extent and method identities not established','executable_vtable_entry_candidates':entries,'table_exact_incoming_relocation_slots':[loc(x) for x in incoming[table]],'instance_exact_incoming_relocation_slots':[loc(x) for x in incoming[instance]],'interpretation':'Absolute pointer and byte checks establish generated-message metadata scaffolding. DescriptorTable/default-instance/vtable roles are layout-based candidates; no runtime population, serialization call or network edge is established.'})
 patterns=[('default_ingest_url','https://telemetry-in.battle.net'),('ingest_option_diagnostic','ValidateOptions: ServiceOptions.ingestBaseUrl %s is invalid'),('serializer_diagnostic','MessageEnqueuer EnqueueMessageLite: Could not serialize message %s /%s'),('http_transport_diagnostic','Service config: Using default HTTP request handler'),('curl_initialization_diagnostic','CurlHttpRequestHandler Initialize: curl_multi_init failure'),('http_post_diagnostic','CurlRequest: curl_easy_setopt CURLOPT_POST error: %d (%s)'),('sdk_identifier','telemetry-sdk-cpp/'),('sdk_version_literal','2.0.0+protobuf_blz-6.30.1')]
 literals=[]
 for label,text in patterns:
  hits=[];needle=text.encode()+b'\0'
  for m in re.finditer(re.escape(needle),b):
   r=pe.get_rva_from_offset(m.start());hits.append({'file_offset':hex(m.start()),'location':loc(r),'exact_incoming_relocation_slots':[loc(x) for x in incoming[r]]})
  assert hits,text
  literals.append({'label':label,'literal':text,'occurrences':hits,'evidence_level':'static literal only; co-location and naming do not establish a call graph or actual send'})
 result={'analysis':'phase2-generated-message-registration-and-transport-leads','source_sha256':digest,'dir64_relocations_read':reloc_count,'messages':traces,'transport_literal_evidence':literals,'input_code_executed':False,'hardware_population_proven':False,'selected_message_to_serializer_proven':False,'selected_message_to_http_proven':False,'selected_message_to_realm_3724_proven':False,'absence_of_hardware_on_3724_proven':False,'limitation':'Main executable code bytes have prior independently measured near-maximal entropy. Data/vtable edges end in code whose semantics are not recovered. This is not complete decompilation; dynamic or computed references and additional transports remain unresolved.'}
 output_dir.mkdir(parents=True,exist_ok=True);(output_dir/'registration-path.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'messages':[{'message':t['message'],'table':t['registration_table_candidate']['rva'],'instance':t['default_instance_candidate']['rva'],'vtable_targets':len(t['executable_vtable_entry_candidates'])} for t in traces],'transport_literals':len(literals),'dir64_relocations_read':reloc_count},indent=2))
 return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--input-dir',type=Path,default=Path('/data/raw/wow-retail-20261022'));p.add_argument('--prior-dir',type=Path,default=Path('/data/analysis/wow-retail-20261022'));p.add_argument('--output-dir',type=Path,default=Path('/data/analysis/wow-retail-20261022-phase2'));a=p.parse_args();analyze(a.input_dir,a.prior_dir,a.output_dir)
