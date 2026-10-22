from pathlib import Path
import sys,json,hashlib,re,struct
sys.path.insert(0,'/data/re-tools')
import pefile
from google.protobuf import descriptor_pb2
import argparse
parser=argparse.ArgumentParser(description='Offline PE analysis; never runs input executables')
parser.add_argument('--input-dir',type=Path,default=Path('/data/raw/wow-retail-20261022'))
parser.add_argument('--output-dir',type=Path,default=Path('/data/analysis/wow-retail-20261022'))
parser.add_argument('--prior-report',type=Path,default=Path('/data/raw/wow-repo-review/hardware_relationship.json'))
args=parser.parse_args()
root=args.input_dir;out=args.output_dir;out.mkdir(parents=True,exist_ok=True)
b=(root/'Wow.exe').read_bytes();pe=pefile.PE(data=b,fast_load=True)
def varint(a,p):
 v=0
 for n in range(10):
  if p>=len(a):raise ValueError('EOF')
  k=a[p];p+=1;v|=(k&127)<<(7*n)
  if k<128:return v,p
 raise ValueError('varint')
def descriptor_end(start):
 p=start;seenname=False
 while p<len(b):
  q=p;tag,p=varint(b,p);field=tag>>3;wire=tag&7
  if not field or field>14 or (field==1 and seenname):return q
  if field==1:seenname=True
  if wire==0:_,p=varint(b,p)
  elif wire==1:p+=8
  elif wire==2:n,p=varint(b,p);p+=n
  elif wire==5:p+=4
  else:return q
  if p>len(b):return q
 return p
records=[];seen=set()
for m in re.finditer(rb'([A-Za-z][A-Za-z0-9_/.-]{1,160}\.proto)',b):
 name=m[1]
 # FileDescriptorProto.name is the first field, with a protobuf length prefix.
 for start in range(max(0,m.start()-4),m.start()):
  if b[start]!=10:continue
  try:
   n,p=varint(b,start+1)
   if p!=m.start() or n!=len(name):continue
   end=descriptor_end(start);fd=descriptor_pb2.FileDescriptorProto();fd.ParseFromString(b[start:end])
   if fd.name.encode()!=name or not fd.package.startswith('Blizzard.Telemetry') or (fd.name,fd.package) in seen:continue
   seen.add((fd.name,fd.package));records.append((start,end,fd))
  except Exception:continue
selected=[]
for start,end,fd in records:
 for msg in fd.message_type:
  full=fd.package+'.'+msg.name
  if msg.name not in ['ClientSystemSpec','ClientEngineLogV2']:continue
  fields=[{'name':f.name,'number':f.number,'label':f.label,'type':f.type,'type_name':f.type_name or None} for f in msg.field]
  selected.append({'message':full,'descriptor':fd.name,'offset':hex(start),'end_offset_exclusive':hex(end),'descriptor_sha256':hashlib.sha256(b[start:end]).hexdigest(),'message_options_hex':msg.options.SerializeToString().hex(),'fields':fields})
assert len(selected)==2,[(x['message'],x['descriptor']) for x in selected]
wrap=next(x for x in selected if x['message'].endswith('.ClientSystemSpec'));engine=next(x for x in selected if x['message'].endswith('.ClientEngineLogV2'))
assert any(f['name']=='engine_log' and f['number']==1 and f['type_name']=='.'+engine['message'] for f in wrap['fields'])
prior=json.loads(args.prior_report.read_text())
for f in prior['selected_hardware_fields']:
 assert any(x['name']==f['name'] and x['number']==f['number'] for x in engine['fields'])
# Reference arithmetic is data-only evidence, not a call graph.
refs=[]
for term in [b'ClientSystemSpec',b'ClientEngineLogV2',b'cpu_vendor',b'cpu_brand',b'motherboardBiosVersion',b'telemetry-in.battle.net']:
 hits=[];off=0
 while (off:=b.find(term,off))>=0:
  rva=pe.get_rva_from_offset(off);va=pe.OPTIONAL_HEADER.ImageBase+rva;needle=struct.pack('<Q',va)
  pointers=[hex(m.start()) for m in re.finditer(re.escape(needle),b)]
  hits.append({'file_offset':hex(off),'rva':hex(rva),'absolute_va_pointer_file_offsets':pointers});off+=len(term)
 refs.append({'term':term.decode(),'occurrences':hits})
report={'source_sha256':hashlib.sha256(b).hexdigest(),'telemetry_file_descriptors_recovered':len(records),'selected_messages':selected,'schema_wrapper_edge_reverified':True,'selected_fields_match_prior_report':True,'data_pointer_references':refs,'runtime_hardware_population_proven':False,'runtime_send_proven':False,'destination_or_port_binding_proven':False,'note':'All references are file/data locations. They are not verified runtime functions, hook points, or evidence of transmission.'}
(out/'descriptor-trace.json').write_text(json.dumps(report,indent=2)+'\n')
print('Descriptors:',len(records));print('Messages:',[(x['message'],len(x['fields'])) for x in selected]);print('Hardware fields independently reverified:',len(prior['selected_hardware_fields']));print('Wrapper edge reverified:',report['schema_wrapper_edge_reverified']);print('Absolute pointer counts:',[(r['term'],sum(len(x['absolute_va_pointer_file_offsets']) for x in r['occurrences'])) for r in refs])
