"""Independent raw PE, ZIP, hashes, entropy and layout consistency checks."""
from pathlib import Path
import argparse,struct,hashlib,zipfile,json,math
from collections import Counter
from google.protobuf import descriptor_pb2
p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,default=Path('/data/.agent-service/files/ba3b1862-6acd-435e-928d-577829864131/_retail_old.zip'));p.add_argument('--old',type=Path,default=Path('/data/raw/wow-retail-old'));p.add_argument('--baseline',type=Path,default=Path('/data/raw/wow-retail-20261022'));p.add_argument('--out',type=Path,default=Path(__file__).parent);a=p.parse_args();w=a.out
profile=json.loads((w/'binary-comparison.json').read_text());descs=json.loads((w/'descriptor-comparison.json').read_text());reg=json.loads((w/'registration-comparison.json').read_text())
assert hashlib.sha256(a.archive.read_bytes()).hexdigest()==profile['archive_sha256']=='ac66e5a4e17747c20483dec508210fb8057e43f862a52a3f0f88596e6db6d4e2'
with zipfile.ZipFile(a.archive) as z:
 assert set(z.namelist())=={'Wow.exe','wow_loader.dll','libxell.dll'} and len(z.namelist())==3
 for name in z.namelist():assert hashlib.sha256(z.read(name)).hexdigest()==hashlib.sha256((a.old/name).read_bytes()).hexdigest()
def parse(path):
 b=path.read_bytes();u16=lambda o:struct.unpack_from('<H',b,o)[0];u32=lambda o:struct.unpack_from('<I',b,o)[0]
 nt=u32(0x3c);assert b[:2]==b'MZ' and b[nt:nt+4]==b'PE\0\0';opt=nt+24;assert u16(opt)==0x20b;base=struct.unpack_from('<Q',b,opt+24)[0]
 ss=[]
 for j in range(u16(nt+6)):
  o=opt+u16(nt+20)+40*j;ss.append((b[o:o+8].rstrip(b'\0').decode(),u32(o+12),u32(o+16),u32(o+20)))
 def raw(r,n):
  for name,va,size,off in ss:
   if va<=r and r+n<=va+size:return b[off+r-va:off+r-va+n]
  raise AssertionError('No raw RVA')
 return b,opt,base,ss,raw
counts=[]
for row in profile['comparison']:
 for kind,root in [('uploaded_old',a.old),('previous_baseline',a.baseline)]:
  r=row[kind];b,opt,base,ss,raw=parse(root/r['name']);assert len(b)==r['bytes'] and hashlib.sha256(b).hexdigest()==r['sha256']
  entry=struct.unpack_from('<I',b,opt+16)[0];assert hex(entry)==r['entry_rva'] and raw(entry,32).hex()==r['entry_first_32_bytes']
  for s in r['sections']:
   bs=raw(int(s['rva'],16),s['raw_size']);assert hashlib.sha256(bs).hexdigest()==s['sha256']
  if r['name']=='Wow.exe':
   sec=next(s for s in r['sections'] if s['name']=='.text');bs=raw(int(sec['rva'],16),sec['raw_size']);values=[]
   for k in range(0,len(bs),65536):
    part=bs[k:k+65536];c=Counter(part);values.append(-sum((n/len(part))*math.log2(n/len(part)) for n in c.values()))
   high=sum(h>7.9 for h in values);assert high==r['text_blocks_entropy_gt_7_9'] and len(values)==r['text_64KiB_blocks'];counts.append({'file':kind,'high_entropy_blocks':high,'total_blocks':len(values)})
   d=struct.unpack_from('<I',b,opt+112+8)[0];imp=struct.unpack('<IIIII',raw(d,20));assert raw(d+20,20)==b'\0'*20
   thunk=struct.unpack('<Q',raw(imp[0] or imp[4],8))[0];assert thunk==(1<<63)|1 and raw((imp[0] or imp[4])+8,8)==b'\0'*8
for label,root in [('old',a.old),('baseline',a.baseline)]:
 b,opt,base,ss,raw=parse(root/'Wow.exe')
 def u32(r):return struct.unpack('<I',raw(r,4))[0]
 def u64(r):return struct.unpack('<Q',raw(r,8))[0]
 relocdir=struct.unpack_from('<II',b,opt+112+5*8);relocs=set();cur=relocdir[0];limit=cur+relocdir[1]
 while cur+8<=limit:
  page,size=struct.unpack('<II',raw(cur,8));assert size>=8 and cur+size<=limit
  for k in range(8,size,2):
   e=struct.unpack('<H',raw(cur+k,2))[0]
   if e>>12==10:relocs.add(page+(e&4095))
  cur+=size
 for dm in descs[label]['selected_messages']:
  blob=raw(int(dm['descriptor_rva'],16),dm['descriptor_size']);assert hashlib.sha256(blob).hexdigest()==dm['descriptor_sha256'];fd=descriptor_pb2.FileDescriptorProto();fd.ParseFromString(blob)
  m=next(x for x in fd.message_type if fd.package+'.'+x.name==dm['message']);assert len(m.field)==len(dm['fields'])
 for rm in reg[label]['messages']:
  table=int(rm['registration_table_candidate_rva'],16);drva=int(rm['descriptor_rva'],16);assert table+8 in relocs and u64(table+8)==base+drva
  index=1 if rm['message'].endswith('.ClientSystemSpec') else 0
  schema=u64(table+0x30)-base;offsets=u64(table+0x40)-base;oi,hi,si,sz=struct.unpack('<iiiI',raw(schema+16*index,16));assert sz==rm['candidate_object_size']
  inst=u64(u64(table+0x38)-base+index*8)-base;assert inst==int(rm['default_instance_rva'],16)
  for j,f in enumerate(rm['fields']):assert hex(u32(offsets+4*(oi+8+j)))==f['object_offset_candidate'] and u32(offsets+4*(hi+j))==f['hasbit_index_candidate']
  vt=u64(inst)-base;assert vt==int(rm['vtable_candidate_rva'],16)
  for method in rm['method_candidates_contiguous_run']:assert u64(vt+8*method['slot'])-base==int(method['target_rva'],16)
# Descriptor equality is rechecked on the raw byte slices, not merely the reported hashes.
for old in descs['old']['selected_messages']:
 new=next(x for x in descs['baseline']['selected_messages'] if x['message']==old['message'])
 ob=parse(a.old/'Wow.exe')[4](int(old['descriptor_rva'],16),old['descriptor_size']);nb=parse(a.baseline/'Wow.exe')[4](int(new['descriptor_rva'],16),new['descriptor_size']);assert ob==nb
assert all(x['field_offsets_and_hasbits_identical'] and not x['method_candidate_RVAs_identical'] for x in reg['comparison'])
lib=next(x for x in profile['comparison'] if x['uploaded_old']['name']=='libxell.dll');assert lib['identical_whole_file'] and (a.old/'libxell.dll').read_bytes()==(a.baseline/'libxell.dll').read_bytes()
qa={'status':'pass_for_static_file_and_comparison_checks','zip_members_crc_and_extracted_hashes_checked':True,'six_PE_file_hashes_and_sections_checked':True,'main_EXE_entropy_blocks_independently_recomputed':counts,'two_selected_descriptor_byte_ranges_identical_across_builds':True,'selected_field_layouts_and_hasbits_identical':True,'method_RVAs_interchangeable':False,'libxell_whole_file_identical':True,'upstream_layout_ABI_identity_proven':False,'code_unpacked_or_semantically_recovered':False,'input_native_execution_emulation_attach_or_patch':False,'hardware_message_population_or_transport_proven':False,'binary_upload_authorized_or_performed_this_stage':False}
(w/'QA.json').write_text(json.dumps(qa,indent=2)+'\n');print(json.dumps(qa,indent=2))
