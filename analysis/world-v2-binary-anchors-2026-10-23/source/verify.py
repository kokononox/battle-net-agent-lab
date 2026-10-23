"""Stdlib and objdump checks; does not import discovery, reference-scan, or PE helper."""
from pathlib import Path
import os,json,struct,hashlib,re,subprocess
D=Path(__file__).resolve().parents[1];I=Path(os.environ.get('INPUT_DIR','/data/wlab-inputs'));DD=Path(os.environ.get('DUMP_DIR','/data/wlab-crash-dump-review/work'));r=json.loads((D/'reports/discovery.json').read_text());refs=json.loads((D/'reports/references.json').read_text());tri=json.loads((D/'reports/triage.json').read_text());buffers={};sec_by_name={};base_by_name={};proofs=[]
def h(b):return hashlib.sha256(b).hexdigest()
for row in r['binaries']:
 b=(I/row['name']).read_bytes();assert h(b)==row['sha256'];buffers[row['name']]=b;pe=struct.unpack_from('<I',b,0x3c)[0];n=struct.unpack_from('<H',b,pe+6)[0];opt=pe+24;st=opt+struct.unpack_from('<H',b,pe+20)[0];secs=[];base_by_name[row['name']]=struct.unpack_from('<Q',b,opt+24)[0]
 for k in range(n):
  off=st+40*k;vs,va,rs,fo=struct.unpack_from('<IIII',b,off+8);flags=struct.unpack_from('<I',b,off+36)[0];secs.append((va,rs,fo,bool(flags&0x20000000)))
 sec_by_name[row['name']]=secs
 for s in row['strings']:
  expected=[m.start() for m in re.finditer(b'(?='+re.escape(s['pattern'].encode(s['encoding']))+b')',b)];assert expected==[x['file_offset'] for x in s['matches']]
 for v in row['literal_dword_search']:
  pat=v['value'].to_bytes(4,'little');expected=[m.start() for m in re.finditer(b'(?='+re.escape(pat)+b')',b)];assert expected==[x['file_offset'] for x in v['matches']]
  executable=0
  for hit in v['matches']:
   off=hit['file_offset'];sec=next((s for s in secs if s[2]<=off and off+4<=s[2]+s[1]),None);assert (sec[0]+off-sec[2] if sec else None)==hit['rva'];ex=bool(sec and sec[3]);assert ex==hit['executable_section'];executable+=ex
   lo=hit['context_file_offset'];raw=bytes.fromhex(hit['context_hex']);assert b[lo:lo+len(raw)]==raw and h(raw)==hit['context_sha256']
  assert executable==v['executable_match_count']
 proofs.append({'module':row['name'],'sha256_and_string_and_dword_matches_independently_checked':True})
def read(name,rva,n):
 b=buffers[name]
 for va,rs,fo,ex in sec_by_name[name]:
  if va<=rva and rva+n<=va+rs:return b[fo+rva-va:fo+rva-va+n]
 raise AssertionError('unmapped range')
for a in refs['anchors']:
 raw=read('Wow.exe',a['rva'],a['length_including_nul']);assert raw==a['text'].encode()+b'\0' and h(raw)==a['sha256'];assert b'\n' not in raw
for x in refs['rip_candidates']:
 raw=bytes.fromhex(x['bytes']);assert read('Wow.exe',x['rva'],len(raw))==raw;disp=int.from_bytes(raw[x['disp_offset']:x['disp_offset']+4],'little',signed=True);assert x['rva']+len(raw)+disp==x['target_rva']
# Independent DIR64 walk and bounded destination check.
b=buffers['Wow.exe'];pe=struct.unpack_from('<I',b,0x3c)[0];opt=pe+24;rr,sz=struct.unpack_from('<II',b,opt+112+5*8);base=base_by_name['Wow.exe'];at=0;out=[];slots=set()
while at<sz:
 page,n=struct.unpack('<II',read('Wow.exe',rr+at,8));assert n>=8 and at+n<=sz
 for k in range(8,n,2):
  v=int.from_bytes(read('Wow.exe',rr+at+k,2),'little')
  if v>>12!=10:continue
  slot=page+(v&4095);slots.add(slot);dest=int.from_bytes(read('Wow.exe',slot,8),'little')-base
  if any(s['begin']<=dest<s['end'] for s in refs['target_spans']):out.append((slot,dest))
 at+=n
assert sorted(out)==sorted((x['slot_rva'],x['target_rva']) for x in refs['relocation_pointer_candidates'])
assert not any(a['rva']<=dest<a['rva']+a['length_including_nul'] for slot,dest in out for a in refs['anchors'])
for a in refs['anchors']:
 for n,form in [(a['rva'],'<I'),(base+a['rva'],'<Q')]:assert struct.pack(form,n) not in b
for x in r['binaries'][0]['single_auth_session_match_context']['nearby_relocation_backed_strings']:
 assert x['pointer_slot_rva'] in slots;assert int.from_bytes(read('Wow.exe',x['pointer_slot_rva'],8),'little')-base==x['string_rva'];assert read('Wow.exe',x['string_rva'],len(x['string'])+1)==x['string'].encode()+b'\0'
for x in r['binaries'][0]['network_component_context']['nearby_strings']:
 raw=bytearray();a=x['rva']
 while True:
  q=read('Wow.exe',a+len(raw),1);raw+=q
  if q==b'\0':break
  assert len(raw)<1024
 assert h(raw)==x['full_string_sha256'];text=bytes(raw[:-1]).decode();check=text.replace('\\','/').rsplit('/',1)[-1] if x['build_path_redacted'] else text;assert check==x['text_or_basename']
for check in r['existing_dump_checks']:
 if not check['available']:continue
 bb=(DD/check['name']).read_bytes();assert h(bb)==check['sha256']
 for x in check['narrow_string_checks']:
  expected=[m.start() for m in re.finditer(b'(?='+re.escape(x['pattern'].encode(x['encoding']))+b')',bb)];assert expected==x['raw_file_offsets']
# Independent decoder for the sole loader DWORD that forms a direct immediate candidate.
imm=refs['loader_executable_literal_triage'][0]['decoder_immediate_candidates'][0];raw=read('wow_loader.dll',imm['rva'],5);assert raw==bytes.fromhex('3500004c00');f=D/'work/loader-xor.bin';f.write_bytes(raw);o=subprocess.run(['objdump','-D','-b','binary','-m','i386:x86-64',f"--adjust-vma={imm['rva']}",str(f)],capture_output=True,text=True,check=True);assert 'xor' in o.stdout and '0x4c0000' in o.stdout
result={'modules':proofs,'normalized_banner_bytes_and_hashes_checked':2,'rip_candidate_arithmetic_checked':len(refs['rip_candidates']),'dir64_candidates_independently_repeated':len(out),'opcode_context_bytes_checked':sum(len(x['matches']) for row in r['binaries'] for x in row['literal_dword_search']),'nearby_relocated_error_strings_checked':True,'network_component_string_hashes_checked':True,'raw_dump_narrow_searches_repeated':True,'loader_xor_objdump_checked':True,'limits':'Does not independently reimplement full RIP-candidate discovery or establish reachability/semantic dataflow. A numeric immediate and nearby source/type names do not identify the V2 dispatcher or cryptographic initialization function.'}
(D/'reports/verification.json').write_text(json.dumps(result,indent=2)+'\n');print('Verified normalized banners, literal matches and contexts, relocation inventory, dump searches, and loader XOR decoding.')
