from pathlib import Path
import hashlib,json,struct,subprocess,tempfile
root=Path('/data/wlab-slot-provenance');b=Path('/data/wlab-inputs/wow_loader.dll').read_bytes();h=hashlib.sha256(b).hexdigest();r=json.loads((root/'provenance.json').read_text());assert h==r['sha256']=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
pe=struct.unpack_from('<I',b,60)[0];opt=pe+24;ss=[]
for k in range(struct.unpack_from('<H',b,pe+6)[0]):
 s=opt+struct.unpack_from('<H',b,pe+20)[0]+k*40;vs,va,rs,raw=struct.unpack_from('<IIII',b,s+8);ss.append((va,vs,raw,rs))
def read(r,n):
 for va,vs,raw,rs in ss:
  if va<=r and r+n<=va+max(vs,rs):assert r+n<=va+rs;return b[raw+r-va:raw+r-va+n]
 raise AssertionError(hex(r))
def i32(r):return struct.unpack('<i',read(r,4))[0]
path=r['dispatch_path_to_frontier']
for idx,n in enumerate(path):
 a=n['rva'];raw=bytes.fromhex(n['bytes']);assert read(a,len(raw))==raw
 if idx+1<len(path):
  dsts=[a+len(raw)]
  if raw[0]==15 and 0x80<=raw[1]<=0x8f:dsts.append(a+6+struct.unpack('<i',raw[2:])[0])
  elif 0x70<=raw[0]<=0x7f:dsts.append(a+2+struct.unpack('<b',raw[1:])[0])
  assert path[idx+1]['rva'] in dsts
assert read(0x902e0c,2).hex()=='31c9';assert read(0x902e0e,2).hex()=='ff15';assert 0x902e14+i32(0x902e10)==0x20a0750
assert read(0x902e14,8).hex()=='4889842438030000'
assert read(0x90593b,15).hex()=='488b8424380300004889057e648901';assert 0x90594a+i32(0x905946)==0x219bdc8
assert struct.unpack('<Q',read(0x20a0750,8))[0]==0x20a1a98
assert read(0x20a1a98,30)==bytes(30)
# Independent decode of all reported exact candidates, dispatcher nodes and source block.
items={n['rva']:n for n in path+r['initialization_block']+r['stack_slot_candidates']};ordered=sorted(items.values(),key=lambda n:n['rva'])
packed=b''.join(bytes.fromhex(n['bytes'])+b'\xcc'*(16-len(bytes.fromhex(n['bytes']))) for n in ordered)
with tempfile.TemporaryDirectory() as td:
 f=Path(td)/'code.bin';f.write_bytes(packed)
 output=subprocess.run(['objdump','-D','-b','binary','-m','i386:x86-64','-M','intel','--insn-width=16',str(f)],capture_output=True,text=True,check=True).stdout
 decoded={}
 for line in output.splitlines():
  parts=line.split('\t')
  if len(parts)<3:continue
  try:a=int(parts[0].strip().rstrip(':'),16)
  except ValueError:continue
  if a%16==0:decoded[a//16]=bytes.fromhex(parts[1].strip())
 for idx,n in enumerate(ordered):
  raw=bytes.fromhex(n['bytes']);assert decoded[idx]==raw==read(n['rva'],len(raw))
# Exact identity/continuity check: preceding CALL ends precisely where RAX is saved.
call=r['return_origin']['call_site'];store=r['return_origin']['store_site'];assert call+6==store
v={'fresh_stdlib_pe_parser':True,'independent_objdump_instruction_boundaries':len(ordered),'syntactic_dispatcher_path_verified':True,'initialization_block_bytes_verified':True,'call_ends_at_return_store':True,'call_slot_and_downstream_destination_verified':True,'disk_name_candidate_empty_verified':True,'claims_not_proven':['runtime API identity','earlier calls return normally','local predicate enables block','initialization block executes before downstream store','complete alias analysis','runtime pointer value','target-page preparation','CPU/BIOS sending']}
(root/'verification.json').write_text(json.dumps(v,indent=2));print(json.dumps(v))
