from pathlib import Path
import json,struct,hashlib,subprocess,tempfile
root=Path('/data/wlab-interrupt-slot-review');b=Path('/data/wlab-inputs/wow_loader.dll').read_bytes();h=hashlib.sha256(b).hexdigest();assert h=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
# Fresh stdlib PE parser; no pe_manual, Capstone, numpy or Z3.
pe=struct.unpack_from('<I',b,60)[0];opt=pe+24;sections=[]
for k in range(struct.unpack_from('<H',b,pe+6)[0]):
 s=opt+struct.unpack_from('<H',b,pe+20)[0]+k*40;vs,va,rs,raw=struct.unpack_from('<IIII',b,s+8);sections.append((va,vs,raw,rs))
def read(r,n):
 for va,vs,raw,rs in sections:
  if va<=r and r+n<=va+max(vs,rs):assert r+n<=va+rs;return b[raw+r-va:raw+r-va+n]
 raise AssertionError(hex(r))
def i32(r):return struct.unpack('<i',read(r,4))[0]
e=json.loads((root/'evidence.json').read_text());w=json.loads((root/'writer-path.json').read_text());assert e['sha256']==w['sha256']==h
assert read(0x74a8e0,16)==bytes.fromhex('cd2c'+'cc'*14)
assert read(0xdeea24,1)==b'\xe8' and 0xdeea29+i32(0xdeea25)==0x74a8e0
# Verify each byte of the initial state expression's original arithmetic.
a=0x902a97;assert read(a,2)==b'\x8b\x05';assert a+6+i32(a+2)==w['initial_global_rva']
expected=bytes.fromhex('89c181f1')+struct.pack('<I',0x9cd9d325)+bytes.fromhex('35')+struct.pack('<I',0x9d1bc029)+bytes.fromhex('01c181c1')+struct.pack('<I',0xf55ae0d7)+bytes.fromhex('05')+struct.pack('<I',0x343f518a)+bytes.fromhex('31c1')
assert read(a+6,len(expected))==expected
assert read(0x902ad7,2)==bytes.fromhex('eb7b') and 0x902ad9+0x7b==w['path'][0]['rva']
mask=0xffffffff;x=w['witness_global_u32'];a=(x^0x9d1bc029);state=(((x^0x9cd9d325)+a+0xf55ae0d7)&mask)^((a+0x343f518a)&mask);assert state==w['witness_state_u32']
def signed(v):return v if v<0x80000000 else v-0x100000000
last=None
for index,n in enumerate(w['path']):
 a=n['rva'];raw=bytes.fromhex(n['bytes']);assert raw==read(a,len(raw));next_=a+len(raw)
 if raw==bytes.fromhex('8b442430'):pass
 elif raw[0]==0x3d:last=struct.unpack('<I',raw[1:])[0]
 elif raw[0] in [0x75,0x74,0x7f,0x7e,0x7c,0x7d] or raw[0]==0x0f and raw[1] in [0x85,0x84,0x8f,0x8e,0x8c,0x8d]:
  op=raw[1]-0x10 if raw[0]==15 else raw[0]
  pred={0x75:state!=last,0x74:state==last,0x7f:signed(state)>signed(last),0x7e:signed(state)<=signed(last),0x7c:signed(state)<signed(last),0x7d:signed(state)>=signed(last)}[op]
  dst=next_+(struct.unpack('<i',raw[2:])[0] if raw[0]==15 else struct.unpack('<b',raw[1:])[0]);assert pred==n['taken'];next_=dst if pred else next_
 else:assert index==len(w['path'])-1 and raw==bytes.fromhex('488b842438030000')
 if index+1<len(w['path']):assert next_==w['path'][index+1]['rva']
assert read(0x90593b,15).hex()=='488b8424380300004889057e648901';assert 0x90594a+i32(0x905946)==0x219bdc8
assert read(0x1f4dc80,7).hex()=='48ff2541e12400';assert 0x1f4dc87+i32(0x1f4dc83)==0x219bdc8
try:read(0x219bdc8,8);raise RuntimeError('slot unexpectedly backed')
except AssertionError:pass
# Independent decoder checks on entry prefix, store block, trap stub and wrapper.
checked=0
for address,length in [(0x902a40,0x99),(0x90593b,15),(0x74a8e0,16),(0xdeea10,26)]:
 with tempfile.TemporaryDirectory() as td:
  f=Path(td)/'code.bin';f.write_bytes(read(address,length))
  text=subprocess.run(['objdump','-D','-b','binary','-m','i386:x86-64','-M','intel','--insn-width=16','--adjust-vma='+hex(address),str(f)],text=True,capture_output=True,check=True).stdout
  decoded=[]
  for line in text.splitlines():
   parts=line.split('\t')
   if len(parts)<3:continue
   try:a=int(parts[0].strip().rstrip(':'),16)
   except ValueError:continue
   decoded.append((a,bytes.fromhex(parts[1].strip()),parts[2].strip()))
  assert b''.join(v[1] for v in decoded)==read(address,length)
  assert all('(bad)' not in v[2] for v in decoded)
  if address==0x74a8e0:assert decoded[0][2].replace(' ','')=='int0x2c'
  if address==0x90593b:assert decoded[0][0]==address and decoded[1][0]==0x905943
  if address==0x902a40:assert not any(v[2].split()[0]=='call' for v in decoded) and decoded[-1][2].split()[0]=='jmp'
  checked+=len(decoded)
v={'fresh_pe_parser':True,'concrete_smt_witness_path_verified_from_raw_branches':True,'initial_state_arithmetic_bytes_verified':True,'independent_objdump_decoded_instructions':checked,'store_boundary_and_destination_verified':True,'known_thunk_and_store_share_slot':True,'slot_not_file_backed_verified':True,'raw_scan_completeness_independently_verified':False,'runtime_execution_proven':False,'runtime_pointer_recovered':False,'scope':'Confirms bounded evidence and a satisfiable offline path model. Does not prove actual global values, initialization of local slot 0x338, runtime execution, exception disposition or page decryption.'}
(root/'verification.json').write_text(json.dumps(v,indent=2));print(json.dumps(v))
