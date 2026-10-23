from pathlib import Path
import json,hashlib,struct,collections,re,subprocess,tempfile
root=Path('/data/wlab-handler-triage');b=Path('/data/wlab-inputs/wow_loader.dll').read_bytes();h=hashlib.sha256(b).hexdigest();assert h=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
# Fresh stdlib parsing, no pe_manual, Capstone or Z3.
pe=struct.unpack_from('<I',b,60)[0];assert b[pe:pe+4]==b'PE\0\0';opt=pe+24;sections=[]
for k in range(struct.unpack_from('<H',b,pe+6)[0]):
 s=opt+struct.unpack_from('<H',b,pe+20)[0]+k*40
 vs,va,rs,raw=struct.unpack_from('<IIII',b,s+8);sections.append((va,vs,raw,rs))
def read(r,n):
 for va,vs,raw,rs in sections:
  if va<=r and r+n<=va+max(vs,rs):
   assert r+n<=va+rs,('not file backed',hex(r));return b[raw+r-va:raw+r-va+n]
 raise AssertionError(('unmapped',hex(r)))
def u(r):return struct.unpack('<I',read(r,4))[0]
s,z=struct.unpack_from('<II',b,opt+112+3*8);functions={}
for a in range(s,s+z,12):
 begin,end,uw=struct.unpack('<III',read(a,12));functions[begin]=(end,uw)
scopes=json.loads((root/'scope-tables.json').read_text());callbacks=json.loads((root/'callback-prefixes.json').read_text());triage=json.loads((root/'triage.json').read_text());assert scopes['sha256']==callbacks['sha256']==triage['sha256']==h
counts=collections.Counter();record_count=0
for t in scopes['tables']:
 end,uw=functions[t['function_begin']];assert end==t['function_end'];head=read(uw,4);assert (head[0]&7)==1 and head[0]>>3&3
 hd=uw+4+((head[2]*2+3)&~3)+4;assert hd==t['handler_data_rva'];assert u(hd-4)==t['handler_rva'];assert u(hd)==len(t['scopes'])==t['scope_count']
 for k,x in enumerate(t['scopes']):
  vals=struct.unpack('<IIII',read(hd+4+16*k,16));assert vals==(x['begin'],x['end'],x['filter_or_finally'],x['jump_target']);record_count+=1
  if vals[2] not in [0,1,0xffffffff]:counts[hex(vals[2])]+=1
assert dict(counts)==scopes['callback_counts'];assert len(callbacks['callbacks'])==len(counts)
allnodes={}
for f in triage['functions']:
 for n in f.get('nodes',[]):allnodes[n['rva']]=n
for row in callbacks['callbacks']:
 assert hex(row['rva']) in counts
 for n in row['instructions']:allnodes[n['rva']]=n
 for link in row['scope_links']:
  assert link['scope']['filter_or_finally']==row['rva']
  assert any(t['function_begin']==link['function_begin'] and t['handler_data_rva']==link['handler_data_rva'] and link['scope'] in t['scopes'] for t in scopes['tables'])
for a,n in allnodes.items():assert read(a,len(bytes.fromhex(n['bytes']))).hex()==n['bytes']
items=sorted(allnodes.values(),key=lambda n:n['rva']);packed=b''.join(bytes.fromhex(n['bytes'])+b'\xcc'*(16-len(bytes.fromhex(n['bytes']))) for n in items)
with tempfile.TemporaryDirectory() as td:
 p=Path(td)/'instructions.bin';p.write_bytes(packed)
 text=subprocess.run(['objdump','-D','-b','binary','-m','i386:x86-64','-M','intel','--insn-width=16',str(p)],capture_output=True,text=True,check=True).stdout
 decoded={}
 for line in text.splitlines():
  parts=line.split('\t')
  if len(parts)<3:continue
  try:a=int(parts[0].strip().rstrip(':'),16)
  except ValueError:continue
  if a%16==0:decoded[a//16]=bytes.fromhex(parts[1].strip())
 for i,n in enumerate(items):assert decoded[i]==bytes.fromhex(n['bytes'])
assert read(0x17dcd50,6).hex()=='b8ffffffffc3'
thunk=next(x for x in callbacks['callbacks'] if x['rva']==0x1f4dc80);n=thunk['instructions'][0];raw=bytes.fromhex(n['bytes']);assert raw[:3]==bytes.fromhex('48ff25');slot=n['rva']+len(raw)+struct.unpack('<i',raw[-4:])[0];assert slot==thunk['disk_indirect_slot']['rva'];assert thunk['disk_indirect_slot']['qword'] is None
try:read(slot,8);raise RuntimeError('slot unexpectedly file backed')
except AssertionError:pass
v={'fresh_pe_parser':True,'scope_tables_verified':len(scopes['tables']),'scope_records_verified':record_count,'distinct_callbacks_verified':len(counts),'unique_instruction_boundaries_verified_with_objdump':len(items),'constant_minus_one_stub_verified':True,'indirect_slot_virtual_only_verified':True,'custom_filter_complete_cfg_verified':False,'scope':'Metadata links and decoded prefixes, not complete semantics, callback execution, decryption, or page preparation.'}
(root/'verification.json').write_text(json.dumps(v,indent=2));print(json.dumps(v))
