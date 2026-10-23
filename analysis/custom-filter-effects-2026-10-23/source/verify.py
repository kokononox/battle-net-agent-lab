"""Independent boundary/effect/stack review using GNU objdump and stdlib PE reader."""
from pathlib import Path
from pe_manual import PE
import json,hashlib,subprocess,re,struct,copy,tempfile
root=Path('/data/wlab-filter-effects');p=PE(Path('/data/wlab-inputs/wow_loader.dll'));r=json.loads((root/'cfg.json').read_text())
assert hashlib.sha256(p.b).hexdigest()==r['sha256'];assert not r['escapes'] and not r['overlaps']
nodes=r['nodes']; packed=b''.join(bytes.fromhex(n['bytes'])+b'\xcc'*(16-len(bytes.fromhex(n['bytes']))) for n in nodes)
with tempfile.TemporaryDirectory() as td:
 f=Path(td)/'instructions.bin';f.write_bytes(packed)
 output=subprocess.run(['objdump','-D','-b','binary','-m','i386:x86-64','-M','intel','--insn-width=16',str(f)],text=True,capture_output=True,check=True).stdout
 version=subprocess.run(['objdump','--version'],capture_output=True,text=True,check=True).stdout.splitlines()[0]
ind={}
for line in output.splitlines():
 parts=line.split('\t')
 if len(parts)<3:continue
 try:a=int(parts[0].strip().rstrip(':'),16)
 except ValueError:continue
 if a%16==0:ind[a//16]=(bytes.fromhex(parts[1].strip()),parts[2].strip())
assert len(ind)==len(nodes)
for idx,n in enumerate(nodes):
 raw=bytes.fromhex(n['bytes']);assert raw==p.read(n['rva'],len(raw))==ind[idx][0]
 text=ind[idx][1].lower(); mn=text.split()[0];capmn=n['asm'].split()[0]
 assert mn==capmn or ('nop' in text and capmn=='nop'),(text,n['asm'])
 if '[' in text and capmn not in ['lea','nop']:
  assert '[rsp' in text or '[rip' in text,text
  # No external memory writes: RIP-relative operands must be MOV sources.
  if '[rip' in text:assert capmn in ['mov','add','sub','xor','and','or','cmp','imul'] and '[rip' not in text.split(',')[0],text
  if '[rsp' in text:
   for v in re.findall(r'\[rsp(?:\+(0x[0-9a-f]+))?\]',text):assert 0<=int(v or '0',0)<=0xc0,text
calls=[n for n in nodes if n['asm'].startswith('call ')]
assert len(calls)==1 and calls[0]['rva']==0xc5997b and calls[0]['asm']=='call 0x1b7abb0'
assert not any(n['asm'].split()[0] in ['syscall','sysenter','int','int3'] for n in nodes)
# Verify both complementary-branch transformations directly from raw bytes.
pairs={x['first']:x for x in r['complementary_pairs']}
assert set(pairs)=={0xc596dd,0xc59ce5}
for a,q in pairs.items():
 raw=bytes.fromhex(q['bytes']);assert p.read(a,len(raw))==raw
 if a==0xc596dd:assert raw==bytes.fromhex('703dc0ea007138');second=a+5
 else:assert raw==bytes.fromhex('79648ac07860');second=a+4
 assert (raw[0]^1)==p.read(second,1)[0]
 assert a+2+struct.unpack('b',raw[1:2])[0]==q['target']
 assert second+2+p.u(second+1,'<b')==q['target']
fixed={x['rva']:x['target'] for x in r['fixed_flag_rules']}
assert fixed=={0xc593c2:0xc59405,0xc5964e:0xc59698,0xc59826:0xc59882,0xc59c6c:0xc59cb4,0xc59cb4:0xc59c89,0xc59c89:0xc59cbc}
# Byte-locked flag writers plus identity operations, independently checked.
assert p.read(0xc593bd,7).hex()=='f6c59b8ac97341' # TEST CH + MOV CL,CL + JAE
assert p.read(0xc5964a,6).hex()=='340086e47148' # XOR AL,0 + XCHG AH,AH + JNO
assert p.read(0xc59825,3).hex()=='f9765a' # STC + JBE
assert p.read(0xc59c69,5).hex()=='80f1007346' # XOR CL,0 + JAE
# TEST/XOR clear CF; XOR clears OF; STC sets CF. Branches preserve flags.
# Independently recompute CFG edge targets and verify a single exact RSP offset at every merge.
by={n['rva']:n for n in nodes}
def successors(n):
 a=n['rva'];b=bytes.fromhex(n['bytes']);end=a+len(b);mn=n['asm'].split()[0]
 if a in pairs:return [pairs[a]['target']]
 if a in fixed:
  assert mn in ['jae','jno','jbe'] and end+struct.unpack('<b',b[1:])[0]==fixed[a]
  return [fixed[a]]
 if mn=='ret':return []
 if mn=='jmp':return [end+struct.unpack('<i' if b[0]==0xe9 else '<b',b[1:])[0]]
 if mn.startswith('j'):
  d=struct.unpack('<i',b[2:])[0] if b[:1]==b'\x0f' else struct.unpack('<b',b[1:])[0]
  return [end+d,end]
 return [end]
def check_graph(report):
 for n in report['nodes']:assert n['successors']==successors(n)
check_graph(r)
pred={n['rva']:[] for n in nodes}
for n in nodes:
 for dst in n['successors']:pred[dst].append(n['rva'])
for a,parents in r['single_predecessor_requirements'].items():assert sorted(pred[int(a,16)])==parents
offsets={r['range'][0]:0};todo=[r['range'][0]];returns=0
while todo:
 a=todo.pop();n=by[a];off=offsets[a];asm=n['asm'];mn=asm.split()[0]
 if mn=='push':off-=8
 elif mn=='pop':off+=8
 elif asm.startswith('sub rsp, '):off-=int(asm.split(', ')[1],0)
 elif asm.startswith('add rsp, '):off+=int(asm.split(', ')[1],0)
 elif 'rsp' in asm and not ('[' in asm or mn=='nop'):raise AssertionError(asm)
 if mn=='ret':assert off==0;returns+=1
 for dst in n['successors']:
  assert dst in by
  if dst in offsets:assert offsets[dst]==off
  else:offsets[dst]=off;todo.append(dst)
for e in r['memory_and_transfer_effects']:
 if e['kind']=='stack_rsp' and 'write' in e['access']:
  assert offsets[e['rva']]==-264
  disp=int(re.search(r'\[rsp \+ (0x[0-9a-f]+)\]',e['asm'])[1],0)
  width=8 if e['asm'].split(',')[0].startswith('mov qword') else 4
  assert 0<=disp and disp+width<=0xc8 and ('dword ptr' in e['asm'] or 'qword ptr' in e['asm'])
assert len(offsets)==len(nodes)
bad=copy.deepcopy(r);bad['nodes'][0]['successors']=[0x3306000]
try:check_graph(bad);raise RuntimeError('bad graph accepted')
except AssertionError:pass
assert p.read(0x1b7abb0,3).hex()=='ff01c3'
# Only explicit writes to the argument slot and R15 must match the observed def-use chain.
slot_writes=[n for n in nodes if n['asm'].startswith('mov qword ptr [rsp + 0xc0],')]
assert [(n['rva'],n['asm']) for n in slot_writes]==[(0xc59a28,'mov qword ptr [rsp + 0xc0], r15')]
assert by[0xc59962]['asm']=='mov rcx, qword ptr [rsp + 0xc0]'
assert [n['asm'] for n in nodes if n['asm'].startswith(('lea r15','mov r15'))]==['lea r15, [rdx + rax + 0x60]']
v={'instruction_boundaries_verified' :len(nodes),'independent_disassembler':version,'complementary_pairs_verified':len(pairs),'cfg_edges_verified':sum(len(n['successors']) for n in nodes),'rsp_offsets_consistent_nodes':len(offsets),'return_nodes_balanced':returns,'explicit_memory_writes_in_callback':'only DWORD/QWORD writes within reserved local stack area','direct_call_sites':1,'callee':'0x1b7abb0: inc dword ptr [rcx]; ret','indirect_transfers':0,'fixed_flag_branches_verified':len(fixed),'conditional_argument_chain':'If stack slot 0xc0 was initialized by its sole in-body store before the call, RCX equals entry RDX+0x60; initialization before every call has not been proven','edge_mutation_rejected':True,'scope':'Static CFG overapproximation including possibly infeasible dispatcher paths. Assumes unchanged bytes, no external entry to interior, ordinary successful instruction execution. Not runtime evidence, termination proof or proof that the single call is reached.'}
(root/'verification.json').write_text(json.dumps(v,indent=2));print(json.dumps(v))
