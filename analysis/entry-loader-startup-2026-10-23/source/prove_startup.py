"""Byte-bound static startup analysis. Never loads or executes the input PE."""
import argparse, hashlib, json, struct
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from z3 import BitVec, BitVecVal, Solver, unsat

PINS={
 'Wow.exe':'1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a',
 'wow_loader.dll':'c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c',
 'libxell.dll':'5ce63652eee5720203e0e41cc97eb45ee541c499c8a51d4bdb1e8fe4eaef4890'}
START, END, CALL = 0xdf87c0, 0xdf88d9, 0xdf88ce
# Entire declared callback, including excluded bytes. A fixed hash prevents
# applying annotations to another binary or a modified snippet.
CALLBACK_SHA='63e6cb40089dcf063485ef3c4d0b0e2d831a20fec57893eb55cd1cbc087dc53d'

def analyze(input_dir, out_dir):
 out_dir.mkdir(parents=True,exist_ok=True); modules=[]; images={}
 for name,pin in PINS.items():
  b=(input_dir/name).read_bytes();digest=hashlib.sha256(b).hexdigest()
  if digest!=pin:raise ValueError('Unsupported input SHA-256: '+name)
  p=pefile.PE(data=b);base=p.OPTIONAL_HEADER.ImageBase
  def loc(r,n=1,p=p):
   for s in p.sections:
    d=r-s.VirtualAddress
    if d>=0 and d+n<=max(s.Misc_VirtualSize,s.SizeOfRawData):
     backed=d+n<=s.SizeOfRawData
     return {'section':s.Name.rstrip(b'\0').decode(),'file_backed':backed,'file_offset':s.PointerToRawData+d if backed else None,'zero_filled_virtual_tail':not backed and d+n<=s.Misc_VirtualSize}
   raise ValueError('Unmapped RVA '+hex(r))
  def read(r,n,p=p,b=b,loc=loc):
   l=loc(r,n)
   if not l['file_backed']:raise ValueError('Not raw-backed: '+hex(r))
   return b[l['file_offset']:l['file_offset']+n]
  images[name]=(p,read,loc)
  imports=[]
  for d in getattr(p,'DIRECTORY_ENTRY_IMPORT',[]):
   imports.append({'dll':d.dll.decode(),'descriptor_file_offset':d.struct.get_file_offset(),'first_thunk':d.struct.FirstThunk,'original_first_thunk':d.struct.OriginalFirstThunk,'entries':[{'ordinal':e.ordinal,'literal_name':e.name.decode() if e.ordinal is None and e.name else None,'slot_rva':e.address-base} for e in d.imports]})
  callbacks=[]; tls=getattr(p,'DIRECTORY_ENTRY_TLS',None)
  if tls and tls.struct.AddressOfCallBacks:
   arr=tls.struct.AddressOfCallBacks-base
   for i in range(64):
    va=struct.unpack('<Q',read(arr+i*8,8))[0]
    if not va:break
    callbacks.append({'slot_rva':arr+i*8,'callback_rva':va-base})
   else:raise ValueError('Unterminated callback array')
  exports=[{'ordinal':e.ordinal,'rva':e.address,'forwarder':e.forwarder.decode() if e.forwarder else None} for e in getattr(getattr(p,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[])]
  modules.append({'name':name,'sha256':digest,'size':len(b),'image_base':base,'entry_rva':p.OPTIONAL_HEADER.AddressOfEntryPoint,'imports':imports,'tls_callbacks':callbacks,'exports':exports})
 p,read,loc=images['wow_loader.dll'];raw=read(START,END-START)
 assert hashlib.sha256(raw).hexdigest()==CALLBACK_SHA,'Callback bytes changed'
 assert any(e.struct.BeginAddress==START and e.struct.EndAddress==END for e in p.DIRECTORY_ENTRY_EXCEPTION)
 # These expressions are translations of the byte-locked straight-line code,
 # not execution of the PE and not a general symbolic CPU emulator.
 x=BitVec('second_global_u32',32); K1=0x4f87b8db;K2=0x4d3e9198;K3=0x72579d11;K4=0x8474598d;magic=0x40b8febe
 c=(x+K1)^K2;r=c+K3;r=r+x;r=r+K1;r=-r;r=r+c;r=r+K3;r=r+x
 g=((c+r)+K4)^x
 proofs=[]
 for name,counterexample in [('r8d_not_negative_K1',r!=BitVecVal(-K1,32)),('second_guard_equal_magic',g==magic),('second_guard_not_odd',(g&1)!=1)]:
  s=Solver();s.set(timeout=30000);s.add(counterexample);status=str(s.check())
  assert status=='unsat',(name,status)
  proofs.append({'counterexample':name,'result':status,'bit_width':32})
 # First guard is not constant: preserve both branches even if disk data fits.
 def first(v):
  mask=0xffffffff;c=v^0x9a7a749d;r8=(c+0x6d947c51)&mask;c^=r8;r8^=0xf3724ca2;r9=((r8+0x21650896)&mask)^0x7881d1cf;c^=0x9a7535ab;c=(c+v+r9+r8)&mask
  return (r8+c+0xd85967b5)&mask
 first_global=START+10+struct.unpack('<i',read(START+6,4))[0]
 # RIP next address is df87ca; second is df8874.
 second_global=0xdf8874+struct.unpack('<i',read(0xdf8870,4))[0]
 disk1=struct.unpack('<I',read(first_global,4))[0];disk2=struct.unpack('<I',read(second_global,4))[0]
 assert first(disk1)==magic and first(0)!=magic
 rules={0xdf8822:('taken','AND AL clears CF; JAE is taken'),0xdf886c:('fallthrough','Reason=DLL_PROCESS_ATTACH (EDX=1), preserved to CMP'),0xdf88b8:('fallthrough','Second guard is odd for every DWORD; even magic cannot equal it')}
 # Build a fresh graph; never reuse overlapping raw CFG starts.
 cs=Cs(CS_ARCH_X86,CS_MODE_64);nodes={};edges={};todo=[START]
 while todo:
  a=todo.pop()
  if a in nodes:continue
  assert START<=a<END,hex(a)
  ins=next(cs.disasm(read(a,min(15,END-a)),a,count=1),None);assert ins is not None
  nodes[a]={'rva':a,'bytes':ins.bytes.hex(),'mnemonic':ins.mnemonic,'operands':ins.op_str}
  nxt=a+ins.size
  if ins.mnemonic=='ret':succ=[]
  elif ins.mnemonic.startswith('j'):
   target=int(ins.op_str,16)
   if a in rules:succ=[target if rules[a][0]=='taken' else nxt]
   else:succ=[target,nxt] if ins.mnemonic!='jmp' else [target]
  else:succ=[nxt] # Calls are not traversed into; return edge is conditional on callee returning.
  edges[a]=succ;todo.extend(succ)
 occupied=set()
 for a,n in sorted(nodes.items()):
  span=set(range(a,a+len(bytes.fromhex(n['bytes']))));assert not occupied&span;occupied|=span
 # Check every maximal pre-call path reaches CALL (no return, cycle, or exit).
 memo={}
 def must_hit(a,active=frozenset()):
  if a==CALL:return True
  if a in memo:return memo[a]
  if a in active or not edges[a]:return False
  result=all(must_hit(t,active|{a}) for t in edges[a]);memo[a]=result;return result
 assert must_hit(START)
 assert [a for a,n in nodes.items() if n['mnemonic']=='call']==[CALL]
 assert nodes[CALL]['operands']=='0x14bc180'
 exe,er,el=images['Wow.exe'];slot=0x4ad5f38
 assert er(0x1da9b4,7).hex()=='488b057db58f04'
 assert 0x1da9bb+struct.unpack('<i',er(0x1da9b7,4))[0]==slot
 slotloc=el(slot,8);assert slotloc['zero_filled_virtual_tail']
 report={'schema':'wlab-startup-review-1','input_modules':modules,'exe_indirect_slot':{'rva':slot,**slotloc,'writer_identified':False,'runtime_target_identified':False},'callback':{'start_rva':START,'end_rva':END,'sha256':CALLBACK_SHA,'reason':1,'raw_bytes':raw.hex(),'global_reads':[{'rva':first_global,'disk_u32':disk1},{'rva':second_global,'disk_u32':disk2}],'first_guard_examples':[{'x':v,'result':first(v),'equals_magic':first(v)==magic} for v in [disk1,0,1,0xffffffff]],'first_guard_policy':'retain both branches; disk value is not a runtime invariant','proofs':proofs,'rules':[{'rva':a,'decision':rule[0],'reason':rule[1]} for a,rule in rules.items()],'nodes':[nodes[a] for a in sorted(nodes)],'edges':[{'from':a,'to':edges[a]} for a in sorted(edges)],'all_modeled_precall_paths_reach_call':True,'call_site_rva':CALL,'callee_rva':0x14bc180,'callsite_register_values':{'ecx':0x62,'edx':0x1f,'r8d':0x19},'callee_semantics':'unresolved; register preparation does not establish a function prototype'},'assumptions':['Normal documented PE/TLS invocation with reason=1','On-disk callback instruction bytes remain unchanged','Ordinary instruction semantics; no exception, asynchronous code change, or nonlocal transfer before call','Stack and DWORD global reads succeed; no assumption about their values','Callee behavior and return are outside the pre-call proof'],'claims':{'observed_runtime_execution':False,'exe_slot_writer_found':False,'unpacker_identified':False,'bios_read_proven':False,'hardware_serialization_proven':False,'hardware_send_3724_proven':False}}
 (out_dir/'startup-proof.json').write_text(json.dumps(report,indent=2)+'\n')
 lines=['; STATIC annotation only. reason=1; original bytes are unchanged.','; Stops conceptually at the call; post-call continuation requires return.']
 for a,n in sorted(nodes.items()):lines.append(f"{a:08x} {n['bytes']:30} {n['mnemonic']} {n['operands']}"+(' ; '+rules[a][1] if a in rules else ''))
 (out_dir/'tls-process-attach.normalized.asm').write_text('\n'.join(lines)+'\n')
 print(json.dumps({'modules':len(modules),'callback_instructions':len(nodes),'proofs':proofs,'precall_must_hit':True}))

if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--input-dir',type=Path,required=True);a.add_argument('--out-dir',type=Path,required=True);args=a.parse_args();analyze(args.input_dir,args.out_dir)
