"""Unchanged archive read fragments; explicit open/frame/OS adapters, no whole-Agent execution."""
import argparse,json,struct,subprocess,re
from pathlib import Path
import agent_activation_audit as base
import agent_static_audit as identity
import source_binding as b
import retail_storage_poc as safety
import patch_audit as a
FRAGMENTS={'range_gate':(0x70da91,0x70db04),'membership':(0x70db89,0x70dba7),'archive_read':(0x70dbd5,0x70dcf3),'buffer_read':(0x70bcad,0x70bd7c),'read_file_wrapper':(0x86516f,0x8651d1),'last_error_jump':(0x86deb1,0x86deb7),'shift64':(0x876d30,0x876d4f)}
TABLES={'success_value':(0x9ad260,0x9ad264)}
STUBS={'ownership':0x67b495,'error_text':0x702e71,'membership_forbidden':0x708bf4,'alignment_forbidden':0x70c839,'error_log':0x70d077,'open_adapter':0x71d1f3,'frame_end':0x876006,'frame_start':0x876038,'log_adapter':0x8c3843}
IATS={0x8fb2c8:'ReadFile',0x8fb248:'GetLastError'}
def build(agent,out):
 out=safety.safe_new(out);watch=b.Watch();raw=watch.read(agent,8*1024**2);a.require(a.sha256(raw)==identity.AGENT_SHA256,'bind_agent_identity');pe=base.PE(raw);out.mkdir();here=Path(__file__).resolve().parent
 assembly=[];receipt=[];graph=[];indirect=[]
 for n,(lo,hi) in {**FRAGMENTS,**TABLES}.items():
  data=pe.read(lo,hi-lo);f=out/(n+'.bin');f.write_bytes(data)
  if n in FRAGMENTS:
   dis=subprocess.check_output(['objdump','-d','-M','intel',f'--start-address={lo}',f'--stop-address={hi}',str(agent)],text=True)
   a.require('(bad)' not in dis and '.byte' not in dis,'bind_disassembly_boundary')
   for line in dis.splitlines():
    if re.search(r'\bcall\s',line):
     m=re.search(r'^\s*([0-9a-f]+):.*\bcall\s+0x([0-9a-f]+)\s*$',line)
     if m:
      site,target=(int(v,16) for v in m.groups());a.require(target in set(STUBS.values())|{v[0] for v in FRAGMENTS.values()},'bind_closed_direct_graph');a.require(pe.relcall(site)==target,'bind_call_receipt');graph.append({'function':n,'site':hex(site),'target':hex(target),'mocked_or_forbidden':target in STUBS.values()})
     else:
      m=re.search(r'^\s*([0-9a-f]+):.*\bcall\s+DWORD PTR ds:0x([0-9a-f]+)\s*$',line)
      a.require(m is not None,'io_indirect_shape');site,iat=(int(v,16) for v in m.groups());a.require(iat in IATS and pe.imports()[iat]['name']==IATS[iat],'io_import_identity');indirect.append({'site':hex(site),'iat':hex(iat),'symbol':IATS[iat]})
   # Publish readable assembly, never the extracted original machine-code blobs.
   (out/(n+'.asm')).write_text(dis.replace(str(agent),'PINNED-Agent.9824.exe'))
  else:a.require(data==bytes(4),'io_success_constant')
  assembly.append(f'.section .{n},"a'+('x' if n in FRAGMENTS else '')+f'"\n.global {n}\n{n}:\n.incbin '+json.dumps(str(f))+'\n')
  receipt.append({'name':n,'start':hex(lo),'end_exclusive':hex(hi),'bytes':len(data),'sha256':a.sha256(data),'kind':'code' if n in FRAGMENTS else 'readonly-jump-tables'})
 (out/'fragments.s').write_text('\n'.join(assembly)+'\n.section .note.GNU-stack,"",@progbits\n')
 sections={'.driver':0x600000,'.scratch':0xb00000,'.iat':0x8fb000,**{'.'+n:v[0] for n,v in {**FRAGMENTS,**TABLES}.items()},**{'.'+n:v for n,v in STUBS.items()}}
 (out/'layout.ld').write_text('ENTRY(_start)\nSECTIONS {\n'+''.join(f' {n} {v:#x} : {{ *({n}) }}\n' for n,v in sorted(sections.items(),key=lambda x:x[1]))+' /DISCARD/ : { *(.note*) *(.comment*) }\n}\n')
 for src,obj in ((here/'harness.s',out/'driver.o'),(out/'fragments.s',out/'fragments.o')):subprocess.run(['as','--32',str(src),'-o',str(obj)],check=True)
 binary=out/'archive_io_oracle';subprocess.run(['ld','-m','elf_i386','-z','noexecstack','-T',str(out/'layout.ld'),str(out/'driver.o'),str(out/'fragments.o'),'-o',str(binary)],check=True)
 watch.check();elf=binary.read_bytes();at=struct.unpack_from('<I',elf,28)[0];width,count=struct.unpack_from('<HH',elf,42);a.require(width==32 and count<=64,'bind_elf_headers');segs=[struct.unpack_from('<8I',elf,at+i*32) for i in range(count)];loads=[s for s in segs if s[0]==1]
 a.require(elf[:7]==b'\x7fELF\x01\x01\x01' and struct.unpack_from('<H',elf,18)[0]==3,'bind_i386');a.require(not any(s[0] in (2,3) for s in segs) and all(s[6]&3!=3 for s in loads),'bind_no_dynamic_no_rwx');a.require(any(s[0]==0x6474e551 and not(s[6]&1) for s in segs),'bind_nx_stack')
 for item in receipt:
  lo=int(item['start'],16);size=item['bytes'];matching=[s for s in loads if s[2]<=lo and lo+size<=s[2]+s[4]];a.require(len(matching)==1,'bind_fragment_mapping');s=matching[0];off=s[1]+lo-s[2];a.require(a.sha256(elf[off:off+size])==item['sha256'],'bind_fragment_unchanged')
 result={'format':'agent-archive-io-build-1','agent_sha256':identity.AGENT_SHA256,'fragments':receipt,'original_code_bytes':sum(v['bytes'] for v in receipt if v['kind']=='code'),'direct_call_graph':graph,'indirect_import_calls':indirect,'helpers':{n:hex(v) for n,v in STUBS.items()},'whole_agent_executed':False,'windows_io_executed':False,'original_archive_read_executed':True,'original_open_manager_executed':False,'original_bytes_verified_in_elf':True,'no_rwx':True,'nx_stack':True,'binary_sha256':a.sha256(elf),'source_sha256':{n:a.sha256((here/n).read_bytes()) for n in ('build.py','harness.s')},'installation_ready':False,'adapters':['normal-frame only, no Windows SEH','open manager returns caller-supplied read-only fd or injected error','ReadFile -> Linux pread64 or injected error','GetLastError -> adapter error','ownership release/logging no-ops; other branches trap'],'fixed_profile':{'shift':30,'mask':'0x3fffffff','alignment_object':None,'membership_set':None,'maximum_read':4096}}
 (out/'BUILD-RECEIPT.json').write_text(json.dumps(result,indent=2)+'\n');return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--agent',type=Path,required=True);p.add_argument('--out-new',type=Path,required=True);x=p.parse_args();print(json.dumps(build(x.agent,x.out_new),indent=2))
