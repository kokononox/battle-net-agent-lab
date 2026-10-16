"""Build only original Agent 9824 range validator at 0x72d18f."""
import argparse,json,struct,subprocess
from pathlib import Path
import agent_activation_audit as base
import agent_static_audit as identity
import retail_storage_poc as safety
import source_binding as b
import patch_audit as a

def build(agent,out):
 out=safety.safe_new(out);w=b.Watch();raw=w.read(agent,8*1024**2);a.require(a.sha256(raw)==identity.AGENT_SHA256,'value_agent_identity');pe=base.PE(raw);fragment=pe.read(0x72d18f,0x69);out.mkdir();(out/'original.bin').write_bytes(fragment)
 asm=subprocess.check_output(['objdump','-d','-M','intel','--start-address=0x72d18f','--stop-address=0x72d1f8',str(agent)],text=True)
 a.require('call' not in asm and '(bad)' not in asm and '.byte' not in asm,'value_pure_fragment');(out/'value-range.asm').write_text(asm.replace(str(agent),'PINNED-Agent.9824.exe'))
 (out/'original.s').write_text('.section .original,"ax"\n.global value_range\nvalue_range:\n.incbin '+json.dumps(str(out/'original.bin'))+'\n.section .note.GNU-stack,"",@progbits\n')
 (out/'layout.ld').write_text('ENTRY(_start)\nSECTIONS { .driver 0x600000 : { *(.driver) } .original 0x72d18f : { *(.original) } .scratch 0x900000 : { *(.scratch) } /DISCARD/ : { *(.note*) *(.comment*) } }\n')
 here=Path(__file__).resolve().parent
 for src,obj in ((here/'value_range.s',out/'driver.o'),(out/'original.s',out/'original.o')):subprocess.run(['as','--32',str(src),'-o',str(obj)],check=True)
 binary=out/'value_range_oracle';subprocess.run(['ld','-m','elf_i386','-z','noexecstack','-T',str(out/'layout.ld'),str(out/'driver.o'),str(out/'original.o'),'-o',str(binary)],check=True)
 elf=binary.read_bytes();at=struct.unpack_from('<I',elf,28)[0];width,count=struct.unpack_from('<HH',elf,42);a.require(width==32 and count<=12,'value_elf_headers');segments=[struct.unpack_from('<8I',elf,at+i*32) for i in range(count)]
 a.require(not any(s[0] in (2,3) for s in segments) and all(s[6]&3!=3 for s in segments if s[0]==1),'value_no_imports_no_rwx');a.require(any(s[0]==0x6474e551 and not(s[6]&1) for s in segments),'value_nx_stack')
 matches=[s for s in segments if s[0]==1 and s[2]<=0x72d18f and 0x72d1f8<=s[2]+s[4]];a.require(len(matches)==1,'value_fragment_mapping');s=matches[0];offset=s[1]+0x72d18f-s[2];a.require(elf[offset:offset+0x69]==fragment,'value_original_unchanged');w.check()
 result={'format':'agent-value-range-build-1','agent_sha256':identity.AGENT_SHA256,'start':'0x72d18f','end_exclusive':'0x72d1f8','original_bytes':len(fragment),'fragment_sha256':a.sha256(fragment),'original_elf_bytes_verified':True,'external_helpers':0,'no_dynamic_imports_no_rwx_nx_stack':True,'windows_apis_executed':False,'full_agent_readpath_executed':False,'installation_ready':False,'binary_sha256':a.sha256(elf),'source_sha256':{n:a.sha256((here/n).read_bytes()) for n in ('build_value_range.py','value_range.s')}}
 (out/'BUILD-RECEIPT.json').write_text(json.dumps(result,indent=2)+'\n');return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--agent',type=Path,required=True);p.add_argument('--out-new',type=Path,required=True);x=p.parse_args();print(json.dumps(build(x.agent,x.out_new),indent=2))
