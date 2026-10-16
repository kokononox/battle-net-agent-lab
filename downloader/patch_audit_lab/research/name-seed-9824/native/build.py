"""Build an isolated Linux i386 harness from hash-pinned pure Agent fragments.
No PE loader/import table or Windows APIs. Generated fragments/binary stay local.
"""
import argparse,hashlib,json,subprocess,struct
from pathlib import Path
import agent_activation_audit as base
import agent_static_audit as identity
import source_binding as binding
import patch_audit as a
import retail_storage_poc as safety

FRAGMENTS={
 'normalize':(0x86398b,0x863b04),
 'md5update':(0x8643ef,0x864497),
 'md5final':(0x864497,0x864541),
 'md5init':(0x864541,0x864565),
 'md5transform':(0x86e40b,0x86ea41),
 'keygen':(0x712a6d,0x712ae3),
 'bucket':(0x712b9f,0x712bc9),
}

def build(agent,out):
    out=safety.safe_new(out)
    watch=binding.Watch();raw=watch.read(agent,8*1024**2);a.require(hashlib.sha256(raw).hexdigest()==identity.AGENT_SHA256,'seed_oracle_agent_identity')
    pe=base.PE(raw);out.mkdir();here=Path(__file__).resolve().parent
    assembly=[];receipt=[]
    for name,(start,end) in FRAGMENTS.items():
        data=pe.read(start,end-start);file=out/(name+'.bin');file.write_bytes(data)
        assembly.append(f'.section .{name},"ax"\n.global {name}\n{name}:\n.incbin {json.dumps(str(file))}\n')
        receipt.append({'name':name,'start':hex(start),'end_exclusive':hex(end),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    (out/'fragments.s').write_text('\n'.join(assembly)+'\n.section .note.GNU-stack,"",@progbits\n')
    sections={'.driver':0x600000,**{'.'+n:v[0] for n,v in FRAGMENTS.items()},'.memcpy':0x879790,'.memset':0x879d10,'.scratch':0x900000}
    script='ENTRY(_start)\nSECTIONS {\n'+''.join(f' {name} {va:#x} : {{ *({name}) }}\n' for name,va in sorted(sections.items(),key=lambda v:v[1]))+' /DISCARD/ : { *(.note*) *(.comment*) }\n}\n'
    (out/'layout.ld').write_text(script)
    subprocess.run(['as','--32',str(here/'harness.s'),'-o',str(out/'driver.o')],check=True)
    subprocess.run(['as','--32',str(out/'fragments.s'),'-o',str(out/'fragments.o')],check=True)
    subprocess.run(['ld','-m','elf_i386','-z','noexecstack','-T',str(out/'layout.ld'),str(out/'driver.o'),str(out/'fragments.o'),'-o',str(out/'name_seed_oracle')],check=True)
    watch.check();binary=out/'name_seed_oracle'
    elf=binary.read_bytes();a.require(elf[:7]==b'\x7fELF\x01\x01\x01' and struct.unpack_from('<H',elf,18)[0]==3,'seed_oracle_elf_i386')
    phoff=struct.unpack_from('<I',elf,28)[0];entrysize,phnum=struct.unpack_from('<HH',elf,42);a.require(entrysize==32 and phnum<=32,'seed_oracle_elf_phdr_bounds')
    segments=[struct.unpack_from('<8I',elf,phoff+i*entrysize) for i in range(phnum)]
    a.require(not any(v[0] in (2,3) for v in segments),'seed_oracle_no_dynamic_or_interpreter')
    loads=[v for v in segments if v[0]==1];a.require(loads and all(v[6]&3!=3 for v in loads),'seed_oracle_no_writable_executable_segment')
    a.require(any(v[0]==0x6474e551 and not(v[6]&1) for v in segments),'seed_oracle_nonexecutable_stack')
    for item in receipt:
        start=int(item['start'],16);size=item['bytes'];matches=[v for v in loads if v[2]<=start and start+size<=v[2]+v[4]]
        a.require(len(matches)==1,'seed_oracle_fragment_elf_mapping');seg=matches[0];at=seg[1]+start-seg[2]
        a.require(hashlib.sha256(elf[at:at+size]).hexdigest()==item['sha256'],'seed_oracle_fragment_elf_identity')
    result={'format':'isolated-agent-pure-fragments-build-1','agent_sha256':identity.AGENT_SHA256,'fragments':receipt,'pure_fragment_bytes':sum(r['bytes'] for r in receipt),'linux_elf_i386':True,'no_writable_executable_load_segments':True,'nonexecutable_stack':True,'no_dynamic_linker_or_imports':True,'all_fragments_elf_bytes_verified':True,'windows_agent_process_executed':False,'windows_apis_executed':False,'replaced_pure_helpers':['memcpy','memset'],'source_sha256':{'harness.s':hashlib.sha256((here/'harness.s').read_bytes()).hexdigest(),'build.py':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'binaries_or_fragments_published':False}
    (out/'BUILD-RECEIPT.json').write_text(json.dumps(result,indent=2)+'\n');return result
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--agent',type=Path,required=True);p.add_argument('--out-new',type=Path,required=True);args=p.parse_args();print(json.dumps(build(args.agent,args.out_new),indent=2))
