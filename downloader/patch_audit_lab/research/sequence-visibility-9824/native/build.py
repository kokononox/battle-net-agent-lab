"""Four hash-pinned Agent fragments with mocked nonthrowing helper boundaries.
Linux i386 only; generated original bytes and executables remain local.
"""
import argparse,hashlib,json,struct,subprocess,re
from pathlib import Path
import agent_activation_audit as base
import agent_static_audit as identity
import agent_publication_audit as publication
import source_binding as b
import retail_storage_poc as safety
import patch_audit as a
FRAGMENTS={'header_publish':(0x71c119,0x71c18e),'header_reader':(0x71c555,0x71c59d),'writer':(0x71e887,0x71e9c1),'reader':(0x71ec75,0x71edd7)}
STUBS={'join':0x50045e,'error_string':0x702e71,'convert_error':0x717221,'filename':0x71f0d3,'errorpath':0x71f07a,'tempname':0x71f126,'flush':0x71f1f1,'bind':0x72b84f,'serialize_full':0x72bbbc,'serialize_some':0x72bda3,'constructor':0x72f5c4,'destroy':0x864c4a,'move':0x864c85,'open':0x864f87,'epilog':0x87601a,'prolog':0x87606b,'logger':0x8c3843}
def build(agent,out):
    out=safety.safe_new(out);watch=b.Watch();raw=watch.read(agent,8*1024**2)
    a.require(a.sha256(raw)==identity.AGENT_SHA256,'visibility_pinned_agent');publication.analyze(raw);pe=base.PE(raw);out.mkdir();here=Path(__file__).resolve().parent
    assembly=[];receipt=[];call_graph=[]
    for n,(lo,hi) in FRAGMENTS.items():
        data=pe.read(lo,hi-lo);file=out/(n+'.bin');file.write_bytes(data)
        disasm=subprocess.check_output(['objdump','-d','-M','intel',f'--start-address={lo}',f'--stop-address={hi}',str(agent)],text=True)
        for line in disasm.splitlines():
            if re.search(r'\bcall\s',line):
                match=re.search(r'^\s*([0-9a-f]+):.*\bcall\s+0x([0-9a-f]+)\s*$',line)
                a.require(match is not None,'visibility_no_unmodeled_indirect_call')
                site,target=(int(x,16) for x in match.groups())
                a.require(target in set(STUBS.values())|{x[0] for x in FRAGMENTS.values()},'visibility_closed_helper_call_graph')
                a.require(pe.relcall(site)==target,'visibility_call_receipt')
                call_graph.append({'function':n,'site':hex(site),'target':hex(target),'mocked':target in STUBS.values()})
        assembly.append(f'.section .{n},"ax"\n.global {n}\n{n}:\n.incbin {json.dumps(str(file))}\n')
        receipt.append({'name':n,'start':hex(lo),'end_exclusive':hex(hi),'bytes':len(data),'sha256':a.sha256(data)})
    (out/'fragments.s').write_text('\n'.join(assembly)+'\n.section .note.GNU-stack,"",@progbits\n')
    sections={'.driver':0x600000,'.scratch':0x900000,**{'.'+n:v[0] for n,v in FRAGMENTS.items()},**{'.'+n:v for n,v in STUBS.items()}}
    script='ENTRY(_start)\nSECTIONS {\n'+''.join(f' {n} {v:#x} : {{ *({n}) }}\n' for n,v in sorted(sections.items(),key=lambda x:x[1]))+' /DISCARD/ : { *(.note*) *(.comment*) }\n}\n'
    (out/'layout.ld').write_text(script)
    for src,obj in ((here/'harness.s',out/'driver.o'),(out/'fragments.s',out/'fragments.o')):subprocess.run(['as','--32',str(src),'-o',str(obj)],check=True)
    binary=out/'sequence_visibility_oracle'
    subprocess.run(['ld','-m','elf_i386','-z','noexecstack','-T',str(out/'layout.ld'),str(out/'driver.o'),str(out/'fragments.o'),'-o',str(binary)],check=True)
    watch.check();elf=binary.read_bytes();a.require(elf[:7]==b'\x7fELF\x01\x01\x01' and struct.unpack_from('<H',elf,18)[0]==3,'visibility_elf_i386')
    at=struct.unpack_from('<I',elf,28)[0];width,count=struct.unpack_from('<HH',elf,42);a.require(width==32 and count<=40,'visibility_phdr')
    segs=[struct.unpack_from('<8I',elf,at+i*32) for i in range(count)];loads=[s for s in segs if s[0]==1]
    a.require(loads and not any(s[0] in (2,3) for s in segs) and all(s[6]&3!=3 for s in loads),'visibility_no_dynamic_no_rwx')
    a.require(any(s[0]==0x6474e551 and not(s[6]&1) for s in segs),'visibility_nx_stack')
    for item in receipt:
        lo=int(item['start'],16);size=item['bytes'];matches=[s for s in loads if s[2]<=lo and lo+size<=s[2]+s[4]];a.require(len(matches)==1,'visibility_fragment_mapping');seg=matches[0];off=seg[1]+lo-seg[2]
        a.require(a.sha256(elf[off:off+size])==item['sha256'],'visibility_original_bytes_unchanged')
    result={'format':'agent-sequence-visibility-fragment-build-1','agent_sha256':identity.AGENT_SHA256,'fragments':receipt,'original_fragment_bytes':sum(x['bytes'] for x in receipt),'direct_call_graph':call_graph,'helper_stubs':{n:hex(v) for n,v in STUBS.items()},'helper_behavior':'mocked nonthrowing helpers; custom stack-frame setup; no SEH or Windows I/O','linux_elf_i386':True,'all_original_fragment_elf_bytes_verified':True,'no_rwx_load_segments':True,'nonexecutable_stack':True,'no_dynamic_linker_or_imports':True,'source_sha256':{'harness.s':a.sha256((here/'harness.s').read_bytes()),'build.py':a.sha256(Path(__file__).read_bytes())},'binary_sha256':a.sha256(elf),'windows_agent_process_executed':False,'windows_apis_executed':False,'power_loss_proven':False,'installation_ready':False,'binaries_or_original_fragments_published':False}
    (out/'BUILD-RECEIPT.json').write_text(json.dumps(result,indent=2)+'\n');return result
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--agent',required=True,type=Path);p.add_argument('--out-new',required=True,type=Path);x=p.parse_args();print(json.dumps(build(x.agent,x.out_new),indent=2))
