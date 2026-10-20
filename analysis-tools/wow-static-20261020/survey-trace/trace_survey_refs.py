"""Read-only byte-reference inventory, NOT a decompiler or runtime dataflow proof.
Usage: PYTHONPATH=vendor python trace_survey_refs.py Wow.exe output.json
Requires numpy, pefile, capstone. Does not execute the input binary.
"""
import sys, re, json, struct, hashlib
from pathlib import Path
import numpy as np
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM, X86_REG_RIP
NAMES=['engineSurvey','engineSurveyPatch','Engine Survey Index','Engine Survey Patch',
       'surveyVersion','surveyPatch','ClientEngineLogV2','ClientSystemSpec',
       'https://wow.ingest.gdp.blizzard.com']
TAILS=[0,1,2,4,8]

def relative_rows(data, section_rva, targets):
    # Examine all byte alignments. Compare modulo 2^32; executable RIP results
    # below are independently checked in full 64-bit arithmetic by Capstone.
    found=[]
    wanted={}
    for t in targets:
        for tail in TAILS:wanted.setdefault((t-tail)&0xffffffff,[]).append((t,tail))
    for align in range(4):
        n=(len(data)-align)//4
        for lo in range(0,n,262144):
            count=min(262144,n-lo)
            a=np.frombuffer(data,dtype='<u4',count=count,offset=align+4*lo)
            pos=np.arange(count,dtype=np.uint32)*np.uint32(4)+np.uint32(align+lo*4)
            total=a+(pos+np.uint32(section_rva+4))
            for w,pairs in wanted.items():
                ix=np.flatnonzero(total==np.uint32(w))
                for i in ix:
                    off=int(pos[i]);d=int.from_bytes(data[off:off+4],'little',signed=True)
                    for t,tail in pairs:
                        # Reject modulo-wrap aliases in a real PE address space.
                        if section_rva+off+4+tail+d==t:
                            found.append((off,t,tail))
    return found

def rip_candidates(md,data,section_rva,base,p,t,tail):
    found=[]
    for st in range(max(0,p-12),p):
        ins=next(md.disasm(data[st:st+15],base+section_rva+st,count=1),None)
        if not ins or ins.disp_size!=4 or st+ins.disp_offset!=p:continue
        if ins.address+ins.size!=base+section_rva+p+4+tail:continue
        if any(op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP
               and ins.address+ins.size+op.mem.disp==base+t for op in ins.operands):
            found.append({'rva':hex(ins.address-base),'bytes':ins.bytes.hex(),
                          'instruction':ins.mnemonic+' '+ins.op_str,
                          'boundary_validated':False,'reachable_path_proven':False})
    return found

def selftest():
    b=bytearray(96); rva=0x1000;t=0x900
    samples=[(1,0),(20,1),(39,2),(52,4),(80,8)]
    for p,tail in samples:struct.pack_into('<i',b,p,t-(rva+p+4+tail))
    got=set(relative_rows(b,rva,[t]))
    assert all((p,t,tail) in got for p,tail in samples)
    # Positive displacement, including the first possible field offset.
    b=bytearray(16);struct.pack_into('<i',b,0,0x4000-(rva+4))
    assert (0,0x4000,0) in relative_rows(b,rva,[0x4000])
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    fixtures=[(b'\x48\x8d\x0d',b'',0x3000),
              (b'\x8b\x05',b'',0x900),
              (b'\xc7\x05',b'\x01\x00\x00\x00',0x3000)]
    for pre,post,target in fixtures:
        off=len(pre);tail=len(post)
        code=pre+struct.pack('<i',target-(rva+off+4+tail))+post
        refs=relative_rows(code,rva,[target])
        assert (off,target,tail) in refs
        assert any(x['rva']==hex(rva) for x in rip_candidates(md,code,rva,0x140000000,off,target,tail))
    return {'passed':True,'negative_displacement_alignments_and_tails':5,
            'positive_displacement_at_offset_zero':True,'capstone_positive_fixtures':3}


b=Path(sys.argv[1]).read_bytes();pe=pefile.PE(data=b,fast_load=True);base=pe.OPTIONAL_HEADER.ImageBase
out={'schema':'wow-survey-byte-reference-trace-1','sha256':hashlib.sha256(b).hexdigest(),'input_executed':False,
     'config_modified':False,'relative_tail_lengths_tested':TAILS,'selftest':selftest(),'targets':[], 'relative_candidates':[],
     'registration_binding_proven':False,'setting_to_message_dataflow_proven':False,'hardware_send_proven':False,
     'limits':['Only exact strings and tested byte-reference representations are covered.',
               'Relative matches in encrypted/high-entropy data can be accidental.',
               'An independently decoded instruction is not a proven instruction boundary or reachable path.',
               'Encoded, hashed, indirect, runtime-relocated or decrypted references are not recovered.',
               'Missing references do not prove an unused setting or disabled telemetry.']}
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
targets={}
for name in NAMES:
    row={'name':name,'hits':[]}
    for m in re.finditer(re.escape(name.encode()),b):
        if m.start()>0 and chr(b[m.start()-1]) in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_':continue
        after=m.end()
        if after<len(b) and chr(b[after]) in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_':continue
        rv=pe.get_rva_from_offset(m.start());targets.setdefault(rv,[]).append(name)
        h={'offset':hex(m.start()),'rva':hex(rv),'absolute_va64_refs':[],'rva32_refs':[]}
        for typ,pattern in [('absolute_va64_refs',struct.pack('<Q',base+rv)),('rva32_refs',struct.pack('<I',rv))]:
            for q in re.finditer(re.escape(pattern),b):h[typ].append(hex(q.start()))
        row['hits'].append(h)
    out['targets'].append(row)
for s in pe.sections:
    data=s.get_data();rows=relative_rows(data,s.VirtualAddress,targets)
    for p,t,tail in rows:
        item={'source_section':s.Name.rstrip(b'\0').decode(),'field_file_offset':hex(s.PointerToRawData+p),
              'field_rva':hex(s.VirtualAddress+p),'target_rva':hex(t),'target_names':targets[t],
              'bytes_after_displacement':tail,'rip_instruction_candidates':[]}
        if s.Characteristics & 0x20000000:
            item['rip_instruction_candidates']=rip_candidates(md,data,s.VirtualAddress,base,p,t,tail)
        out['relative_candidates'].append(item)
    print(s.Name.rstrip(b'\0').decode(),'relative candidates',len(rows),flush=True)
# Known pointer acts as a real-file control for the VA search, NOT dataflow.
control=next(x for x in out['targets'] if x['name'].startswith('https:'))
out['real_file_absolute_pointer_positive_control_passed']=any(h['absolute_va64_refs'] for h in control['hits'])
# Entry stub confirms an indirect callback boundary, not its eventual target.
er=pe.OPTIONAL_HEADER.AddressOfEntryPoint
entry=[]
for ins in md.disasm(pe.get_data(er,32),base+er,count=12):
    entry.append({'rva':hex(ins.address-base),'bytes':ins.bytes.hex(),
                  'instruction':ins.mnemonic+' '+ins.op_str})
    if ins.mnemonic=='ret':break
out['entry_stub']=entry
out['entry_callback_destination_recovered']=False
out['counts']={'relative_candidates':len(out['relative_candidates']),
 'rip_instruction_candidates':sum(len(c['rip_instruction_candidates']) for c in out['relative_candidates'])}
Path(sys.argv[2]).write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps(out['counts']))
