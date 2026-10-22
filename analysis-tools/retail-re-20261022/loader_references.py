from pathlib import Path
import sys,re,json,struct,bisect
sys.path.insert(0,'/data/re-tools')
import pefile,capstone
from capstone.x86_const import X86_REG_RIP
import argparse
parser=argparse.ArgumentParser(description='Offline PE analysis; never runs input executables')
parser.add_argument('--input-dir',type=Path,default=Path('/data/raw/wow-retail-20261022'))
parser.add_argument('--output-dir',type=Path,default=Path('/data/analysis/wow-retail-20261022'))
parser.add_argument('--prior-report',type=Path,default=Path('/data/raw/wow-repo-review/hardware_relationship.json'))
args=parser.parse_args()
root=args.input_dir;out=args.output_dir;out.mkdir(parents=True,exist_ok=True)
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
reports=[]
terms=['https://telemetry-in.battle.net/','https://telemetry-in.battle.net','telemetry-in.battle.net','GetSystemFirmwareTable','GetNativeSystemInfo','NtQuerySystemInformation','NtQueryInformationProcess','GetComputerNameW','WinHttpSendRequest','WSASend','send','EncryptMessage','SSL_write','IsDebuggerPresent','CheckRemoteDebuggerPresent','Security Crash']
for name in ['wow_loader.dll','Wow.exe','libxell.dll']:
 b=(root/name).read_bytes();pe=pefile.PE(data=b);base=pe.OPTIONAL_HEADER.ImageBase
 func=sorted((x.struct.BeginAddress,x.struct.EndAddress) for x in getattr(pe,'DIRECTORY_ENTRY_EXCEPTION',[]))
 starts=[x[0] for x in func]
 matches=[]
 for term in terms:
  # Exact NUL-terminated names only. Counted literal spellings do not establish active APIs.
  for encoding in ['ascii','utf-16le']:
   needle=term.encode(encoding)+(b'\0' if encoding=='ascii' else b'\0\0')
   for m in list(re.finditer(re.escape(needle),b))[:30]:
    try:rva=pe.get_rva_from_offset(m.start())
    except Exception:continue
    matches.append({'term':term,'encoding':encoding,'file_offset':hex(m.start()),'rva':hex(rva)})
 # Decode only unwind-bounded loader functions. Main EXE high-entropy blocks are not treated as plaintext code.
 xrefs=[];stats={'functions_considered':0,'functions_exactly_decoded':0,'functions_partial_or_capped':0,'decoded_instruction_count':0}
 if name=='wow_loader.dll':
  targets={int(x['rva'],16):x['term'] for x in matches}
  for begin,end in func:
   length=end-begin
   if length<=0 or length>131072:stats['functions_partial_or_capped']+=1;continue
   sec=pe.get_section_by_rva(begin)
   if not sec or not(sec.Characteristics&0x20000000):continue
   stats['functions_considered']+=1;last=begin
   for ins in md.disasm(pe.get_data(begin,length),base+begin):
    last=ins.address-base+ins.size;stats['decoded_instruction_count']+=1
    for operand in ins.operands:
     if operand.type==capstone.CS_OP_MEM and operand.mem.base==X86_REG_RIP:
      dest=ins.address+ins.size+operand.mem.disp-base
      if dest in targets:
       xrefs.append({'term':targets[dest],'function_start_rva':hex(begin),'instruction_rva':hex(ins.address-base),'mnemonic':ins.mnemonic,'operands':ins.op_str,'function_decoded_to_end':False})
   exact=last==end
   stats['functions_exactly_decoded' if exact else 'functions_partial_or_capped']+=1
   if exact:
    for x in xrefs:
     if x['function_start_rva']==hex(begin):x['function_decoded_to_end']=True
 reports.append({'name':name,'literal_matches':matches,'bounded_scan_statistics':stats,'rip_relative_literal_references':xrefs,'absence_scope':'bounded literal spelling and unwind-listed linear decode only; obfuscated/computed/indirect references can be missed','network_destination_binding_proven':False})
(out/'loader-reference-scan.json').write_text(json.dumps(reports,indent=2)+'\n')
for r in reports:
 print(r['name'],'literal terms:',sorted(set(x['term'] for x in r['literal_matches'])));print('Scan:',r['bounded_scan_statistics']);print('Exact literal xrefs:',r['rip_relative_literal_references'][:12])
