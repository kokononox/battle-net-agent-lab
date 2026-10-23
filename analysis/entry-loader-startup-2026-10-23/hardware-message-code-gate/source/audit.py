"""Bounded offline decode gate. Never executes or loads input as native code."""
import argparse,hashlib,json,struct,subprocess,tempfile
from pathlib import Path
import pefile,capstone
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
SHA='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a'
SLOTS={'merge_candidate':0x47cf800,'creator_candidate':0x47cf810,'parse_fallback_candidate':0x47cec38}
def audit(path):
 b=Path(path).read_bytes();assert hashlib.sha256(b).hexdigest()==SHA,'Wrong input build'
 p=pefile.PE(data=b,fast_load=True);p.parse_data_directories(directories=[3,5]);base=p.OPTIONAL_HEADER.ImageBase
 reloc={e.rva for block in p.DIRECTORY_ENTRY_BASERELOC for e in block.entries if e.type==10}
 md=Cs(CS_ARCH_X86,CS_MODE_64);rows=[]
 for role,slot in SLOTS.items():
  r=struct.unpack('<Q',p.get_data(slot,8))[0]-base
  es=[e.struct for e in p.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress==r];assert len(es)==1
  e=es[0];raw=p.get_data(r,e.EndAddress-r);assert len(raw)==e.EndAddress-r
  sec=p.get_section_by_rva(r);decoded=[{'rva':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'op_str':i.op_str} for i in md.disasm(raw,r)]
  consumed=sum(len(bytes.fromhex(i['bytes'])) for i in decoded)
  with tempfile.TemporaryDirectory() as td:
   f=Path(td)/'slice.bin';f.write_bytes(raw)
   text=subprocess.check_output(['objdump','-D','-b','binary','-m','i386:x86-64','-M','intel',f'--adjust-vma={r}',str(f)],text=True)
  lines=text.split('Disassembly of section .data:\n',1)[1].strip().splitlines()[1:]
  # Keep the independent decoder's first bad marker and preceding lines only.
  bad=next((k for k,l in enumerate(lines) if '(bad)' in l),None);assert bad is not None
  rows.append({'role_candidate':role,'slot_rva':hex(slot),'slot_has_dir64_relocation':slot in reloc,
   'target_rva':hex(r),'section':sec.Name.rstrip(b'\0').decode(),'section_executable':bool(sec.Characteristics&0x20000000),
   'pdata_begin':hex(e.BeginAddress),'pdata_end':hex(e.EndAddress),'unwind_rva':hex(e.UnwindData),
   'range_bytes':len(raw),'range_sha256':hashlib.sha256(raw).hexdigest(),'first_24_bytes':raw[:24].hex(),
   'capstone_linear_prefix':decoded,'capstone_consumed_bytes':consumed,'capstone_first_undecoded_rva':hex(r+consumed),
   'objdump_prefix_through_first_bad':lines[:bad+1],
   'interpretation':'ordinary x86-64 linear decode gate did not establish a callable body; no CFG/semantics claim'})
 return {'schema_version':1,'source_sha256':SHA,'image_base':hex(base),
  'scope':'three metadata-pinned candidates only; not all message methods and not a collector search',
  'layout_assumption':'candidate protobuf v30.1 model for protobuf_blz, not proven fork ABI identity',
  'tools':{'pefile':pefile.__version__,'capstone':capstone.__version__,'objdump':subprocess.check_output(['objdump','--version'],text=True).splitlines()[0]},
  'targets':rows,'decision':'stop this static code gate; do not infer runtime code, encryption, collection, serialization, sending or no-send',
  'claims':{'message_field_population_proven':False,'serialization_proven':False,'send_on_tcp_3724_proven':False,'no_send_proven':False}}
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input');ap.add_argument('output');a=ap.parse_args()
 src=Path(a.input);dst=Path(a.output)
 assert src.resolve()!=dst.resolve() and not (dst.exists() and src.samefile(dst)), 'Output must not overwrite input'
 dst.write_text(json.dumps(audit(src),ensure_ascii=False,indent=2)+'\n')
