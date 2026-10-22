from pathlib import Path
import sys,json,hashlib,struct,math
from collections import Counter
sys.path.insert(0,'/data/re-tools')
import pefile,capstone
import argparse
parser=argparse.ArgumentParser(description='Offline PE analysis; never runs input executables')
parser.add_argument('--input-dir',type=Path,default=Path('/data/raw/wow-retail-20261022'))
parser.add_argument('--output-dir',type=Path,default=Path('/data/analysis/wow-retail-20261022'))
parser.add_argument('--prior-report',type=Path,default=Path('/data/raw/wow-repo-review/hardware_relationship.json'))
args=parser.parse_args()
root=args.input_dir;out=args.output_dir;out.mkdir(parents=True,exist_ok=True)
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
reports=[]
for name in ['Wow.exe','wow_loader.dll','libxell.dll']:
 b=(root/name).read_bytes();pe=pefile.PE(data=b);base=pe.OPTIONAL_HEADER.ImageBase
 # Inspect designated entrypoints only; never use successful random-byte decoding as proof of live code.
 rv=[('entry',pe.OPTIONAL_HEADER.AddressOfEntryPoint)]
 if name=='wow_loader.dll':rv += [('export_ordinal_1',x.address) for x in pe.DIRECTORY_ENTRY_EXPORT.symbols if x.ordinal==1]
 entries=[]
 for label,rva in rv:
  code=pe.get_data(rva,128)
  instructions=[{'rva':hex(i.address-base),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in md.disasm(code,base+rva,count=16)]
  entries.append({'label':label,'rva':hex(rva),'instructions':instructions})
 tls=[]
 if hasattr(pe,'DIRECTORY_ENTRY_TLS'):
  a=pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
  if a:
   for i in range(64):
    v=struct.unpack('<Q',pe.get_data(a-base+i*8,8))[0]
    if not v:break
    tls.append(hex(v-base))
 text=next(x for x in pe.sections if x.Name.rstrip(b'\0')==b'.text')
 blockstats=[]
 raw=text.get_data()
 for off in range(0,len(raw),65536):
  z=raw[off:off+65536];c=Counter(z);h=-sum((n/len(z))*math.log2(n/len(z)) for n in c.values())
  blockstats.append(h)
 # Certificate presence is not signature validity, authenticity, or reputation.
 cert=pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
 report={'name':name,'entry_disassembly':entries,'tls_callback_rvas':tls,'certificate_table_bytes':cert.Size,'certificate_table_present':bool(cert.Size),'signature_validated':False,'text_64k_blocks':len(blockstats),'text_blocks_entropy_gt_7_9':sum(x>7.9 for x in blockstats),'text_blocks_entropy_lt_7':sum(x<7 for x in blockstats),'min_block_entropy':min(blockstats),'max_block_entropy':max(blockstats)}
 reports.append(report)
(out/'code-layout.json').write_text(json.dumps(reports,indent=2)+'\n')
for r in reports:
 print(r['name'],'TLS',r['tls_callback_rvas'],'certbytes',r['certificate_table_bytes'],'blocks',r['text_64k_blocks'],'high entropy',r['text_blocks_entropy_gt_7_9'])
 for e in r['entry_disassembly']:
  print(e['label'],e['rva'],[(i['mnemonic'],i['operands']) for i in e['instructions'][:12]])
