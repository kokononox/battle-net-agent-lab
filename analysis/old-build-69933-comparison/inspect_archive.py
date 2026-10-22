"""Read-only PE comparison; input binaries are never executed or emulated."""
from pathlib import Path
import sys,os,argparse,zipfile,hashlib,json,math,struct
sys.path.insert(0,os.environ.get('RE_TOOLS','/data/re-tools'))
import pefile,numpy as np
p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,default=Path('/data/.agent-service/files/ba3b1862-6acd-435e-928d-577829864131/_retail_old.zip'));p.add_argument('--extract',type=Path,default=Path('/data/raw/wow-retail-old'));p.add_argument('--baseline',type=Path,default=Path('/data/raw/wow-retail-20261022'));p.add_argument('--out',type=Path,default=Path(__file__).parent);a=p.parse_args();a.extract.mkdir(parents=True,exist_ok=True);a.out.mkdir(parents=True,exist_ok=True)
allowed={'Wow.exe','wow_loader.dll','libxell.dll'}
archivehash=hashlib.sha256(a.archive.read_bytes()).hexdigest()
assert archivehash=='ac66e5a4e17747c20483dec508210fb8057e43f862a52a3f0f88596e6db6d4e2'
with zipfile.ZipFile(a.archive) as z:
 assert set(z.namelist())==allowed and len(z.infolist())==3
 assert all(i.file_size<150_000_000 for i in z.infolist())
 for name in sorted(allowed):
  data=z.read(name);target=a.extract/name
  if target.exists():assert target.read_bytes()==data
  else:target.write_bytes(data);target.chmod(0o600)
def entropy(bs):
 if not bs:return 0
 c=np.bincount(np.frombuffer(bs,dtype=np.uint8),minlength=256);v=c[c>0]/len(bs);return float(-(v*np.log2(v)).sum())
def inspect(path):
 b=path.read_bytes();pe=pefile.PE(data=b);base=pe.OPTIONAL_HEADER.ImageBase
 version=[]
 for f in getattr(pe,'VS_FIXEDFILEINFO',[]):version.append('.'.join(str(x) for x in [f.FileVersionMS>>16,f.FileVersionMS&65535,f.FileVersionLS>>16,f.FileVersionLS&65535]))
 sections=[]
 for s in pe.sections:
  data=s.get_data();sections.append({'name':s.Name.decode(errors='replace').rstrip('\0'),'rva':hex(s.VirtualAddress),'raw_size':len(data),'virtual_size':s.Misc_VirtualSize,'sha256':hashlib.sha256(data).hexdigest(),'entropy':entropy(data),'executable':bool(s.Characteristics&0x20000000)})
 text=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text');bs=text.get_data();blocks=[entropy(bs[i:i+65536]) for i in range(0,len(bs),65536)]
 imports=[{'dll':d.dll.decode(errors='replace'),'functions':[{'name':i.name.decode(errors='replace') if i.name else None,'ordinal':i.ordinal,'slot_rva':hex(i.address-base)} for i in d.imports]} for d in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])]
 cert=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
 return {'name':path.name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'fixed_file_versions':version,'image_base':hex(base),'entry_rva':hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),'entry_first_32_bytes':pe.get_data(pe.OPTIONAL_HEADER.AddressOfEntryPoint,32).hex(),'image_size':pe.OPTIONAL_HEADER.SizeOfImage,'imports':imports,'exports':[{'name':e.name.decode(errors='replace') if e.name else None,'ordinal':e.ordinal,'rva':hex(e.address)} for e in getattr(getattr(pe,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[])],'sections':sections,'text_64KiB_blocks':len(blocks),'text_blocks_entropy_gt_7_9':sum(h>7.9 for h in blocks),'text_min_block_entropy':min(blocks),'text_max_block_entropy':max(blocks),'certificate_table_present':bool(cert.Size),'certificate_table_bytes':cert.Size,'signature_trust_validated':False,'debug_directory_present':bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size),'archive_contains_PDB':False}
results=[]
for name in sorted(allowed):
 old=inspect(a.extract/name);baseline=inspect(a.baseline/name);results.append({'uploaded_old':old,'previous_baseline':baseline,'identical_whole_file':old['sha256']==baseline['sha256']})
 print(name,'old_version',old['fixed_file_versions'],'oldsha',old['sha256'],'identical',old['sha256']==baseline['sha256'])
 for label,r in [('uploaded',old),('baseline',baseline)]:
  text=next(s for s in r['sections'] if s['name']=='.text');print(' ',label,'text_entropy',round(text['entropy'],6),'high_blocks',r['text_blocks_entropy_gt_7_9'],'/',r['text_64KiB_blocks'],'entry',r['entry_rva'],'import_entries',sum(len(d['functions']) for d in r['imports']))
report={'archive_sha256':archivehash,'archive_members':sorted(allowed),'comparison':results,'input_executed_emulated_patched':False,'meaning':'Entropy and entry/import patterns characterize file contents; they do not establish a specific protector or recovered semantics.'}
(a.out/'binary-comparison.json').write_text(json.dumps(report,indent=2)+'\n')
