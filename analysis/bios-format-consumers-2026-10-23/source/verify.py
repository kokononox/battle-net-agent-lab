"""Stdlib/objdump verification of artifacts; no NumPy/Capstone dependency."""
from pathlib import Path
import os,json,struct,hashlib,subprocess
from pe_manual import PE
D=Path(__file__).resolve().parents[1];p=PE(Path(os.environ.get('INPUT_DIR','/data/wlab-inputs'))/'Wow.exe');r=json.loads((D/'reports/discovery.json').read_text());t=json.loads((D/'reports/triage.json').read_text());assert hashlib.sha256(p.b).hexdigest()==r['sha256']
bios=r['bios_rva'];fmt=r['bios_format'];assert p.read(bios,len(fmt)+1)==fmt.encode()+b'\0'
# Byte-pattern searches independently repeat every literal value inside format.
counts={}
for name,base,form in [('rva32',bios,'<I'),('file_offset32',p.loc(bios)['file_offset'],'<I'),('preferred_va64',p.base+bios,'<Q')]:
 found=[]
 for n in range(len(fmt)+1):
  needle=struct.pack(form,base+n);off=0
  while True:
   off=p.b.find(needle,off)
   if off<0:break
   # Producer scans file-backed section bytes, not PE headers/overlay.
   if any(s[4]<=off and off+len(needle)<=s[4]+s[3] for s in p.sections):found.append((off,n))
   off+=1
 counts[name]=len(found);assert not found
assert not r['bios_literal_candidates']
for x in r['rip_candidates']:
 b=bytes.fromhex(x['bytes']);assert p.read(x['rva'],len(b))==b;delta=struct.unpack_from('<i',b,x['disp_offset'])[0];assert x['rva']+len(b)+delta==x['target_rva']
for x in r['bios_self_relative_dword_candidates']:
 b=p.read(x['slot_rva'],4);assert b.hex()==x['raw_hex'];d=struct.unpack('<i',b)[0];assert x['slot_rva']+(4 if x['basis']=='field_end' else 0)+d==x['target_rva'];assert bios<=x['target_rva']<bios+len(fmt)+1
# Independently parse all DIR64 entries and compare bounded target inventory.
rva,size=p.dirs[5];off=0;out=[]
while off<size:
 page,bs=struct.unpack('<II',p.read(rva+off,8));assert bs>=8 and off+bs<=size
 for k in range(8,bs,2):
  entry=p.u(rva+off+k,'<H')
  if entry>>12!=10:continue
  slot=page+(entry&4095);dest=p.u(slot,'<Q')-p.base
  if any(s['begin']<=dest<s['end'] for s in r['spans']):out.append((slot,dest))
 off+=bs
assert sorted(out)==sorted((x['slot_rva'],x['target_rva']) for x in r['relocation_pointer_candidates'])
assert not any(bios<=a<bios+len(fmt)+1 for _,a in out)
assert any(x['rva']==0x1da9b4 and x['target_rva']==0x4ad5f38 for x in r['rip_candidates'])
assert len(t['traces'])==3 and all(not x['candidate_visited'] for x in t['traces'])
for tr in t['traces']:
 for ins in tr['instructions']:
  b=bytes.fromhex(ins['bytes']);assert p.read(ins['rva'],len(b))==b
 # Check reported failure at each frontier with another decoder.
 for stop in tr['stops']:
  if stop['reason']!='decode_failure':continue
  a=stop['rva'];raw=p.read(a,min(15,tr['pdata'][1]-a));f=D/'work'/f'frontier-{a:x}.bin';f.write_bytes(raw)
  result=subprocess.run(['objdump','-D','-b','binary','-m','i386:x86-64',f'--adjust-vma={a}',str(f)],capture_output=True,text=True,check=True)
  lines=[s.strip() for s in result.stdout.splitlines() if s.strip().startswith(f'{a:x}:')];assert lines
  # Capstone and objdump can differ on unsupported/reserved opcodes. Record, do not silently hide.
  stop['objdump_first_line']=lines[0]
# Decoder agreement on all five RIP candidates (including overlapping control decode).
check=[]
for x in r['rip_candidates']:
 a=x['rva'];f=D/'work'/f'rip-{a:x}.bin';f.write_bytes(bytes.fromhex(x['bytes']));res=subprocess.run(['objdump','-D','-b','binary','-m','i386:x86-64',f'--adjust-vma={a}',str(f)],capture_output=True,text=True,check=True)
 lines=[s.strip() for s in res.stdout.splitlines() if s.strip().startswith(f'{a:x}:')];assert lines and '(bad)' not in lines[0];check.append({'rva':a,'objdump':lines[0]})
report={'input_hash_checked':True,'literal_counts_independently_repeated':counts,'rip_bytes_and_address_arithmetic_checked':len(r['rip_candidates']),'relative_dword_arithmetic_checked':len(r['bios_self_relative_dword_candidates']),'relocation_inventory_independently_repeated':len(out),'known_control_mov_found':True,'traced_instruction_bytes_checked':sum(len(tr['instructions']) for tr in t['traces']),'objdump_rip_checks':check,'objdump_frontiers':[{'candidate_rva':tr['candidate_rva'],'frontiers':tr['stops']} for tr in t['traces']],'limits':'No independent full CFG rebuild, runtime use or exhaustive semantic reference proof. Full literal searches repeated only for file-backed sections; raw numerical matches are not pointer evidence.'}
(D/'reports/verification.json').write_text(json.dumps(report,indent=2)+'\n')
print('Verified:',counts,'RIP bytes',len(check),'traced instructions',report['traced_instruction_bytes_checked'])
for tr in report['objdump_frontiers']:print(tr)
