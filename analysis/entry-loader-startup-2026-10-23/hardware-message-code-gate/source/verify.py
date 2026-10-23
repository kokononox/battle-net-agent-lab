"""Independent stdlib PE checks; NOT a semantic verifier or independent CFG proof."""
import copy,hashlib,json,struct,sys
from pathlib import Path
from pe_manual import PE
SHA='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a'
EXPECTED=[('merge_candidate',0x47cf800,0x1b14120,0x1b14138,6),('creator_candidate',0x47cf810,0x1b11190,0x1b111fe,0),('parse_fallback_candidate',0x47cec38,0x33068c0,0x33069b4,23)]
def verify(p,d):
 assert hashlib.sha256(p.b).hexdigest()==d['source_sha256']==SHA
 assert d['image_base']==hex(p.base);assert len(d['targets'])==3
 start,size=p.dirs[3];entries=[struct.unpack('<III',p.read(r,12)) for r in range(start,start+size,12)]
 relocs=set();r,size=p.dirs[5];end=r+size
 while r<end:
  page,n=struct.unpack('<II',p.read(r,8));assert n>=8 and n%2==0 and r+n<=end
  for off in range(r+8,r+n,2):
   x=p.u(off,'<H')
   if x>>12==10:relocs.add(page+(x&0xfff))
  r+=n
 for row,(role,slot,target,limit,consumed) in zip(d['targets'],EXPECTED):
  assert row['role_candidate']==role and row['slot_rva']==hex(slot)
  assert p.u(slot,'<Q')-p.base==int(row['target_rva'],16)==target
  assert row['slot_has_dir64_relocation']==(slot in relocs)==True
  es=[e for e in entries if e[0]==target];assert len(es)==1
  assert es[0]==(target,limit,int(row['unwind_rva'],16))
  assert row['pdata_begin']==hex(target) and row['pdata_end']==hex(limit)
  raw=p.read(target,limit-target);assert row['range_bytes']==len(raw)
  assert row['range_sha256']==hashlib.sha256(raw).hexdigest() and row['first_24_bytes']==raw[:24].hex()
  loc=p.loc(target,len(raw));assert loc['section']==row['section']=='.text' and loc['file_backed']
  nt=struct.unpack_from('<I',p.b,0x3c)[0];nsec=struct.unpack_from('<H',p.b,nt+6)[0];optsz=struct.unpack_from('<H',p.b,nt+20)[0]
  sh=nt+24+optsz;flags=[]
  for k in range(nsec):
   h=sh+k*40;vsz,va,rsz=struct.unpack_from('<III',p.b,h+8)
   if va<=target and limit<=va+max(vsz,rsz):flags.append(struct.unpack_from('<I',p.b,h+36)[0])
  assert len(flags)==1 and row['section_executable']==bool(flags[0]&0x20000000)==True
  # Concatenated prefix bytes, contiguous offsets and recorded stop, not mnemonic semantics.
  cursor=target
  for ins in row['capstone_linear_prefix']:
   assert int(ins['rva'],16)==cursor
   ib=bytes.fromhex(ins['bytes']);assert ib and ib==p.read(cursor,len(ib));cursor+=len(ib)
  assert cursor-target==row['capstone_consumed_bytes']==consumed
  assert row['capstone_first_undecoded_rva']==hex(cursor)
  assert row['objdump_prefix_through_first_bad'][-1].endswith('(bad)')
  assert '(bad)' not in '\n'.join(row['objdump_prefix_through_first_bad'][:-1])
 assert all(v is False for v in d['claims'].values())
 return True
if __name__=='__main__':
 p=PE(Path(sys.argv[1]));d=json.loads(Path(sys.argv[2]).read_text());verify(p,d)
 changes=[lambda x:x.update(source_sha256='0'*64),lambda x:x['targets'][0].update(target_rva='0x1b14121'),lambda x:x['targets'][1].update(pdata_end='0x1b111ff'),lambda x:x['targets'][2].update(capstone_consumed_bytes=24)]
 rejected=0
 for mutate in changes:
  m=copy.deepcopy(d);mutate(m)
  try:verify(p,m)
  except AssertionError:rejected+=1
 assert rejected==len(changes)
 print(json.dumps({'checks':'manual PE slots/relocations/pdata/file bytes/prefix continuity; no semantic proof','report_mutations_rejected':rejected}))
