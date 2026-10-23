"""Independent stdlib checks of bytes/index/arithmetic, NOT CFG or instruction validity."""
from pathlib import Path
import json,hashlib,struct,copy
from pe_manual import PE
D=Path(__file__).resolve().parents[1]
p=PE(Path('/data/wlab-inputs/wow_loader.dll'))
d=json.loads((D/'reports/discovery.json').read_text());r=json.loads((D/'reports/reachability.json').read_text())
PIN='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
def validate(d):
 assert hashlib.sha256(p.b).hexdigest()==d['input_sha256']==PIN
 targets={n:(va,va+vs) for n,vs,va,rs,ro in p.sections if n in ['.eid','.eidsig']}
 assert d['target_sections']==[[n,*targets[n]] for n in ['.eid','.eidsig']]
 pr,ps=p.dirs[3];bounds={tuple(struct.unpack('<III',p.read(pr+i,12))[:2]) for i in range(0,ps,12)}
 seen=set()
 for c in d['rip_syntactic_candidates']:
  a=c['rva'];b=bytes.fromhex(c['bytes']);o=c['disp_offset'];assert p.read(a,len(b))==b
  assert 1<=o and o+4<=len(b)<=15 and b[o-1]&0xc7==5
  assert len(b)-o-4==c['immediate_tail_bytes']
  t=a+len(b)+struct.unpack_from('<i',b,o)[0];assert t==c['target_rva']
  lo,hi=targets[c['target_section']];assert lo<=t<hi
  if c['containing_function']:
   x,y=c['containing_function'];assert (x,y) in bounds and x<=a<y
  k=(a,c['bytes']);assert k not in seen;seen.add(k)
 for row in d['literal_names']:
  n=bytes.fromhex(row['needle_hex']);hits=[];i=0
  while (i:=p.b.find(n,i))>=0:hits.append(i);i+=1
  assert hits==row['file_offsets']
 # Independently enumerate DIR64 relocations.
 a,size=p.dirs[5];end=a+size;matches=[]
 while a<end:
  page,sz=struct.unpack('<II',p.read(a,8));assert sz>=8 and sz%2==0 and a+sz<=end
  for off in range(8,sz,2):
   v=p.u(a+off,'<H')
   if v>>12==10:
    slot=page+(v&0xfff);t=p.u(slot,'<Q')-p.base
    for n,(lo,hi) in targets.items():
     if lo<=t<hi:matches.append((slot,t,n))
  a+=sz
 assert matches==[(x['slot_rva'],x['target_rva'],x['section']) for x in d['relocation_backed_pointers']]
 assert not any(d['claims'].values())
 return len(seen)
n=validate(d)
rejected=[]
for label,change in [
 ('wrong target',lambda q:q['rip_syntactic_candidates'][0].__setitem__('target_rva',0)),
 ('wrong bytes',lambda q:q['rip_syntactic_candidates'][0].__setitem__('bytes','90')),
 ('wrong displacement',lambda q:q['rip_syntactic_candidates'][0].__setitem__('disp_offset',0)),
 ('wrong literal offset',lambda q:q['literal_names'][0]['file_offsets'].append(0)),
 ('unbacked consumer claim',lambda q:q['claims'].__setitem__('eid_consumer_identified',True)),
 ('wrong section bounds',lambda q:q['target_sections'][0].__setitem__(1,0))]:
 q=copy.deepcopy(d);change(q)
 try:validate(q)
 except (AssertionError,struct.error,IndexError):rejected.append(label)
 else:raise AssertionError(label)
# Decode branch targets using raw opcodes only, without Capstone.
def branch(a,opcode):
 b=p.read(a,6);assert b.startswith(opcode)
 off=len(opcode);size=1 if len(opcode)==1 else 4
 return a+off+size+int.from_bytes(b[off:off+size],'little',signed=True)
assert branch(0x11a6bdd,b'\x72')==0x11a6c3c
assert p.read(0x11a6bdf,2)==bytes.fromhex('8adb')
assert branch(0x11a6be1,b'\x73')==0x11a6c34
assert all(not ((not bool(cf)) and (not (not bool(cf)))) for cf in [0,1])
# JBE encodings can be short or near; read the real encoding.
def jbe(a):
 b=p.read(a,2)
 return branch(a,b'\x76' if b[0]==0x76 else b'\x0f\x86')
assert jbe(0x1157a59)==0x1157a78 and jbe(0x1157a78)==0x1157aa2
assert all(not ((cf or zf) and not(cf or zf)) for cf in [0,1] for zf in [0,1])
keys=lambda xs:{(x['rva'],x['bytes']) for x in xs}
parts=[keys(r[k]) for k in ['retained_syntactic_candidates','excluded_in_closed_model','unresolved_in_incomplete_model','outside_pdata_candidates']]
assert sum(map(len,parts))==n and set.union(*parts)==keys(d['rip_syntactic_candidates'])
assert all(not any(a&b) for i,a in enumerate(parts) for b in parts[i+1:])
assert not any(r['claims'].values())
out={'status':'PASS','scope':'Stdlib byte/index/PE/partition and two local branch-contradiction checks; NOT independent instruction/CFG validation or runtime evidence.','indexed_candidates_checked':n,'dir64_target_matches':len(d['relocation_backed_pointers']),'corruptions_rejected':rejected,'local_witness_contradictions_verified':2,'input_sha256':PIN}
(D/'reports/verification.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
