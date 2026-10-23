"""Independent stdlib PE/reference arithmetic + raw opcode/displacement prefilter scan."""
from pathlib import Path
import json,struct,hashlib,collections,copy
from pe_manual import PE
D=Path(__file__).resolve().parents[1];p=PE(Path('/data/wlab-inputs/Wow.exe'));d=json.loads((D/'reports/discovery.json').read_text());PIN='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a'
# Read executable characteristics independently, not from pefile.
o=struct.unpack_from('<I',p.b,0x3c)[0];n=struct.unpack_from('<H',p.b,o+6)[0];sz=struct.unpack_from('<H',p.b,o+20)[0];sec=[]
for j in range(n):
 a=o+24+sz+j*40;name=p.b[a:a+8].rstrip(b'\0').decode();vs,va,rs,ro=struct.unpack_from('<IIII',p.b,a+8);flags=struct.unpack_from('<I',p.b,a+36)[0];sec.append((name,vs,va,rs,ro,flags))
def section(r):
 return next(s for s in sec if s[2]<=r<s[2]+max(s[1],s[3]))
slots={'merge_candidate':0x47cf800,'creator_candidate':0x47cf810,'parse_fallback_candidate':0x47cec38};targets={k:p.u(v,'<Q')-p.base for k,v in slots.items()}
ranges=d['metadata_ranges'];classbase=slots['creator_candidate']-0x30;table=slots['parse_fallback_candidate']-0x30;prototype=p.u(classbase,'<Q')-p.base
expected_ranges=[['candidate_class_record',classbase,classbase+0x68],['candidate_parse_header',table,table+56],['prototype_first_qword',prototype,prototype+8]]
rr=[];cursor,size=p.dirs[5];end=cursor+size
while cursor<end:
 page,bs=struct.unpack('<II',p.read(cursor,8));assert bs>=8 and bs%2==0 and cursor+bs<=end
 for off in range(8,bs,2):
  e=p.u(cursor+off,'<H')
  if e>>12==10:
   slot=page+(e&0xfff);t=p.u(slot,'<Q')-p.base;kind=next((k for k,v in targets.items() if t==v),None)
   kind=kind or next((name for name,lo,hi in expected_ranges if lo<=t<hi),None)
   if kind:
    s=section(slot);rr.append({'slot_rva':slot,'target_rva':t,'target_kind':kind,'slot_section':s[0],'slot_in_executable_section':bool(s[5]&0x20000000)})
 cursor+=bs
# Independent raw arithmetic prefilter. Not a decoder and NOT a runtime call graph.
raw_direct=[];raw_rip=[]
for name,vs,va,rs,ro,flags in sec:
 if not flags&0x20000000:continue
 data=p.b[ro:ro+min(vs,rs)];length=len(data)
 for opcode in [b'\xe8',b'\xe9']:
  at=0
  while (at:=data.find(opcode,at))>=0:
   if at+5<=length:
    t=va+at+5+struct.unpack_from('<i',data,at+1)[0]
    if t in targets.values():raw_direct.append((va+at,t))
   at+=1
 for q in range(1,length-3):
  if data[q-1]&0xc7!=5:continue
  disp=struct.unpack_from('<i',data,q)[0]
  for tail in [0,1,2,4,8]:
   t=va+q+4+tail+disp
   if any(lo<=t<hi for _,lo,hi in expected_ranges):raw_rip.append((va+q,tail,t))
def check(d):
 assert hashlib.sha256(p.b).hexdigest()==d['sha256']==PIN and d['image_base']==p.base
 assert d['slot_rvas']==slots and d['code_targets']==targets and d['metadata_ranges']==expected_ranges
 assert p.u(classbase+8,'<Q')-p.base==table and p.u(table+32,'<Q')-p.base==classbase
 assert d['selection']['target']=='creator_candidate' and d['selection']['slot_rva']==slots['creator_candidate'] and d['selection']['target_rva']==targets['creator_candidate']
 assert d['relocation_backed_references']==rr
 # Zero raw arithmetic hits independently corroborate zero decoded candidates.
 if not raw_direct:assert d['direct_branch_candidates']==[]
 if not raw_rip:assert d['rip_metadata_candidates']==[]
 for c in d['direct_branch_candidates']+d['rip_metadata_candidates']:
  b=bytes.fromhex(c['bytes']);assert p.read(c['rva'],len(b))==b
 assert not any(d['claims'].values())
check(d)
rejected=[]
for name,mut in [('target address',lambda q:q['code_targets'].__setitem__('creator_candidate',0)),('record range',lambda q:q['metadata_ranges'][0].__setitem__(1,0)),('pointer slot',lambda q:q['relocation_backed_references'][0].__setitem__('slot_rva',0)),('executable classification',lambda q:q['relocation_backed_references'][0].__setitem__('slot_in_executable_section',True)),('collector claim',lambda q:q['claims'].__setitem__('hardware_collector_identified',True)),('selected target',lambda q:q['selection'].__setitem__('target_rva',0))]:
 q=copy.deepcopy(d);mut(q)
 try:check(q)
 except (AssertionError,IndexError):rejected.append(name)
 else:raise AssertionError(name)
out={'status':'PASS','scope':'Independent stdlib PE/metadata-cycle/relocation/section checks; full raw E8/E9 and RIP-displacement arithmetic prefilter over executable sections; not a semantic decoder/ABI/runtime proof.','relocation_references_checked':len(rr),'reference_kinds':dict(collections.Counter(r['target_kind'] for r in rr)),'reference_sections':dict(collections.Counter(r['slot_section'] for r in rr)),'executable_reference_slots':sum(r['slot_in_executable_section'] for r in rr),'independent_raw_direct_branch_hits':len(raw_direct),'independent_raw_rip_prefilter_hits':len(raw_rip),'raw_rip_prefilter_sample':raw_rip[:20],'mutations_rejected':rejected}
(D/'reports/verification.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
