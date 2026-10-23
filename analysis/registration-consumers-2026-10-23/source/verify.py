"""Independent stdlib index/PE/overlap checks; objdump checks only index/call-site boundaries."""
from pathlib import Path
import json,struct,hashlib,tempfile,subprocess,re,copy
from pe_manual import PE
D=Path(__file__).resolve().parents[1];p=PE(Path('/data/wlab-inputs/wow_loader.dll'));a=json.loads((D/'reports/discovery.json').read_text());t=json.loads((D/'reports/trace.json').read_text());PIN='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
def check(a,t):
 assert hashlib.sha256(p.b).hexdigest()==a['sha256']==t['sha256']==PIN
 head=0x20d2d18;node=p.u(head,'<Q')-p.base
 assert a['target_ranges']==[['head_slot',head,head+8],['initial_node_fields',node,node+16]]
 assert a['head_disk_qword']==p.base+node
 n=a['initial_node_disk_fields'];assert n['rva']==node and n['first_qword']==p.u(node,'<Q') and n['second_qword']==p.u(node+8,'<Q')
 for c in a['syntactic_candidates']:
  b=bytes.fromhex(c['bytes']);d=c['disp_offset'];assert p.read(c['rva'],len(b))==b and 1<=d and d+4<=len(b)<=15
  assert b[d-1]&0xc7==5 and c['rva']+len(b)+struct.unpack_from('<i',b,d)[0]==c['target_rva']
  assert any(lo<=c['target_rva']<hi for _,lo,hi in a['target_ranges'])
 # Independently enumerate relocations to BOTH ranges.
 cursor,size=p.dirs[5];end=cursor+size;rr=[]
 while cursor<end:
  page,sz=struct.unpack('<II',p.read(cursor,8));assert sz>=8 and sz%2==0 and cursor+sz<=end
  for off in range(8,sz,2):
   v=p.u(cursor+off,'<H')
   if v>>12==10:
    slot=page+(v&0xfff);target=p.u(slot,'<Q')-p.base
    if any(lo<=target<hi for _,lo,hi in a['target_ranges']):rr.append({'slot_rva':slot,'target_rva':target})
  cursor+=sz
 assert rr==a['relocation_backed_pointers']
 for r in t['raw_literal_occurrences']:
  b=bytes.fromhex(r['needle_hex']);hits=[];i=0
  while (i:=p.b.find(b,i))>=0:hits.append(i);i+=1
  assert hits==r['file_offsets'] and int.from_bytes(b,'little')==r['value']
 f=t['initial_node_callback_model'];assert f['begin']==n['first_qword']-p.base
 pr,ps=p.dirs[3];bounds={struct.unpack('<III',p.read(pr+i,12))[:2] for i in range(0,ps,12)};assert (f['begin'],f['end']) in bounds
 for r in f['instructions']:
  b=bytes.fromhex(r['bytes']);assert p.read(r['rva'],len(b))==b
 # Independent interval intersection confirms why this model is incomplete.
 intervals=sorted((r['rva'],r['rva']+len(bytes.fromhex(r['bytes']))) for r in f['instructions']);overlaps=set()
 for i,(lo,hi) in enumerate(intervals):
  for q,z in intervals[i+1:]:
   if q>=hi:break
   overlaps.add((lo,q))
 assert {tuple(x) for x in f['overlapping_instruction_pairs']}==overlaps and overlaps and not f['closed_under_stated_model']
 assert not any(a['claims'].values()) and not any(t['claims'].values())
check(a,t)
recs=a['syntactic_candidates']+t['initial_node_callback_model']['direct_call_candidates']
with tempfile.TemporaryDirectory() as tmp:
 f=Path(tmp)/'packed.bin';f.write_bytes(b''.join(bytes.fromhex(r['bytes']).ljust(16,b'\xcc') for r in recs));text=subprocess.check_output(['objdump','-D','-b','binary','-m','i386:x86-64','-M','intel','-w',str(f)],text=True);decoded={}
 for line in text.splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)',line)
  if m:decoded[int(m[1],16)]=bytes.fromhex(m[2])
 for i,r in enumerate(recs):assert decoded[16*i]==bytes.fromhex(r['bytes'])
for c in t['initial_node_callback_model']['direct_call_candidates']:
 b=bytes.fromhex(c['bytes']);assert len(b)==5 and b[0]==0xe8 and c['rva']+5+int.from_bytes(b[1:],'little',signed=True)==c['target_rva']
rejected=[]
for name,which,mut in [('reference target','a',lambda q:q['syntactic_candidates'][0].__setitem__('target_rva',0)),('node pointer','a',lambda q:q['initial_node_disk_fields'].__setitem__('first_qword',0)),('relocation target','a',lambda q:q['relocation_backed_pointers'][0].__setitem__('target_rva',0)),('raw literal count','t',lambda q:q['raw_literal_occurrences'][0]['file_offsets'].append(0)),('false closed model','t',lambda q:q['initial_node_callback_model'].__setitem__('closed_under_stated_model',True)),('consumer claim','t',lambda q:q['claims'].__setitem__('independent_anchor_consumer_identified',True))]:
 aa,tt=copy.deepcopy(a),copy.deepcopy(t);mut(aa if which=='a' else tt)
 try:check(aa,tt)
 except (AssertionError,IndexError):rejected.append(name)
 else:raise AssertionError(name)
out={'status':'PASS','scope':'Independent stdlib PE/index/relocation/literal/byte/overlap checks; objdump checks 2 anchor candidates + 7 call-site candidates. NOT proof of full scan completeness, CFG correctness or runtime.','rip_candidates_checked':len(a['syntactic_candidates']),'relocation_matches_checked':len(a['relocation_backed_pointers']),'callback_instruction_bytes_checked':len(t['initial_node_callback_model']['instructions']),'independently_confirmed_overlap_pairs':len(t['initial_node_callback_model']['overlapping_instruction_pairs']),'objdump_boundaries_checked':len(recs),'mutation_tests_rejected':rejected}
(D/'reports/verification.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
