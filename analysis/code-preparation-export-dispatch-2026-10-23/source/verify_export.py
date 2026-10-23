from pathlib import Path
from pe_manual import PE
import json,struct,hashlib,random,copy
root=Path('/data/wlab-code-preparation-review');p=PE(Path('/data/wlab-inputs/wow_loader.dll'));r=json.loads((root/'export-dispatch.json').read_text());mask=0xffffffff
assert hashlib.sha256(p.b).hexdigest()==r['module_sha256']
for node in r['nodes']:assert p.read(node['rva'],len(bytes.fromhex(node['bytes']))).hex()==node['bytes']
def state(x):
 c=(x+0x624149a5)&mask;d=c^0x961d302b;v=((d+0x6def6a44)&mask)^0xc2d359a2
 c^=0xa135c2cd
 return ((c-v+x+0x624149a5+d+0x6def6a44-v+0x9f000b38)&mask)^x
def signed(v):return v if v<0x80000000 else v-0x100000000
def walk(x):
 a=0x22f0e0;last=None;v=state(x)
 for _ in range(100):
  b=p.read(a,10)
  if b[:5]==bytes.fromhex('448b54240c'):a+=5;continue
  if b[:3]==bytes.fromhex('4181fa'):last=struct.unpack_from('<I',b,3)[0];a+=7;continue
  if b[0]==0x0f and b[1] in [0x84,0x85,0x8f,0x8e,0x8c,0x8d]:
   pred={0x84:v==last,0x85:v!=last,0x8f:signed(v)>signed(last),0x8e:signed(v)<=signed(last),0x8c:signed(v)<signed(last),0x8d:signed(v)>=signed(last)}[b[1]]
   a=a+6+(struct.unpack_from('<i',b,2)[0] if pred else 0);continue
  return a
 raise AssertionError('bound')
frontiers={l['rva'] for l in r['leaves']};seen=set();rng=random.Random(70448);samples=[0,1,mask,r['disk_global_u32']]+[rng.getrandbits(32) for _ in range(10000)]
for x in samples:
 a=walk(x);assert a in frontiers;seen.add(a)
for leaf in r['leaves']:assert walk(leaf['witness'])==leaf['rva']
assert walk(r['disk_global_u32'])==next(l['rva'] for l in r['leaves'] if l['disk_matches'])
# Mutation rejection uses the independent byte-bound/witness checks above.
mutations=[]
for key in ['rva','witness']:
 bad=copy.deepcopy(r['leaves'][0]);bad[key]^=1
 try:assert walk(bad['witness'])==bad['rva']
 except AssertionError:mutations.append(key)
# A witness mutation can happen to stay in the same partition; do not claim rejected unless it is.
v={'raw_instruction_bytes_matched':len(r['nodes']),'independent_concrete_samples':len(samples),'solver_witnesses_verified':len(r['leaves']),'sampled_frontiers':len(seen),'independent_decoder':'stdlib struct for MOV/CMP/rel32 signed conditional branches; no Capstone/Z3','sample_scope':'Sampling is not universal proof; universal coverage is the separate Z3 result.','mutations_rejected':mutations,'disk_value_not_runtime_invariant':True}
(root/'verification.json').write_text(json.dumps(v,indent=2));print(json.dumps(v))
