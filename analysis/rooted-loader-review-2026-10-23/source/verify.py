"""Independent PE/bytes/table/branch/objdump-boundary checks. Not a CFG proof."""
from pathlib import Path
import json,struct,hashlib,subprocess,re,tempfile,copy
from pe_manual import PE
D=Path(__file__).resolve().parents[1];p=PE(Path('/data/wlab-inputs/wow_loader.dll'));d=json.loads((D/'reports/arrays.json').read_text());PIN='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
def check(d):
 assert hashlib.sha256(p.b).hexdigest()==d['sha256']==PIN
 for table in d['tables']:
  lo,hi=table['begin'],table['end_exclusive'];assert hi>=lo and (hi-lo)%8==0
  assert [e['slot_rva'] for e in table['entries']]==list(range(lo,hi,8))
  for e in table['entries']:
   v=p.u(e['slot_rva'],'<Q');assert v==e['disk_qword'];assert e['target_rva']==(v-p.base if v else None)
  for rec,t in zip(table['bound_loads'],[lo,hi]):
   b=bytes.fromhex(rec['bytes']);assert len(b)==7 and b[:2] in [b'\x48\x8d',b'\x4c\x8d'] and b[2]&0xc7==5
   assert rec['rva']+7+struct.unpack('<i',b[3:])[0]==t and p.read(rec['rva'],7)==b
  if table['call_site']:
   rec=table['call_site'];b=bytes.fromhex(rec['bytes']);assert b[0]==0xe8 and len(b)==5 and p.read(rec['rva'],5)==b
   assert rec['rva']+5+int.from_bytes(b[1:],'little',signed=True)==table['callee']
 for f in d['functions']+d['support_bodies']:
  for rec in f['instructions']:
   b=bytes.fromhex(rec['bytes']);assert 1<=len(b)<=15 and p.read(rec['rva'],len(b))==b
 for k,v in d['claims'].items():assert v is False
check(d)
# Independent decoder validates reported instruction bytes/lengths of support bodies.
recs=[r for f in d['support_bodies'] for r in f['instructions']]
with tempfile.TemporaryDirectory() as td:
 path=Path(td)/'packed.bin';path.write_bytes(b''.join(bytes.fromhex(r['bytes']).ljust(16,b'\xcc') for r in recs))
 text=subprocess.check_output(['objdump','-D','-b','binary','-m','i386:x86-64','-M','intel','-w',str(path)],text=True)
 decoded={}
 for line in text.splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)',line)
  if m:decoded[int(m[1],16)]=bytes.fromhex(m[2])
 for n,r in enumerate(recs):assert decoded[n*16]==bytes.fromhex(r['bytes'])
# All direct rel8/rel32 transfers in support bodies independently recomputed.
branches=0
for f in d['support_bodies']:
 for r in f['instructions']:
  b=bytes.fromhex(r['bytes']);off=size=None
  if b[0] in [0xe8,0xe9]:off,size=1,4
  elif b[0]==0xeb or 0x70<=b[0]<=0x7f:off,size=1,1
  elif len(b)>1 and b[0]==0x0f and 0x80<=b[1]<=0x8f:off,size=2,4
  if off is not None:
   t=r['rva']+len(b)+int.from_bytes(b[off:off+size],'little',signed=True)
   assert t==int(r['asm'].split()[-1],16);branches+=1
rejected=[]
for name,mutate in [('table bound',lambda q:q['tables'][0].__setitem__('end_exclusive',0)),('pointer target',lambda q:q['tables'][0]['entries'][1].__setitem__('target_rva',0)),('instruction bytes',lambda q:q['support_bodies'][0]['instructions'][0].__setitem__('bytes','90')),('runtime claim',lambda q:q['claims'].__setitem__('runtime_execution_observed',True)),('call target',lambda q:q['tables'][0].__setitem__('callee',0)),('bound load',lambda q:q['tables'][0]['bound_loads'][0].__setitem__('rva',0x2006387))]:
 q=copy.deepcopy(d);mutate(q)
 try:check(q)
 except (AssertionError,IndexError):rejected.append(name)
 else:raise AssertionError(name)
out={'status':'PASS','scope':'Independent stdlib byte/table arithmetic and objdump instruction boundary checks for 3 support bodies; NOT independent full CFG or runtime validation.','tables_checked':3,'nonnull_disk_pointer_entries':sum(e['target_rva'] is not None for t in d['tables'] for e in t['entries']),'all_reported_bytes_checked':sum(len(f['instructions']) for f in d['functions']+d['support_bodies']),'objdump_support_boundaries_checked':len(recs),'support_rel_branches_checked':branches,'mutation_tests_rejected':rejected}
(D/'reports/verification.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
