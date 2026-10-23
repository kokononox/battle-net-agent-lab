"""Independent stdlib metadata/thunk checks + objdump boundaries, not full CFG validation."""
from pathlib import Path
import json,hashlib,struct,tempfile,subprocess,re,copy
from pe_manual import PE
D=Path(__file__).resolve().parents[1];p=PE(Path('/data/wlab-inputs/wow_loader.dll'));d=json.loads((D/'reports/evidence.json').read_text());PIN='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
# PE32+ field offsets from the IMAGE_LOAD_CONFIG_DIRECTORY64 layout.
FIELDS={'GuardCFDispatchFunctionPointer':0x78,'GuardXFGDispatchFunctionPointer':0x120}
def records(d):
 return [x['target_instruction'] for x in d['fields']]+[s['instruction'] for c in d['disk_chains'] for s in c['steps']]+d['call_sites']+d['helper']['instructions']+[r for c in d['caller_evidence'] for r in c['instructions']]
def validate(d):
 assert hashlib.sha256(p.b).hexdigest()==d['input_sha256']==PIN and d['image_base']==p.base
 cfg,sz=p.dirs[10];assert d['load_config_rva']==cfg and d['load_config_directory_size']==sz
 structsz=p.u(cfg,'<I');assert d['load_config_struct_size']==structsz and sz>=0x128 and structsz>=0x128
 assert d['guard_flags']==p.u(cfg+0x90,'<I')
 assert len(d['fields'])==2
 slots=[]
 for row in d['fields']:
  off=FIELDS[row['field']];assert row['relative_offset']==off
  v=p.u(cfg+off,'<Q');slot=v-p.base;assert row['value_va']==v and row['slot_rva']==slot
  q=p.u(slot,'<Q');assert row['slot_disk_qword']==q and row['target_rva']==q-p.base
  assert row['target_instruction']['rva']==q-p.base;slots.append(slot)
 assert len(set(slots))==2 and len(d['disk_chains'])==2
 for slot,chain in zip(slots,d['disk_chains']):
  assert chain['terminal']=='jmp_rax_on_disk' and chain['runtime_binding_confirmed'] is False
  visited=set()
  for n,step in enumerate(chain['steps']):
   assert slot not in visited;visited.add(slot);assert step['slot_rva']==slot
   a=p.u(slot,'<Q')-p.base;assert a==step['disk_target_rva']==step['instruction']['rva']
   b=bytes.fromhex(step['instruction']['bytes']);assert p.read(a,len(b))==b
   if b==b'\xff\xe0':assert n==len(chain['steps'])-1
   else:
    assert len(b)==6 and b[:2]==b'\xff\x25' and n+1<len(chain['steps'])
    slot=a+6+int.from_bytes(b[2:],'little',signed=True);assert step['next_slot_rva']==slot
  assert chain['steps'][-1]['instruction']['bytes']=='ffe0'
 for c in d['call_sites']:
  b=bytes.fromhex(c['bytes']);assert len(b)==6 and b[:2]==b'\xff\x15'
  slot=c['rva']+6+int.from_bytes(b[2:],'little',signed=True);assert c['slot_rva']==slot
  assert next(r['slot_rva'] for r in d['fields'] if r['field']==c['load_config_field'])==slot
 for r in records(d):
  b=bytes.fromhex(r['bytes']);assert p.read(r['rva'],len(b))==b and 1<=len(b)<=15
 assert d['claims']=={'disk_guard_dispatch_chain_identified':True,'runtime_guard_binding_verified':False,'all_initializer_targets_execute':False,'eid_consumer_identified':False,'decryptor_identified':False,'cpu_bios_send_chain_identified':False}
 assert d['helper']['begin']==0x957f00 and d['helper']['end']==0x9580d6
 assert not d['helper']['calls']
validate(d)
rs=list({(r['rva'],r['bytes']):r for r in records(d)}.values())
with tempfile.TemporaryDirectory() as tmp:
 f=Path(tmp)/'packed.bin';f.write_bytes(b''.join(bytes.fromhex(r['bytes']).ljust(16,b'\xcc') for r in rs))
 text=subprocess.check_output(['objdump','-D','-b','binary','-m','i386:x86-64','-M','intel','-w',str(f)],text=True);decoded={}
 for line in text.splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)',line)
  if m:decoded[int(m[1],16)]=bytes.fromhex(m[2])
 for i,r in enumerate(rs):assert decoded[16*i]==bytes.fromhex(r['bytes'])
branches=0
for r in rs:
 b=bytes.fromhex(r['bytes']);off=size=None
 if b[0] in [0xe8,0xe9]:off,size=1,4
 elif b[0]==0xeb or 0x70<=b[0]<=0x7f:off,size=1,1
 elif len(b)>1 and b[0]==15 and 0x80<=b[1]<=0x8f:off,size=2,4
 if off is not None:
  assert r['rva']+len(b)+int.from_bytes(b[off:off+size],'little',signed=True)==int(r['asm'].split()[-1],16);branches+=1
rejected=[]
for name,mutate in [('field offset',lambda q:q['fields'][0].__setitem__('relative_offset',0)),('dispatch slot',lambda q:q['call_sites'][0].__setitem__('slot_rva',0)),('thunk target',lambda q:q['disk_chains'][1]['steps'][0].__setitem__('next_slot_rva',0)),('terminal bytes',lambda q:q['disk_chains'][0]['steps'][0]['instruction'].__setitem__('bytes','c3')),('runtime claim',lambda q:q['claims'].__setitem__('runtime_guard_binding_verified',True)),('helper bytes',lambda q:q['helper']['instructions'][0].__setitem__('bytes','90')),('config size',lambda q:q.__setitem__('load_config_struct_size',0))]:
 q=copy.deepcopy(d);mutate(q)
 try:validate(q)
 except (AssertionError,IndexError,StopIteration):rejected.append(name)
 else:raise AssertionError(name)
out={'status':'PASS','scope':'Independent stdlib load-config/slot/call/thunk arithmetic and objdump instruction boundaries; no runtime or full CFG validation.','dispatch_fields_checked':2,'disk_chains_checked':2,'callsites_checked':3,'unique_instruction_boundaries_checked':len(rs),'direct_relative_branches_checked':branches,'mutations_rejected':rejected}
(D/'reports/verification.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
