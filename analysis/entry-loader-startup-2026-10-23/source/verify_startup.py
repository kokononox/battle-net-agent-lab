"""Independent standard-library-only verifier; does not import producer or PE libs."""
import argparse, copy, hashlib, json, random, struct
from pathlib import Path
PINS={'Wow.exe':'1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a','wow_loader.dll':'c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c','libxell.dll':'5ce63652eee5720203e0e41cc97eb45ee541c499c8a51d4bdb1e8fe4eaef4890'}
class PE:
 def __init__(self,path):
  self.b=path.read_bytes();b=self.b
  assert b[:2]==b'MZ';o=struct.unpack_from('<I',b,0x3c)[0];assert b[o:o+4]==b'PE\0\0'
  machine,n,_,_,_,sz,_=struct.unpack_from('<HHIIIHH',b,o+4);assert machine==0x8664
  opt=o+24;assert struct.unpack_from('<H',b,opt)[0]==0x20b
  self.base=struct.unpack_from('<Q',b,opt+24)[0];self.ep=struct.unpack_from('<I',b,opt+16)[0]
  self.dirs=[struct.unpack_from('<II',b,opt+112+i*8) for i in range(16)];self.sections=[]
  for i in range(n):
   s=opt+sz+i*40;name=b[s:s+8].rstrip(b'\0').decode();vs,r,rs,ro=struct.unpack_from('<IIII',b,s+8)
   self.sections.append((name,vs,r,rs,ro))
 def loc(self,r,n=1):
  for name,vs,va,rs,ro in self.sections:
   d=r-va
   if d>=0 and d+n<=max(vs,rs):return {'section':name,'file_backed':d+n<=rs,'file_offset':ro+d if d+n<=rs else None,'zero_filled_virtual_tail':d+n>rs and d+n<=vs}
  raise AssertionError('RVA unmapped')
 def read(self,r,n):
  l=self.loc(r,n);assert l['file_backed'];o=l['file_offset'];assert o+n<=len(self.b);return self.b[o:o+n]
 def u(self,r,fmt):return struct.unpack(fmt,self.read(r,struct.calcsize(fmt)))[0]
 def text(self,r):
  out=bytearray()
  for i in range(4096):
   c=self.read(r+i,1)
   if c==b'\0':return out.decode()
   out+=c
  raise AssertionError('Unterminated name')
 def imports(self):
  start,size=self.dirs[1];rows=[]
  if not start:return rows
  for k in range(4096):
   r=start+k*20;d=struct.unpack('<IIIII',self.read(r,20))
   if not any(d):return rows
   oft,_,_,name,ft=d;entries=[]
   for i in range(65536):
    v=self.u((oft or ft)+i*8,'<Q')
    if not v:break
    ordinal=(v&0xffff) if v>>63 else None
    entries.append({'ordinal':ordinal,'literal_name':None if ordinal is not None else self.text(v+2),'slot_rva':ft+i*8})
   else:raise AssertionError('Unterminated thunk')
   rows.append({'dll':self.text(name),'descriptor_file_offset':self.loc(r,20)['file_offset'],'first_thunk':ft,'original_first_thunk':oft,'entries':entries})
  raise AssertionError('Unterminated descriptors')
 def tls(self):
  start,size=self.dirs[9];out=[]
  if not start:return out
  va=self.u(start+24,'<Q')
  if not va:return out
  arr=va-self.base
  for i in range(64):
   v=self.u(arr+i*8,'<Q')
   if not v:return out
   out.append({'slot_rva':arr+i*8,'callback_rva':v-self.base})
  raise AssertionError('Unterminated TLS')
 def exports(self):
  start,size=self.dirs[0];out=[]
  if not start:return out
  raw=self.read(start,40);base,n,names,funcs=struct.unpack_from('<IIII',raw,16)
  for i in range(n):
   r=self.u(funcs+4*i,'<I')
   if r:out.append({'ordinal':base+i,'rva':r,'forwarder':self.text(r) if start<=r<start+size else None})
  return out

def validate(report,images):
 assert report['schema']=='wlab-startup-review-1'
 assert len(report['input_modules'])==3
 for row in report['input_modules']:
  p=images[row['name']];assert row['sha256']==PINS[row['name']]==hashlib.sha256(p.b).hexdigest()
  assert row['size']==len(p.b) and row['image_base']==p.base and row['entry_rva']==p.ep
  assert row['imports']==p.imports() and row['tls_callbacks']==p.tls() and row['exports']==p.exports()
 exe,loader=images['Wow.exe'],images['wow_loader.dll']
 assert exe.ep==0x1da9b0 and len(exe.imports())==1
 imp=exe.imports()[0];assert imp['dll'].lower()=='wow_loader.dll' and imp['entries']==[{'ordinal':1,'literal_name':None,'slot_rva':0x3b5b000}]
 assert any(e['ordinal']==1 and e['rva']==0x22eff0 and e['forwarder'] is None for e in loader.exports())
 assert len(loader.imports())==36 and {d['first_thunk'] for d in loader.imports()}=={0x20a0088}
 assert [t['callback_rva'] for t in exe.tls()]==[0x1da9e0]*3
 assert exe.read(0x1da9e0,3)==bytes.fromhex('c20000')
 assert [t['callback_rva'] for t in loader.tls()]==[0xdf87c0,0x200319c]
 assert exe.read(exe.ep,25).hex()=='4883ec28488b057db58f044885c07402ffd033c04883c428c3'
 target=0x1da9bb+struct.unpack('<i',exe.read(0x1da9b7,4))[0];assert target==0x4ad5f38
 expected={'rva':target,**exe.loc(target,8),'writer_identified':False,'runtime_target_identified':False}
 assert report['exe_indirect_slot']==expected and expected['zero_filled_virtual_tail']
 c=report['callback'];assert (c['start_rva'],c['end_rva'],c['reason'])==(0xdf87c0,0xdf88d9,1)
 raw=loader.read(0xdf87c0,0x119);assert bytes.fromhex(c['raw_bytes'])==raw and c['sha256']==hashlib.sha256(raw).hexdigest()
 exception_rva,exception_size=loader.dirs[3]
 assert any(struct.unpack('<II',loader.read(a,8))==(0xdf87c0,0xdf88d9) for a in range(exception_rva,exception_rva+exception_size,12))
 critical={0xdf8820:'24ff7345',0xdf8869:'83fa017565',0xdf88b0:'817c2424befeb8400f8462ffffff',0xdf88be:'b962000000ba1f00000041b819000000e8ad386c00'}
 for a,h in critical.items():assert loader.read(a,len(bytes.fromhex(h))).hex()==h
 assert 0xdf88d3+struct.unpack('<i',loader.read(0xdf88cf,4))[0]==0x14bc180
 assert c['call_site_rva']==0xdf88ce and c['callee_rva']==0x14bc180
 assert c['callsite_register_values']=={'ecx':0x62,'edx':0x1f,'r8d':0x19}
 assert [(r['rva'],r['decision']) for r in c['rules']]==[(0xdf8822,'taken'),(0xdf886c,'fallthrough'),(0xdf88b8,'fallthrough')]
 # Independent algebra: after cancellation r=-K1. K1 odd, K2 even,
 # K4-K1 even => parity(((x+K1)^K2)+(K4-K1)) XOR x is 1.
 # Every equality with an even magic is therefore false, for all DWORDs.
 k1,k2,k3,k4=0x4f87b8db,0x4d3e9198,0x72579d11,0x8474598d;mask=0xffffffff
 assert k1&1 and not k2&1 and not (k4-k1)&1 and not 0x40b8febe&1
 rng=random.Random(20261023)
 for x in [0,1,0xffffffff,0xf02a9b7c]+[rng.getrandbits(32) for _ in range(10000)]:
  c0=((x+k1)&mask)^k2;r=(c0+k3)&mask;r=(r+x)&mask;r=(r+k1)&mask;r=(-r)&mask;r=(r+c0)&mask;r=(r+k3)&mask;r=(r+x)&mask
  g=((c0+r+k4)&mask)^x
  assert r==(-k1)&mask and g&1 and g!=0x40b8febe
 assert c['first_guard_policy']=='retain both branches; disk value is not a runtime invariant'
 for row,site,next_rva in zip(c['global_reads'],[0xdf87c4,0xdf886e],[0xdf87ca,0xdf8874]):
  r=next_rva+struct.unpack('<i',loader.read(site+2,4))[0];assert row=={'rva':r,'disk_u32':loader.u(r,'<I')}
 assert [x['equals_magic'] for x in c['first_guard_examples']]==[True,False,False,False]
 nodes={n['rva']:n for n in c['nodes']};assert len(nodes)==len(c['nodes'])
 supplied={e['from']:e['to'] for e in c['edges']};edges={};occupied=set()
 for a,n in nodes.items():
  b=bytes.fromhex(n['bytes']);assert loader.read(a,len(b))==b
  span=set(range(a,a+len(b)));assert not occupied&span;occupied|=span
  end=a+len(b)
  # Branch targets independently computed from bytes, never operand strings.
  if a==0xdf8814:succ=[end+struct.unpack('<i',b[2:])[0],end]
  elif a==0xdf8822:assert b==b'\x73\x45';succ=[end+struct.unpack('<b',b[1:])[0]]
  elif a in (0xdf886c,0xdf88b8):succ=[end]
  elif b==b'\xc3':succ=[]
  else:succ=[end]
  assert supplied[a]==succ;edges[a]=succ
 assert nodes[0xdf8869]['bytes']=='83fa01' and nodes[0xdf8820]['bytes']=='24ff'
 assert nodes[0xdf88ce]['bytes']=='e8ad386c00'
 assert not any(0xdf8824<=a<0xdf8869 for a in nodes)
 seen=set()
 def walk(a,stack=frozenset()):
  assert a in nodes and a not in stack;seen.add(a)
  for t in edges[a]:walk(t,stack|{a})
 walk(0xdf87c0);assert seen==set(nodes)
 def must_hit(a,stack=frozenset()):
  if a==0xdf88ce:return True
  if a in stack or not edges[a]:return False
  return all(must_hit(t,stack|{a}) for t in edges[a])
 assert must_hit(0xdf87c0) and c['all_modeled_precall_paths_reach_call'] is True
 assert len(c['proofs'])==3 and all(p['result']=='unsat' and p['bit_width']==32 for p in c['proofs'])
 assert report['claims']=={'observed_runtime_execution':False,'exe_slot_writer_found':False,'unpacker_identified':False,'bios_read_proven':False,'hardware_serialization_proven':False,'hardware_send_3724_proven':False}
 return {'manual_pe_checks':'passed','byte_and_edge_checks':'passed','independent_modular_parity_proof':'passed','deterministic_arithmetic_samples':10004,'precall_path_check':'passed','normalized_instructions':len(nodes)}

if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--input-dir',type=Path,required=True);ap.add_argument('--report',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);args=ap.parse_args()
 images={name:PE(args.input_dir/name) for name in PINS};report=json.loads(args.report.read_text());result=validate(report,images)
 mutants=[]
 for label,mutate in [('wrong_callee',lambda r:r['callback'].__setitem__('callee_rva',0x14bc181)),('wrong_branch',lambda r:r['callback']['rules'][0].__setitem__('decision','fallthrough')),('file_backed_slot',lambda r:r['exe_indirect_slot'].__setitem__('file_backed',True)),('runtime_global_assumed',lambda r:r['callback'].__setitem__('first_guard_policy','assume disk value unchanged')),('send_overclaim',lambda r:r['claims'].__setitem__('hardware_send_3724_proven',True)),('changed_instruction_byte',lambda r:r['callback']['nodes'][0].__setitem__('bytes','90')),('removed_precall_edge',lambda r:r['callback']['edges'][0].__setitem__('to',[]))]:
  bad=copy.deepcopy(report);mutate(bad)
  try:validate(bad,images)
  except (AssertionError,KeyError,ValueError):mutants.append({'mutation':label,'rejected':True})
  else:raise AssertionError('Accepted mutation: '+label)
 result['mutation_tests']=mutants;result['external_game_execution']=False;args.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
