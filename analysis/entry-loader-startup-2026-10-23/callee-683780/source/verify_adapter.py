"""Independent integer replay and byte-locked algebra certificate.
The decoder is shared Capstone; PE mapping and arithmetic are separate.
"""
import argparse,copy,hashlib,json,random,struct
from pathlib import Path
from integer_replay import replay
from pe_manual import PE
PIN='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
ASSUMPTIONS=['All recorded module reads equal their disk bytes at each read; instruction bytes unchanged','Valid stack, ordinary memory and nonaliasing analysis regions; no exceptions, nonlocal control flow or asynchronous code mutation','The prefix ends before the opaque call; the suffix is a separate snapshot, NOT an inferred postcondition of that call']
CONCLUSIONS={'runtime_observed':False,'opaque_call_implemented_or_summarized':False,'source_content_or_encoding_proven':False,'hardware_read_proven':False,'hardware_send_3724_proven':False,'exe_slot_writer_found':False,'actual_output_bytes_proven':False}
PREFIX_CONTRACT={'destination_span':['D','D + 256 (mod 2^64)'],'source_span':['U','U + 2*N (mod 2^64)'],'opaque_target':'0x6995D0','opaque_call_registers':{'RCX':'0x63','RDX':'pointer to local destination span (16 bytes)','R8':'pointer to local source span (16 bytes)','R9':'0x63'},'opaque_stack_args':{'5':'incoming control DWORD pointer','6':'0xA'},'control_pointer_dereferenced_in_prefix':False,'source_and_destination_contents_read_in_prefix':False}
SUFFIX_CONTRACT={'write_site':'0x683CDD','write_size':8,'destination':'Q','value':'A - D (mod 2^64)','return_low32':'low32 of opaque return','does_not_establish':'A is advanced correctly, output is in bounds, or bytes were actually produced by the opaque call'}
LOCKS={
 0x68379b:'488b8424480100004c8bac2438010000488b9c2430010000',
 0x6837eb:'498d744500',
 0x19480e0:'4989104889442410',
 0x1948186:'488b4424104889084883c4185f5ec3',
 0xe83615:'48890248894a084883c4105ec3',
 0x683cac:'488b8424a00000004889442438',
 0x683b22:'48f7d0488d0c80488d04484889442460',
 0x683809:'488b4424704889442478488b44244048f7d048234424384889842480000000',
 0x683ba0:'488b842480000000488d04c04889842488000000',
 0x683c1d:'488b44243848234424404889842490000000',
 0x6838a0:'486b842490000000f5482b842488000000482b4424784803442468482b4424604889842498000000',
 0x683cd0:'488b842498000000488b4c24504889018b44244c'
}
def algebra_certificate():
 # These four one-bit cases prove disjoint partition identities at every bit.
 table=[]
 for a in (0,1):
  for b in (0,1):
   u,v,w=a&b,a&(1-b),(1-a)&b
   assert a==u+v and b==u+w and (a|b)==u+v+w and (a^b)==v+w
   table.append({'a':a,'b':b,'common':u,'only_A':v,'only_B':w})
 # Byte-locked final block: -11*slot90 -slot88 -slot78 +slot68 -slot60.
 # slot90=u, slot88=9v, slot78=v+w, slot68=11(u+v+w), slot60=11w.
 coeffs=[-11+11,-9-1+11,-1+11-11];assert coeffs==[0,1,-1]
 # Disjoint sums have no carries: A=u+v; D=u+w; so v-w=A-D modulo 2^64.
 return table

def verify(p,prefix,suffix,expected):
 assert hashlib.sha256(p.b).hexdigest()==PIN
 directory,size=p.dirs[3]
 for start,end in [(0x683780,0x683d12),(0x1948090,0x1948195),(0xe83570,0xe83622)]:
  assert any(p.read(a,8)==struct.pack('<II',start,end) for a in range(directory,directory+size,12))
 for a,h in LOCKS.items():assert p.read(a,len(bytes.fromhex(h))).hex()==h
 for phase,r in [('prefix',prefix),('suffix',suffix)]:
  ex=expected[phase]
  assert r['schema']=='wlab-span-adapter-'+phase+'-1' and r['module_sha256']==PIN
  assert r['assumptions']==ASSUMPTIONS and r['conclusions']==CONCLUSIONS
  assert r['synthetic_entry_rsp']==0x1000000008
  assert r['trace']==ex['trace'] and r['branches']==ex['branches']
  assert r['global_reads']==[{'rva':a,'size':n,'bytes':h} for (a,n),h in sorted(ex['reads'].items())]
  assert [(c['site'],c['target']) for c in r['calls']]==[(c['site'],c['target']) for c in ex['calls']]
 assert prefix['events']==[{'kind':'opaque_call_boundary','site':0x683ca3,'target':0x6995d0}]
 assert prefix['semantic_contract']==PREFIX_CONTRACT
 assert prefix['span_proofs']=={k:'unsat' for k in ['destination_begin','destination_end','source_begin','source_end']}
 assert not prefix['external_writes']
 assert suffix['semantic_contract']==SUFFIX_CONTRACT
 assert suffix['snapshot']=={'entry_instruction':'0x683CA8','frame':'entry RSP - 0x108','RBX':'D','RBP':'~D','frame+0xA0':'arbitrary A (cursor_after_opaque_call)','frame+0x50':'arbitrary Q (output_qword_pointer)','RAX':'arbitrary opaque return','cookie':'matching recorded cookie for normal epilogue','saved_nonvolatile_registers':'arbitrary saved values for epilogue'}
 assert suffix['events']==[{'kind':'return','rax':'Concat(0, Extract(31, 0, opaque_return_rax))'}]
 assert suffix['intermediate_proofs']=={hex(k):'unsat' for k in [0x60,0x68,0x70,0x78,0x80,0x88,0x90]}
 assert suffix['partition_truth_table']==algebra_certificate() and suffix['partition_ring_proof']=='unsat'
 assert suffix['output_identity']=='cursor_after_opaque_call - destination_base (mod 2^64)'
 assert len(suffix['external_writes'])==1 and suffix['external_writes'][0]['site']==0x683cdd and suffix['external_writes'][0]['size']==8

def numeric_checks(p):
 mask=(1<<64)-1;rng=random.Random(683780)
 cases=[(d,u,n,a,s) for d,u,n,a,s in [(0,0,0,0,0),(1,2,3,4,5),(mask,mask,mask,0,mask),(0x7fffffffffffffff,0x8000000000000000,1,0x8000000000000000,0xffffffff),(0xff,0x100,0x8000000000000000,0x100,0x100000000),(0x100,0x200,12,0xf0,0xabcdef0123456789)]]
 cases += [tuple(rng.getrandbits(64) for _ in range(5)) for _ in range(100)]
 first={}
 for D,U,N,A,status in cases:
  for phase in ['prefix','suffix']:
   r=replay(p,phase,D,U,N,A,status)
   if phase not in first:first[phase]=r
   assert r['trace']==first[phase]['trace'] and r['branches']==first[phase]['branches']
   if phase=='prefix':
    assert r['spans']==[D,(D+256)&mask,U,(U+2*N)&mask] and not r['external']
    assert [(c['site'],c['target']) for c in r['calls']]==[(0x683a8a,0xe83570),(0x683c7f,0x1948090),(0x683ca3,0x6995d0)]
    assert r['calls'][-1]['args']==[0x63,r['frame']+0xa0,r['frame']+0xb0,0x63,0x710000006666,0xa]
   else:
    assert r['external']==[{'pointer':'Q','size':8,'value':(A-D)&mask}] and r['return']==status&0xffffffff
    slots=r['slots'];assert slots[0x60]==11*(~A&D)&mask and slots[0x68]==11*(A|D)&mask
    assert slots[0x70]==A^D and slots[0x78]==A^D and slots[0x80]==~D&A
    assert slots[0x88]==9*(~D&A)&mask and slots[0x90]==A&D and slots[0x98]==(A-D)&mask
 return first,len(cases)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--input',required=True,type=Path);ap.add_argument('--reports',required=True,type=Path);ap.add_argument('--out',required=True,type=Path);a=ap.parse_args();assert a.out.resolve()!=a.input.resolve();p=PE(a.input)
 prefix=json.loads((a.reports/'prefix-proof.json').read_text());suffix=json.loads((a.reports/'suffix-proof.json').read_text());expected,n=numeric_checks(p);verify(p,prefix,suffix,expected)
 mutations=[('changed_span_end',0,lambda q:q['semantic_contract']['destination_span'].__setitem__(1,'D + 512')),('changed_source_scale',0,lambda q:q['semantic_contract']['source_span'].__setitem__(1,'U + N')),('changed_opaque_target',0,lambda q:q['semantic_contract'].__setitem__('opaque_target','0x6995D1')),('crossed_opaque_boundary',0,lambda q:q['conclusions'].__setitem__('opaque_call_implemented_or_summarized',True)),('deleted_instruction',0,lambda q:q['trace'].pop(10)),('flipped_branch',0,lambda q:q['branches'][0].__setitem__('taken',not q['branches'][0]['taken'])),('removed_snapshot_boundary',1,lambda q:q['assumptions'].__setitem__(2,'Inferred opaque behavior')),('xor_instead_of_subtraction',1,lambda q:q['semantic_contract'].__setitem__('value','A XOR D')),('wrong_output_width',1,lambda q:q['semantic_contract'].__setitem__('write_size',4)),('wrong_output_site',1,lambda q:q['semantic_contract'].__setitem__('write_site','0x683CDE')),('claimed_actual_output',1,lambda q:q['conclusions'].__setitem__('actual_output_bytes_proven',True)),('claimed_hardware_send',1,lambda q:q['conclusions'].__setitem__('hardware_send_3724_proven',True)),('changed_global_bytes',1,lambda q:q['global_reads'][0].__setitem__('bytes','00'*q['global_reads'][0]['size'])),('changed_algebra_certificate',1,lambda q:q['partition_truth_table'][0].__setitem__('common',1))]
 tests=[]
 for label,index,fn in mutations:
  items=[copy.deepcopy(prefix),copy.deepcopy(suffix)];fn(items[index])
  try:verify(p,*items,expected)
  except AssertionError:tests.append({'mutation':label,'rejected':True})
  else:raise AssertionError('Accepted mutation '+label)
 result={'manual_PE_and_function_ranges':'passed','separate_integer_replay':'passed','shared_decoder':'Capstone; not independent disassemblers','numeric_cases_per_fragment':n,'numeric_cases_are_universal_proof':False,'prefix_instructions':len(prefix['trace']),'suffix_instructions':len(suffix['trace']),'prefix_stops_before_opaque_call':True,'suffix_is_separate_snapshot':True,'byte_locked_partition_algebra':'proved modulo 2^64; exhaustive one-bit partition plus ring coefficient identity','source_bytes_encoding_and_core_effects':'unresolved','mutation_tests':tests,'input_PE_executed':False}
 a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
