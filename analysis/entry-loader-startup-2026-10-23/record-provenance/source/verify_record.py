"""Separate integer/finite-domain arithmetic and ctypes layout comparison.
Manual PE parsing. Baseline replay uses the shared prior Capstone implementation.
"""
import argparse,copy,ctypes,hashlib,json,struct
from collections import Counter
from pathlib import Path
from pe_manual import PE
from baseline_5c6440 import replay,verify as verify_baseline
PIN='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
ASSUMPTIONS=['Conditional on reaching 0x14C2225 and its nonempty-list branch; code unchanged and ordinary valid reads; no concurrent loader-list mutation','Structure names assume ordinary Windows x64 GS/TEB semantics and the cited reference layout, not an observed OS build or runtime memory snapshot','The half-length formula requires word global G=0xF92D at the read; no runtime invariance is assumed','Transfer through 0x5C6440 inherits the rechecked previous static disk-global scenario and stack guard; it is not an observed execution']
LOCKS={0x14c2225:'65488b042560000000488b4018488d481048898c2460030000488b40104839c80f84ed150000',0x14c224b:'4889842490020000488b8424900200004889842418010000',0x14c22e3:'0fb740580fb70daa78c3008d912af8ffff448d81bc1100004131d089caf7d24189d14181c9962d00004189d24181e269d2ffff4501ca81e1962d000001c981f12c5b00004401d129d1ffc14431c10c008aed',0x14c2374:'80f1d648d3e8',0x14c2414:'488b8c24180100004c8b4160488d8c24d805000048894c242848c74424305b00000048c74424204d00000041b9440000004889c1488d9424e0070000e84b1c0f00',0x15b40a0:'4883ec384c89c04c8b4c2468',0x15b40eb:'48894c243048c74424281c00000048c74424202100000041b8460000004889d14889c2e82d2301ff',0x68379b:'488b8424480100004c8bac2438010000488b9c2430010000',0x6837eb:'498d744500',0x14c2335:'713d',0x14c237a:'7b36',0x14c237c:'7a4a',0x14c23b2:'7b08',0x14c23bc:'7b16',0x14c23c8:'7a0a',0x14c23d4:'a8e1',0x14c23d6:'c0ff00',0x14c23d9:'7128',0x14c2403:'90',0x14c2404:'710e',0x15b40ac:'733b',0x15b40ae:'86ff',0x15b40b0:'722b',0x15b40dd:'720c',0x15b40e9:'7300'}
def count(g,p):
 # Constants are read from their locked opcodes, not the producer's formula.
 mask=0xffffffff
 disp1=p.u(0x14c22f0,'<i');disp2=p.u(0x14c22f7,'<i')
 t=((g+disp2)&mask)^((g+disp1)&mask)
 d=(~g)&mask;r9=d|p.u(0x14c2308,'<I');r10=(d&p.u(0x14c2312,'<I'))+r9
 c=((g&p.u(0x14c231b,'<I'))*2)&mask;c^=p.u(0x14c2323,'<I');c=(c+r10-d+1)&mask;c^=t
 return ((c&255)^p.u(0x14c2376,'<B'))&63

def layouts():
 class US64(ctypes.Structure):_fields_=[('Length',ctypes.c_uint16),('MaximumLength',ctypes.c_uint16),('Buffer',ctypes.c_uint64)]
 class LIST64(ctypes.Structure):_fields_=[('Flink',ctypes.c_uint64),('Blink',ctypes.c_uint64)]
 class LDR64(ctypes.Structure):_fields_=[('InLoadOrderLinks',LIST64),('InMemoryOrderLinks',LIST64),('InInitializationOrderLinks',LIST64),('DllBase',ctypes.c_uint64),('EntryPoint',ctypes.c_uint64),('SizeOfImage',ctypes.c_uint32),('FullDllName',US64),('BaseDllName',US64)]
 class LD64(ctypes.Structure):_fields_=[('Length',ctypes.c_uint32),('Initialized',ctypes.c_uint8),('SsHandle',ctypes.c_uint64),('InLoadOrderModuleList',LIST64),('InMemoryOrderModuleList',LIST64)]
 class PEB64(ctypes.Structure):_fields_=[('Prefix',ctypes.c_uint8*24),('Ldr',ctypes.c_uint64)]
 class TEB64(ctypes.Structure):_fields_=[('Reserved1',ctypes.c_uint64*12),('ProcessEnvironmentBlock',ctypes.c_uint64)]
 actual={'TEB.ProcessEnvironmentBlock':TEB64.ProcessEnvironmentBlock.offset,'PEB.Ldr':PEB64.Ldr.offset,'PEB_LDR_DATA.InLoadOrderModuleList':LD64.InLoadOrderModuleList.offset,'LDR_DATA_TABLE_ENTRY.InLoadOrderLinks':LDR64.InLoadOrderLinks.offset,'UNICODE_STRING.Buffer':US64.Buffer.offset,'LDR_DATA_TABLE_ENTRY.BaseDllName':LDR64.BaseDllName.offset,'record_length_offset':LDR64.BaseDllName.offset+US64.Length.offset,'record_buffer_offset':LDR64.BaseDllName.offset+US64.Buffer.offset,'record_adjustment':0,'reference_layout_only':True,'runtime_os_build_confirmed':False}
 assert actual['record_length_offset']==0x58 and actual['record_buffer_offset']==0x60 and ctypes.sizeof(US64)==16
 return actual

def fixtures():
 cases=[]
 for L in [0,2,6,14,65534,65535]:
  T,P,D,R,U=0x100000,0x200000,0x300000,0x400000,0x500000;mem={}
  def put(a,n,v):
   for i,c in enumerate(v.to_bytes(n,'little')):mem[a+i]=c
  def get(a,n):return int.from_bytes(bytes(mem[a+i] for i in range(n)),'little')
  put(T+0x60,8,P);put(P+0x18,8,D);put(D+0x10,8,R);put(R+0x58,2,L);put(R+0x60,8,U)
  peb=get(T+0x60,8);ldr=get(peb+0x18,8);head=ldr+0x10;record=get(ldr+0x10,8);assert record!=head
  observed_L=get(record+0x58,2);observed_U=get(record+0x60,8);N=observed_L>>1
  assert observed_U==U and N==L//2 and observed_U+2*N==U+(L&~1)
  cases.append({'synthetic':True,'length_bytes':L,'N':N,'source_byte_extent':2*N})
 # Equality means empty/sentinel branch, not an LDR entry to dereference.
 head=0x300010;record=head;assert record==head;cases.append({'synthetic':True,'empty_list_returns_frontier':'0x14C3838','record_fields_read':False})
 return cases

def verify(r,p,baseline_hash):
 assert hashlib.sha256(p.b).hexdigest()==PIN and r['module_sha256']==PIN and r['schema']=='wlab-record-provenance-1'
 assert r['assumptions']==ASSUMPTIONS
 for a,h in LOCKS.items():assert p.read(a,len(bytes.fromhex(h))).hex()==h
 for section in r['byte_sections']:assert p.read(section['rva'],len(bytes.fromhex(section['bytes']))).hex()==section['bytes']
 assert {s['rva'] for s in r['byte_sections']}==set(LOCKS)
 for n in r['arithmetic_trace']:assert p.read(n['rva'],len(bytes.fromhex(n['bytes']))).hex()==n['bytes']
 assert r['word_global']=={'rva':0x20f9b98,'disk_u16':0xf92d,'runtime_invariant':False}
 assert 0x14c22ee+p.u(0x14c22ea,'<i')==0x20f9b98 and p.u(0x20f9b98,'<H')==0xf92d
 assert r['proofs']=={k:'unsat' for k in ['disk_shift_is_one','disk_N_is_half_word','even_byte_extent','all_byte_extent','source_end']}
 assert r['layout_mapping']==layouts()
 assert r['transfer']=={'U':'qword(record + 0x60)','L':'word(record + 0x58)','N_disk_scenario':'floor(L/2)','argument_path':['0x14C2450: RCX=N, R8=U','0x15B410E: RDX=U, stack argument 7=N','0x5C6ED9: stack argument 6=U, stack argument 8=N','0x68379B..0x6837EF: source range U..U+2*N'],'baseline_5c6440_rechecked':True,'baseline_report_sha256':baseline_hash}
 ce=r['noninvariant_counterexample'];assert ce['kind']=='solver witness, not runtime observation' and 0<=ce['global_word']<65536
 c=count(ce['global_word'],p);assert c!=1 and ce['effective_shift']==c and ce['record_word']==2 and ce['N']==2>>c and ce['half_word']==1
 assert r['conclusions']=={'static_reference_layout_interpretation':'loaded-module BaseDllName descriptor','actual_module_name_observed':False,'runtime_execution_observed':False,'BIOS_read_proven':False,'CPU_BIOS_send_3724_proven':False,'absence_of_hardware_send_proven':False,'runtime_contents_decoded':False,'core_6995d0_analyzed':False,'pause_deeper_generic_callee_expansion':True,'next_work':'Return to dedicated hardware-collection/message-population evidence; do not continue this generic name-buffer branch solely for 3724'}
 # Boolean flag replay of the byte-locked opaque-branch guards.
 # OR AL,0 before the first JNO clears OF; its destination is locked.
 assert 0x14c2335+2+p.u(0x14c2336,'<b')==0x14c2374
 for initial_pf in [False,True]:
  PF,OF=initial_pf,False;ip=0x14c237a;seen=set()
  while ip!=0x14c2414:
   assert ip not in seen;seen.add(ip);raw=p.read(ip,3)
   if raw[0] in [0x7b,0x7a,0x71]:
    taken={0x7b:not PF,0x7a:PF,0x71:not OF}[raw[0]];ip+=2+(struct.unpack('<b',raw[1:2])[0] if taken else 0)
   elif raw[:2]==bytes.fromhex('a8e1'):OF=False;ip+=2
   elif raw==bytes.fromhex('c0ff00'):ip+=3
   elif raw[0]==0x90:ip+=1
   else:raise AssertionError('Unexpected value-changing guard instruction')
  assert 0x14c23d4 in seen
 for CF in [False,True]:
  ip=0x15b40ac;seen=set()
  while ip!=0x15b40eb:
   assert ip not in seen;seen.add(ip);raw=p.read(ip,2)
   if raw[0] in [0x72,0x73]:
    taken=CF if raw[0]==0x72 else not CF;ip+=2+(struct.unpack('<b',raw[1:2])[0] if taken else 0)
   elif raw==bytes.fromhex('86ff'):ip+=2
   else:raise AssertionError('Unexpected wrapper guard instruction')
 return True
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--input',required=True,type=Path);ap.add_argument('--report',required=True,type=Path);ap.add_argument('--out',required=True,type=Path);a=ap.parse_args();assert a.out.resolve()!=a.input.resolve();p=PE(a.input)
 root=Path(__file__).resolve().parent.parent;bp=root/'baseline/5c6440-scenario-proof.json';br=json.loads(bp.read_text());verify_baseline(br,p,replay(p));baseline_hash=hashlib.sha256(bp.read_bytes()).hexdigest()
 r=json.loads(a.report.read_text());verify(r,p,baseline_hash)
 histogram=Counter(count(g,p) for g in range(65536));assert histogram==Counter({i:1024 for i in range(64)})
 disk_shift=count(0xf92d,p);assert disk_shift==1
 for L in range(65536):assert (L>>disk_shift)==L//2 and 2*(L>>disk_shift)==(L&0xfffe)
 fixture_cases=fixtures();tests=[]
 mutations=[('wrong_list',lambda q:q['layout_mapping'].__setitem__('PEB_LDR_DATA.InLoadOrderModuleList',0x20)),('wrong_entry_adjustment',lambda q:q['layout_mapping'].__setitem__('record_adjustment',-0x10)),('wrong_string_field',lambda q:q['layout_mapping'].__setitem__('LDR_DATA_TABLE_ENTRY.BaseDllName',0x48)),('wrong_buffer_offset',lambda q:q['layout_mapping'].__setitem__('record_buffer_offset',0x58)),('assumed_runtime_global',lambda q:q['word_global'].__setitem__('runtime_invariant',True)),('removed_length_condition',lambda q:q['assumptions'].__setitem__(2,'N always equals half length')),('wrong_N_scale',lambda q:q['transfer'].__setitem__('N_disk_scenario','L')),('wrong_U_source',lambda q:q['transfer'].__setitem__('U','qword(record + 0x68)')),('damaged_bytes',lambda q:q['byte_sections'][0].__setitem__('bytes','90')),('claimed_runtime_name',lambda q:q['conclusions'].__setitem__('actual_module_name_observed',True)),('claimed_no_hardware_send',lambda q:q['conclusions'].__setitem__('absence_of_hardware_send_proven',True)),('claimed_BIOS_send',lambda q:q['conclusions'].__setitem__('CPU_BIOS_send_3724_proven',True)),('claimed_current_OS_verified',lambda q:q['layout_mapping'].__setitem__('runtime_os_build_confirmed',True)),('damaged_baseline_link',lambda q:q['transfer'].__setitem__('baseline_report_sha256','0'*64))]
 for name,mutate in mutations:
  bad=copy.deepcopy(r);mutate(bad)
  try:verify(bad,p,baseline_hash)
  except AssertionError:tests.append({'mutation':name,'rejected':True})
  else:raise AssertionError('Accepted mutation: '+name)
 result={'manual_PE_and_byte_locks':'passed','current_arithmetic_implementation':'separate Python integers, no Z3 or Capstone required for new length formula','global_shift_domain_size':65536,'global_shift_histogram':{str(k):v for k,v in sorted(histogram.items())},'length_domain_at_disk_global':65536,'disk_shift':disk_shift,'reference_layout_derived_with_ctypes':layouts(),'synthetic_fixtures':fixture_cases,'guard_paths_checked':{'record_PF_cases':2,'wrapper_CF_cases':2},'prior_5c6440_replay_rechecked':True,'prior_replay_decoder':'shared Capstone from earlier verifier; not an independent decoder','mutation_tests':tests,'input_PE_executed':False,'runtime_structure_contents_observed':False}
 a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'all_word_globals_checked':65536,'all_lengths_at_disk_global_checked':65536,'disk_shift':disk_shift,'synthetic_fixtures':len(fixture_cases),'mutation_tests_rejected':len(tests),'baseline_transfer_rechecked':True}))
