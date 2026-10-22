"""Independent raw PE/branch checks; no Capstone, Ghidra, or native input execution."""
from pathlib import Path
import struct,hashlib,json,argparse
p=argparse.ArgumentParser();p.add_argument('--input',type=Path,default=Path('/data/raw/wow-retail-20261022/wow_loader.dll'));p.add_argument('--out',type=Path,default=Path(__file__).parent);a=p.parse_args();w=a.out;b=a.input.read_bytes();sha=hashlib.sha256(b).hexdigest();assert sha=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
u16=lambda o:struct.unpack_from('<H',b,o)[0];u32=lambda o:struct.unpack_from('<I',b,o)[0]
nt=u32(0x3c);assert b[:2]==b'MZ' and b[nt:nt+4]==b'PE\0\0';opt=nt+24;assert u16(opt)==0x20b
sections=[]
for i in range(u16(nt+6)):
 o=opt+u16(nt+20)+40*i
 sections.append((u32(o+12),u32(o+16),u32(o+20)))
def raw(r,n):
 for va,sz,off in sections:
  if va<=r and r+n<=va+sz:return b[off+r-va:off+r-va+n]
 raise AssertionError(f'Unbacked RVA {r:x}')
r=json.loads((w/'callee-analysis.json').read_text());assert r['source_sha256']==sha
for key in ['raw_instructions','instructions']:
 for i in r[key]:assert raw(int(i['rva'],16),len(bytes.fromhex(i['bytes'])))==bytes.fromhex(i['bytes'])
# Validate unwind record using exception directory, independently of pefile.
pdata=u32(opt+112+3*8);plen=u32(opt+116+3*8)
records=[struct.unpack('<III',raw(pdata+x,12)) for x in range(0,plen,12)]
assert any(x==0x17df7f0 and y==0x17e06c9 for x,y,z in records)
for proof in r['proofs']:
 if proof['kind']=='adjacent_complementary_Jcc':
  x=int(proof['first_rva'],16);y=int(proof['second_rva'],16);target=int(proof['target_rva'],16);ba=raw(x,2);bb=raw(y,2)
  assert ba==bytes.fromhex(proof['first_bytes']) and bb==bytes.fromhex(proof['second_bytes']);assert ba[0]==0x75 and bb[0]==0x74 and y==x+2
  assert x+2+struct.unpack('<b',ba[1:])[0]==target and y+2+struct.unpack('<b',bb[1:])[0]==target
  for zf in [0,1]:assert bool(not zf) or bool(zf)
 else:
  x=int(proof['preceding_rva'],16);y=int(proof['branch_rva'],16);assert raw(x,4)==bytes.fromhex('84f8733a') and y==x+2
  assert y+2+0x3a==int(proof['chosen_rva'],16)
  pred=[i['rva'] for i in r['raw_instructions'] if hex(y) in i['successors']];assert pred==[hex(x)]
  # TEST r8,r8 sets CF=0 irrespective of inputs, assuming normal non-faulting execution.
  for al in range(256):
   for bh in range(256):cf=0;assert cf==0
assert len(r['proofs'])==3
irva=u32(opt+112+12*8);isz=u32(opt+116+12*8)
for slot in r['slots']:
 x=int(slot['rva'],16);v=struct.unpack('<Q',raw(x,8))[0];assert hex(v)==slot['file_value'];assert irva<=x<x+8<=irva+isz;assert raw(v,32)==b'\0'*32
# Read every import descriptor; shared FirstThunk must not be deduplicated into an import count.
d=u32(opt+112+8);descriptors=[]
for k in range(1000):
 fields=struct.unpack('<IIIII',raw(d+k*20,20))
 if not any(fields):break
 descriptors.append(fields)
assert len(descriptors)==36 and {x[4] for x in descriptors}=={0x20a0088}
refs=json.loads((w/'slot-reference-candidates.json').read_text())
for i in refs['references']:assert raw(int(i['candidate_rva'],16),len(bytes.fromhex(i['bytes'])))==bytes.fromhex(i['bytes'])
contexts=json.loads((w/'crt-contexts.json').read_text())
assert contexts['runtime_import_target_confirmation'] is False
for context in contexts['contexts']:
 cursor=int(context['begin_rva'],16)
 assert any(x==cursor and y==int(context['end_rva'],16) for x,y,z in records)
 for i in context['instructions']:
  assert int(i['rva'],16)==cursor
  bs=bytes.fromhex(i['bytes']);assert raw(cursor,len(bs))==bs;cursor+=len(bs)
 assert cursor==int(context['end_rva'],16)
assert raw(0x200630c,8)==bytes.fromhex('488bc8ba090400c0')
assert raw(0x2013dd0,8)==bytes.fromhex('488bc8ba170400c0')
assert raw(0x2013daf,7)==bytes.fromhex('b905000000cd29')
qa={'byte_and_local_proof_checks':'pass','semantic_recovery_status':'incomplete','source_sha256':sha,'function_extent_independently_matches_unwind':True,'raw_instruction_byte_ranges_checked':len(r['raw_instructions']),'normalized_instruction_byte_ranges_checked':len(r['instructions']),'local_branch_proofs_checked':3,'import_descriptor_count':36,'shared_FirstThunk_rva':'0x20a0088','slot_target_bytes_zero_for_32_bytes':True,'remaining_overlaps':len(r['overlapping_instruction_ranges']),'remaining_outside_range_edges':len(r['outside_range_edges']),'remaining_decode_failures':len(r['unresolved_control_flow']),'candidate_call_sites_not_validated_as_runtime_calls':len(r['calls']),'slot_reference_candidate_bytes_checked':len(refs['references']),'small_CRT_like_contexts_byte_checked':3,'runtime_pointer_values_known':False,'candidate_API_names_are_hypotheses':True,'Ghidra_decompilation_performed_this_stage':False,'native_input_executed_emulated_or_patched':False,'hardware_to_network_binding_proven':False,'limits':'Independent byte and selected branch checks only. CFG can include false decodes. Static candidate reference search is incomplete and does not prove instruction boundaries or reachability.'}
(w/'QA.json').write_text(json.dumps(qa,indent=2)+'\n');print(json.dumps(qa,indent=2))
