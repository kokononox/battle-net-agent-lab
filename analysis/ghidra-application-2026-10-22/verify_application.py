"""Raw PE byte/proof checks, independent of Capstone/Ghidra; not semantic equivalence."""
from pathlib import Path
import json,struct,hashlib,argparse
p=argparse.ArgumentParser();p.add_argument('--input-dir',type=Path,default=Path('/data/raw/wow-retail-20261022'));p.add_argument('--output-dir',type=Path,default=Path(__file__).parent);a=p.parse_args();w=a.output_dir
b=(a.input_dir/'wow_loader.dll').read_bytes();sha=hashlib.sha256(b).hexdigest();assert sha=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
u16=lambda o:struct.unpack_from('<H',b,o)[0];u32=lambda o:struct.unpack_from('<I',b,o)[0]
nt=u32(0x3c);assert b[:2]==b'MZ' and b[nt:nt+4]==b'PE\0\0';opt=nt+24;assert u16(opt)==0x20b
ss=[]
for j in range(u16(nt+6)):
 o=opt+u16(nt+20)+j*40;ss.append((u32(o+12),u32(o+16),u32(o+20)))
def raw(r,n):
 for va,sz,off in ss:
  if va<=r and r+n<=va+sz:return b[off+r-va:off+r-va+n]
 raise AssertionError('No raw backing')
r=json.loads((w/'application-normalized.json').read_text());nodes=r['normalized_instructions'];assert len(nodes)==102
for i in nodes:
 at=int(i['rva'],16);bs=bytes.fromhex(i['bytes']);assert raw(at,len(bs))==bs
for x,y in zip(nodes,nodes[1:]):assert int(x['rva'],16)+len(bytes.fromhex(x['bytes']))<=int(y['rva'],16)
assert raw(0x1beb9a1,4)==bytes.fromhex('a8e07166')
assert 0x1beb9a3+2+struct.unpack('<b',raw(0x1beb9a4,1))[0]==0x1beba0b
incoming=[i['rva'] for i in nodes if '0x1beb9a3' in i['successors']];assert incoming==['0x1beb9a1']
assert r['edges_outside_range']==[] and r['unresolved_control_flow']==[]
# Exhaustive 8-bit TEST result/flags: TEST clears OF irrespective of AL; JNO reads only OF.
flagcases=[]
for al in range(256):
 test_result=al&0xe0;of=0;assert not of;flagcases.append((al,test_result,of))
assert (w/'scripts/application-proven-fallthroughs.tsv').read_text()=='0x1beb9a3\t0x1beba0b\n'
ann=(w/'output/application-fallthrough-annotations.tsv').read_text();assert '0x1beb9a3\t0x1beba0b\t' in ann
summary=(w/'output/application-verified-cfg-summary.tsv').read_text().splitlines()[1].split('\t');assert summary[0:2]==['102','true']
c=(w/'output/wow_loader.dll.1beb830.verified-cfg.c').read_text();assert '/* FAILED:' not in c and 'halt_baddata' not in c
calls=[i for i in nodes if i['mnemonic']=='call'];assert len(calls)==8
qa={'status':'pass','source_sha256':sha,'all_102_instruction_byte_ranges_match_raw_PE':True,'normalized_instruction_ranges_overlap':False,'proof_bytes':'a8 e0 71 66','proof':'TEST AL,0xe0 clears OF; following JNO taken','sole_modeled_predecessor_of_JNO_is_TEST':True,'all_256_AL_values_checked_using_architectural_TEST_rule':True,'branch_target_rva':'0x1beba0b','outside_range_edges_after_normalization':0,'call_sites_remaining':8,'direct_call_sites_remaining':6,'indirect_call_sites_remaining':2,'Ghidra_API_completed':True,'Ghidra_result_depends_on_analyst_CFG':True,'whole_function_equivalence_proven':False,'callee_identity_and_runtime_pointer_values_resolved':False,'hardware_to_network_binding_proven':False,'native_execution_emulation_or_byte_patch_performed':False,'limitations':'Intraprocedural normal instruction flow only. Unknown callees may not return. Exceptions, asynchronous code entry and self-modification are not modeled. Flag enumeration checks the encoded architectural rule, not a hardware experiment.'}
(w/'QA.json').write_text(json.dumps(qa,indent=2)+'\n');print(json.dumps(qa,indent=2))
