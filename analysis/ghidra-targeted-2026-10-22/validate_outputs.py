"""Checks byte/provenance/artifact consistency, not decompiler semantic correctness."""
import argparse,json,hashlib,csv,struct,itertools
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--input-dir',type=Path,required=True);p.add_argument('--work-dir',type=Path,default=Path(__file__).resolve().parent);a=p.parse_args();r=a.work_dir
provenance=json.loads((r/'provenance.json').read_text())
for f in provenance['files']:
 b=(a.input_dir/f['name']).read_bytes();assert len(b)==f['bytes'] and hashlib.sha256(b).hexdigest()==f['sha256']
b=(a.input_dir/'wow_loader.dll').read_bytes();u16=lambda o:struct.unpack_from('<H',b,o)[0];u32=lambda o:struct.unpack_from('<I',b,o)[0];nt=u32(0x3c);opt=nt+24;sections=[]
for i in range(u16(nt+6)):
 o=opt+u16(nt+20)+i*40;sections.append((u32(o+12),u32(o+16),u32(o+20)))
def raw(at,n):
 for va,size,off in sections:
  if va<=at and at+n<=va+size:return b[off+at-va:off+at-va+n]
 raise AssertionError('unbacked RVA')
count=0
for line in (r/'scripts/export-verified-instructions.tsv').read_text().splitlines():
 at,bs=line.split('\t');bs=bytes.fromhex(bs);assert raw(int(at,16),len(bs))==bs;count+=1
assert count==289
proof=json.loads((r/'scripts/export-normalization-proofs.json').read_text());cond={0x7e:lambda z,s,o:z or s!=o,0x7f:lambda z,s,o:not z and s==o,0x7d:lambda z,s,o:s==o,0x7c:lambda z,s,o:s!=o}
expected_annotations=[]
for q in proof['rewrites']:
 x=int(q['first_rva'],16);y=int(q['second_rva'],16);target=int(q['target_rva'],16);p1=raw(x,2);p2=raw(y,2)
 assert x+2+struct.unpack('b',p1[1:])[0]==target==y+2+struct.unpack('b',p2[1:])[0]
 assert (b'' if x+2==y else raw(x+2,y-x-2)) in [b'',bytes.fromhex('c0f200')]
 for z,s,o in itertools.product([False,True],repeat=3):assert bool(cond[p1[0]](z,s,o))!=bool(cond[p2[0]](z,s,o))
 expected_annotations.append((q['first_rva'],q['target_rva']))
provided=[tuple(s.split('\t')) for s in (r/'scripts/export-proven-fallthroughs.tsv').read_text().splitlines()]
assert provided==expected_annotations
actual=list(csv.DictReader((r/'output/export-fallthrough-annotations.tsv').read_text().splitlines(),delimiter='\t'));assert [(s['rva'],s['new_fallthrough_rva']) for s in actual]==expected_annotations
rows=[]
for path in (r/'output').glob('*.targeted.tsv'):rows.extend(csv.DictReader(path.read_text().splitlines(),delimiter='\t'))
assert len(rows)==7 and sum(q['decompile_api_completed']=='true' for q in rows)==5
normalized=list(csv.DictReader((r/'output/export-verified-cfg-summary.tsv').read_text().splitlines(),delimiter='\t'))[0];assert normalized['decompile_api_completed']=='true' and normalized['verified_instruction_count']=='289'
code=(r/'output/wow_loader.dll.22eff0.verified-cfg.c').read_text();assert 'halt_baddata' not in code and 'while' in code
cookie=(r/'output/wow_loader.dll.2006670.raw.c').read_text();assert '0x2b992ddfa232' in cookie and '0xffffffffffff' in cookie and '_DAT_1820d0200 = ~_DAT_1820d01c0' in cookie
entry=(r/'output/Wow.exe.1da9b0.raw.c').read_text();assert '144ad5f38' in entry and 'return 0' in entry
qa={'status':'pass','all_three_input_file_hashes_match_pilot_and_prior_work':True,'verified_normalized_instruction_byte_ranges':count,'branch_proofs_rechecked':len(expected_annotations),'raw_decompile_API_completed':5,'raw_selected_targets':7,'normalized_export_API_completed':True,'proof_backed_annotations_match_artifacts':True,'normalization_independent_of_Ghidra':True,'normalized_decompilation_independent_of_supplied_CFG':False,'cookie_and_exe_stub_marker_sanity_checks':'pass; not a full semantic proof','original_game_binaries_executed_emulated_or_patched':False,'whole_function_or_program_equivalence_proven':False,'telemetry_destination_proven':False}
(r/'QA.json').write_text(json.dumps(qa,indent=2)+'\n');print(json.dumps(qa,indent=2))
