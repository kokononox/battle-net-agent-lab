from pathlib import Path
import hashlib,json,csv,struct,copy,shutil,os
from pe_manual import PE
D=Path(__file__).resolve().parents[1]
P=PE(Path(os.environ.get('INPUT_DIR','/data/wlab-inputs'))/'Wow.exe')
plan=json.loads((D/'reports/plan.json').read_text())
assert hashlib.sha256(P.b).hexdigest()==plan['sha256']
assert P.base==plan['image_base'] and P.dirs[14]==(0,0)
out=D/'reports/output';out.mkdir(exist_ok=True)
if (D/'work/run-01/output').exists():
 for f in (D/'work/run-01/output').iterdir():shutil.copy2(f,out/f.name)
 log=(D/'work/run-01/headless.log').read_text()
 for a,b in [(str(D),'<REVIEW_DIR>'),('/data/wlab-inputs','<INPUT_DIR>'),('/data/re-tools','<TOOLS_DIR>'),('/root','<HOME>')]:log=log.replace(a,b)
 (D/'reports/headless.normalized.log').write_text(log)
rows=list(csv.DictReader((out/'results.tsv').open(),delimiter='\t'));listing=list(csv.DictReader((out/'listing.tsv').open(),delimiter='\t'))
cs={r['role']:(out/(r['role']+'.raw.c')).read_text() for r in rows}
pr,sz=P.dirs[3];bounds=dict(struct.unpack('<III',P.read(pr+i,12))[:2] for i in range(0,sz,12))
def verify(pl,rs,ls,c):
 assert len(rs)==len(pl['targets'])==4
 for t,r in zip(pl['targets'],rs):
  role=t['role'];assert r['role']==role
  start,end=t['rva'],t['end'];assert int(r['rva'],16)==start and int(r['end'],16)==end
  if t['slot_rva'] is not None:
   assert P.u(t['slot_rva'],'<Q')-P.base==start and bounds[start]==end
  raw=P.read(start,end-start);sha=hashlib.sha256(raw).hexdigest()
  assert sha==t['range_sha256']==r['sha256_before']==r['sha256_after']
  items=[x for x in ls if x['role']==role];assert len(items)==int(r['listing_instructions'])
  cursor=start
  for x in items:
   a=int(x['rva'],16);b=bytes.fromhex(x['bytes']);assert a==cursor and start<=a and a+len(b)<=end
   assert P.read(a,len(b))==b;cursor+=len(b)
  assert (r['entry_instruction_defined']=='true')==bool(items)
  assert (r['c_present']=='true')==bool(c[role])
  assert (r['halt_baddata_marker']=='true')==('halt_baddata' in c[role])
 assert all(r['decompile_api_completed']=='true' for r in rs)
 assert all('halt_baddata' in c[r['role']] for r in rs[:3])
 assert 'halt_baddata' not in c[rs[3]['role']] and int(rs[3]['listing_instructions'])>0
 return True
verify(plan,rows,listing,cs)
cases=[]
for name in ['wrong_slot','changed_hash','wrong_range','listing_byte_mutation','hide_bad_data_marker','drop_positive_control']:
 pl,rs,ls,c=copy.deepcopy((plan,rows,listing,cs))
 if name=='wrong_slot':pl['targets'][0]['slot_rva']+=8
 elif name=='changed_hash':rs[0]['sha256_after']='0'*64
 elif name=='wrong_range':rs[1]['end']='1b111ff'
 elif name=='listing_byte_mutation':ls[0]['bytes']='00'
 elif name=='hide_bad_data_marker':rs[0]['halt_baddata_marker']='false'
 elif name=='drop_positive_control':rs.pop()
 try:verify(pl,rs,ls,c)
 except AssertionError:cases.append({'case':name,'rejected':True})
 else:raise AssertionError(name)
summary={'input_sha256_after_analysis':hashlib.sha256(P.b).hexdigest(),'input_file_bytes':len(P.b),'amd64_pe32plus':True,'clr_directory_absent':True,'range_and_listing_checks_passed':True,'negative_tests':cases,'decompiler_api_completed':4,'target_requests':3,'targets_with_bad_data_C':3,'targets_accepted_as_recovered':0,'positive_control_without_bad_data':True,'prefix_bytes':{t['role']:sum(len(bytes.fromhex(x['bytes'])) for x in listing if x['role']==t['role']) for t in plan['targets']},'caveat':'Accept/reject is a conservative experiment gate, not proof of whole-function semantics or impossibility of future recovery.'}
(D/'reports/validation.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
