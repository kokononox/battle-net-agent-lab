"""Prepare pinned ranges and audit prior recorded targets. Never executes the input PE."""
from pathlib import Path
import json,hashlib,struct,re,os
from pe_manual import PE
D=Path(__file__).resolve().parents[1];p=PE(Path(os.environ.get('INPUT_DIR','/data/wlab-inputs'))/'Wow.exe');PIN='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a';assert hashlib.sha256(p.b).hexdigest()==PIN
sources=[('prior-targeted.java','044f2fb77cd0003629f8e8c0e91561308b4b9e26'),('prior-pilot-summary.txt','65bc43d0713a8b693d1bf83c12b295605ea91d63'),('prior-loader-targeted.tsv','1cd8ad33d023951262085ef4f9cc52c69f1a81f9')]
source_rows=json.loads((D/'reports/plan.json').read_text())['prior_sources']
for name,sha in sources:
 b=(D/'reference'/name).read_bytes()
 actual=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
 assert actual==sha
 assert next(r for r in source_rows if r['name']==name)['sha256']==hashlib.sha256(b).hexdigest()
script=(D/'reference/prior-targeted.java').read_text();oldpairs=[(int(a,16),int(b,16)) for a,b in re.findall(r'\{0x([0-9a-f]+)L,0x([0-9a-f]+)L\}',script)];assert len(oldpairs)==7
old_exe=oldpairs[5:];pilot=[int(x,16)-p.base for x in re.findall(r'^Sample ([0-9a-f]+) ',(D/'reference/prior-pilot-summary.txt').read_text(),re.M)];assert len(pilot)==12
pr,ps=p.dirs[3];bounds=dict(struct.unpack('<III',p.read(pr+i,12))[:2] for i in range(0,ps,12));rows=[]
for role,start,slot in [('merge_candidate',0x1b14120,0x47cf800),('creator_candidate',0x1b11190,0x47cf810),('parse_fallback_candidate',0x33068c0,0x47cec38),('positive_control_entry_stub',0x1da9b0,None)]:
 end=bounds[start] if slot else 0x1da9c9
 if slot:assert p.u(slot,'<Q')-p.base==start
 raw=p.read(start,end-start);rows.append({'role':role,'rva':start,'end':end,'slot_rva':slot,'range_sha256':hashlib.sha256(raw).hexdigest(),'bytes_hex':raw.hex(),'previous_targeted_entry_in_audited_script':any(a==start for a,b in old_exe),'previous_pilot_sample_entry':start in pilot})
plan={'sha256':PIN,'image_base':p.base,'targets':rows,'prior_sources':source_rows,'prior_coverage':{'targeted_loader_ranges':oldpairs[:5],'targeted_exe_ranges':old_exe,'pilot_exe_sample_rvas':pilot,'scope_caveat':'These audited script/output lists, not every historical Ghidra project or all autoanalysis-discovered functions.'},'experiment':{'no_global_autoanalysis':True,'no_patch_or_cfg_override':True,'decompile_timeout_seconds_per_function':30,'heap':'1800M','max_cpu':2,'requests':4,'native_input_execution':False}}
(D/'reports/plan.json').write_text(json.dumps(plan,indent=2)+'\n');(D/'reference/targets.tsv').write_text('role\trva\tend\tsha256\n'+''.join(f"{r['role']}\t{r['rva']:x}\t{r['end']:x}\t{r['range_sha256']}\n" for r in rows));print('Prepared',len(rows),'ranges. New target coverage:',[(r['role'],r['previous_targeted_entry_in_audited_script'],r['previous_pilot_sample_entry']) for r in rows])
