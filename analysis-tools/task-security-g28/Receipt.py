import json,hashlib,base64,sys,os
from pathlib import Path
p=Path(sys.argv[1]);d=json.loads(p.read_text(encoding='utf-8-sig'))
assert d['schema']=='task_security_g28_v1' and d['source_commit']==os.environ['GITHUB_SHA'] and d['run_id']==os.environ['GITHUB_RUN_ID'] and d['system_identity'] is True
assert all(d[k] is False for k in ['installer_executed','firewall_changed','target_tasks_modified','automatic_exemptions_added','mutation_actor_proven'])
assert len(d['samples'])==2 and all(len(s['tasks'])==4 for s in d['samples'])
raw=json.dumps(d,sort_keys=True,separators=(',',':')).encode();assert len(raw)<=65536
p.write_bytes(raw);packed=base64.b64encode(raw).decode();parts=[packed[i:i+600] for i in range(0,len(packed),600)]
print('G28_MANIFEST '+json.dumps({'parts':len(parts),'raw_bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}),flush=True)
for i,x in enumerate(parts,1):print(f'G28_PART {i}/{len(parts)} {x}',flush=True)
