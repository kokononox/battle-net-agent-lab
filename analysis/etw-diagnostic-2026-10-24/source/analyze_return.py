"""Read the returned 0.1/0.1.1 result as data; no raw module paths published."""
from pathlib import Path
import json,zipfile,hashlib,sys
p=Path(sys.argv[1]);out=Path(sys.argv[2])
with zipfile.ZipFile(p) as z:
 names=z.namelist();s=json.loads(z.read('STATUS.json').decode('utf-8-sig'));text=z.read('start.txt').decode('utf-8-sig');check=z.read('profile-check.txt').decode('utf-8-sig')
 assert s['start_succeeded'] is False and s['control_success'] is False
 assert s['trace_saved'] is False and not any(n.lower().endswith('.etl') for n in names)
 assert '0xc558300c' in text.lower() and 'The event provider was not enabled.' in text
 assert 'WLabControl' in check
 r=dict(input_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),status=s,profile_listed_by_target_wpr=True,provider_enable_error='0xc558300c',etl_present=False,control_json_present='control.json' in names,root_cause_known=False,failed_provider_identified=False,meaning='Failure before loopback execution. It says nothing about game stacks, encryption, hardware transmission or anti-cheat.')
 out.write_text(json.dumps(r,indent=2)+'\n')
 print('Independently checked status flags, WPR error text and absent ETL/control result.')
