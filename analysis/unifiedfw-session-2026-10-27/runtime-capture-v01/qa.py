"""Offline QA; never runs the selected installer or native Windows audit here."""
from pathlib import Path
import argparse,subprocess,json
p=argparse.ArgumentParser();p.add_argument('--pwsh',required=True);a=p.parse_args();r=Path(__file__).resolve().parent
v=subprocess.run([a.pwsh,'-NoLogo','-NoProfile','-File',str(r/'Test-Runtime.ps1')],capture_output=True,text=True,timeout=180)
(r/'evidence/runtime-test.log').write_text(v.stdout+'\n'+v.stderr)
if v.returncode:raise RuntimeError('runtime test failed; inspect evidence/runtime-test.log')
subprocess.run(['python',str(r.parent/'program-observer-v01/qa.py'),'--pwsh',a.pwsh],check=True)
old=r.parent/'program-observer-v01/evidence'
for n in ['candidate-regression','picker-regression','journal-regression']:(r/'evidence'/f'{n}.json').write_bytes((old/f'{n}.json').read_bytes())
(r/'evidence/observer-regression.json').write_bytes((old/'model-tests.json').read_bytes())
print(json.dumps(json.loads((r/'evidence/model-tests.json').read_text('utf-8-sig'))))
