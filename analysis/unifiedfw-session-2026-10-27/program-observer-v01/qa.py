"""Offline QA only; no Windows native qualification or target execution."""
from pathlib import Path
import subprocess, json, tempfile, argparse
p=argparse.ArgumentParser();p.add_argument('--pwsh',required=True);a=p.parse_args()
r=Path(__file__).resolve().parent;base=r.parent;ev=r/'evidence';ev.mkdir(exist_ok=True)
def run(name,source):
 with tempfile.TemporaryDirectory(prefix='ufw-qa-') as temp:
  script=Path(temp)/'test.ps1';script.write_text(source)
  v=subprocess.run([a.pwsh,'-NoLogo','-NoProfile','-File',str(script)],capture_output=True,text=True,timeout=180)
  (ev/(name+'.log')).write_text(v.stdout+'\n'+v.stderr)
  if v.returncode:raise RuntimeError(name+' failed; inspect evidence log')
# Tests have historical build paths; relocate in temporary harnesses, never alter prior milestones.
cases=[('candidate-regression',base/'program-candidate-v01/Test-ProgramCandidate.ps1','/data/ufw-program-candidate-v01',base/'program-candidate-v01'),('picker-regression',base/'program-review-v011/Test-FilePickerReview.ps1','/data/ufw-program-review-v011',base/'program-review-v011'),('journal-regression',base/'session-journal-v01/tests/Test-SessionJournal.ps1','/data/ufw-session-journal-v01',base/'session-journal-v01')]
for name,src,old,new in cases:
 s=src.read_text().replace(old,str(new))
 s=s.replace(str(new/'evidence/model-tests.json'),str(ev/(name+'.json')))
 s=s.replace("(Join-Path $Root 'evidence/model-tests.json')","'"+str(ev/(name+'.json'))+"'")
 s=s.replace('/data/ufw-program-review-v01',str(base/'program-review-v01'))
 # Some journal fixtures refer to historical runner sources outside the journal root.
 s=s.replace('/data/ufw-normal-exit-runner-v01',str(base/'normal-exit-runner-v01'))
 run(name,s)
 print(name,json.loads((ev/(name+'.json')).read_text('utf-8-sig'))['assertions'])
v=subprocess.run([a.pwsh,'-NoLogo','-NoProfile','-File',str(r/'Test-Observer.ps1')],capture_output=True,text=True,timeout=180)
(ev/'observer-test.log').write_text(v.stdout+'\n'+v.stderr)
if v.returncode:raise RuntimeError('observer suite failed')
print('observer',json.loads((ev/'model-tests.json').read_text('utf-8-sig'))['assertions'])
