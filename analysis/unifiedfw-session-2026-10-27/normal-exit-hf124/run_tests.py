import pathlib,subprocess,json
r=pathlib.Path('/data/ufd-normal-exit-hf124');c=r/'candidate';logs=r/'ps-logs';logs.mkdir(exist_ok=True);rows=[]
for f in sorted((c/'tests').glob('Test-*.ps1')):
 try:
  p=subprocess.run(['/data/ufd-isolation-hf1/pwsh/pwsh','-NoLogo','-NoProfile','-File',str(f),'-Root',str(c)],cwd=c,capture_output=True,text=True,timeout=120)
  (logs/(f.stem+'.log')).write_text(p.stdout+'\n'+p.stderr)
  rows.append(dict(suite=f.name,exit_code=p.returncode,passed=p.returncode==0))
 except Exception as e:rows.append(dict(suite=f.name,passed=False,error=str(e)))
(r/'ps-suite-results.json').write_text(json.dumps(rows,indent=2))
print('TOTAL',len(rows),'PASS',sum(x['passed'] for x in rows));print('FAILURES',json.dumps([x for x in rows if not x['passed']]))
