import json,os,pathlib,hashlib,sys
r=pathlib.Path(__file__).resolve().parent;p=pathlib.Path(os.environ['RUNNER_TEMP'])/'diagnostic-test.json'
t=json.loads(p.read_text(encoding='utf-8-sig')) if p.is_file() and p.stat().st_size<3000 else None
v={'schema':'sstp-resume-diagnostic-build-1','source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'test':t,'outcome':os.environ['TEST_OUTCOME'],'sha256':{x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in sorted(r.iterdir()) if x.suffix=='.ps1' or x.name=='receipt.py'},'native_resume_rerun_in_ci':False,'user_device_tested':False}
v['passed']=isinstance(t,dict) and t.get('passed') is True and t.get('checks')==14 and t.get('network_changed') is False and v['outcome']=='success'
(r/'build-receipt.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps({'passed':v['passed'],'checks':t.get('checks') if t else None}));sys.exit(0 if v['passed'] else 1)
