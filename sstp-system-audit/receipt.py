import json,os,pathlib,hashlib,sys
r=pathlib.Path(__file__).resolve().parent;tmp=pathlib.Path(os.environ['RUNNER_TEMP']);d={'schema':'sstp-system-audit-build-1','source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'runner_os':os.environ['RUNNER_OS_LABEL'],'sha256':{},'user_device_tested':False,'complete_security_audit':False}
for key in ['model','native']:
 p=tmp/('audit-'+key+'.json');d[key]=json.loads(p.read_text(encoding='utf-8-sig')) if p.is_file() and p.stat().st_size<6000 else None;d[key+'_outcome']=os.environ[key.upper()+'_OUTCOME']
for p in sorted(r.iterdir()):
 if p.suffix in ['.ps1','.cmd'] or p.name=='receipt.py':d['sha256'][p.name]=hashlib.sha256(p.read_bytes()).hexdigest()
m=d['model'];n=d['native'];ok=isinstance(m,dict) and m.get('passed') is True and m.get('checks')==20 and isinstance(n,dict) and n.get('passed') is True and n.get('checks')==22
if ok:ok=all(n.get(k) is True for k in ['firewall_strict_equal','hosts_equal','ipv6_registry_equal','overlay_directory_presence_equal','launcher_admin_path_tested']) and n.get('launcher_nonadmin_uac_tested') is False and all(d[k+'_outcome']=='success' for k in ['model','native'])
d['passed']=bool(ok);(r/'build-receipt.json').write_text(json.dumps(d,indent=2)+'\n');print(json.dumps({'passed':bool(ok),'model':m,'native':n}));sys.exit(0 if ok else 1)
