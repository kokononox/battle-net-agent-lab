import os,pathlib,hashlib,json,sys
p=pathlib.Path(__file__).resolve().parent
n=pathlib.Path(os.environ['RUNNER_TEMP'])/'startup.json'
r=None
if n.is_file() and n.stat().st_size<12000:r=json.loads(n.read_text(encoding='utf-8-sig'))
valid=bool(r and r.get('schema')=='sstp-visible-startup-test-1' and r.get('passed') is True and r.get('unrelated_policy_equal') is True and r.get('policy_code_changed') is False and os.environ.get('TEST_OUTCOME')=='success')
if valid:
 for k in ['spaced_unicode_path_tested','ui_smoke_passed','missing_dependency_reported','syntax_error_reported','module_error_reported']:valid=valid and r.get(k) is True
 valid=valid and r.get('uac_nonadmin_path_tested') is False and r.get('user_device_tested') is False and type(r.get('checks')) is int
files={x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in p.iterdir() if x.suffix in ('.ps1','.cmd') or x.name in ('receipt.py','base-policy-sha256.json')}
receipt={'schema':'sstp-startup-build-1','source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'passed':bool(valid),'test':r,'sha256':files,'uac_nonadmin_path_tested':False,'user_device_tested':False}
(p/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({'passed':bool(valid),'test_receipt_available':r is not None}))
sys.exit(0 if valid else 1)
