import hashlib, json, os, pathlib, sys
root=pathlib.Path(__file__).resolve().parent
base=pathlib.Path(os.environ['RUNNER_TEMP'])
pure=None;native=None
for name in ['overlay-ranges','overlay-native']:
 p=base/(name+'.json')
 if p.is_file() and p.stat().st_size<12000:
  x=json.loads(p.read_text(encoding='utf-8-sig'))
  if name=='overlay-ranges':pure=x
  else:native=x
r={'schema':'sstp-overlay-build-1','source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'pure_outcome':os.environ.get('PURE_OUTCOME'),'native_outcome':os.environ.get('NATIVE_OUTCOME'),'pure':pure,'native':native,'sha256':{},'ready_for_production':False}
for p in sorted(root.iterdir()):
 if p.suffix in ('.ps1','.cs','.cmd') or p.name=='receipt.py':r['sha256'][p.name]=hashlib.sha256(p.read_bytes()).hexdigest()
valid=isinstance(pure,dict) and pure.get('schema')=='sstp-overlay-ranges-1' and pure.get('passed') is True and pure.get('checks')==247
valid=valid and isinstance(native,dict) and native.get('schema')=='sstp-overlay-native-1' and native.get('passed') is True
if valid:
 for field in ['checks','worker_exits','fault_recoveries','probe_pairs','remaining_objects','foreign_display_changes']:
  valid=valid and type(native.get(field)) is int
 valid=valid and native.get('source_commit')==os.environ['GITHUB_SHA'] and native.get('run_id')==os.environ['GITHUB_RUN_ID']
 valid=valid and native.get('remaining_objects')==0 and native.get('unrelated_policy_equal') is True and native.get('fault_recoveries')==2
 for field in ['ipv6_packet_tested','remote_access_packet_tested','real_sstp_tested','disconnect_tested','reboot_tested','user_device_tested','ready_for_production']:valid=valid and native.get(field) is False
valid=bool(valid and r['pure_outcome']=='success' and r['native_outcome']=='success')
r['passed']=valid
(root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'passed':valid,'native_receipt':native is not None,'pure_receipt':pure is not None}))
sys.exit(0 if valid else 1)
