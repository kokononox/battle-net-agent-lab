import hashlib,json,os,pathlib,sys
root=pathlib.Path(__file__).resolve().parent;base=pathlib.Path(os.environ['RUNNER_TEMP'])
r={'schema':'sstp-portable-prefix-build-1','runner_os':os.environ['RUNNER_OS_LABEL'],'source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'ready_for_production':False,'sha256':{}}
for key,name in [('pure','ranges'),('cidrs','cidrs'),('native','native'),('recovery','recovery')]:
 p=base/('overlay-'+name+'.json');r[key]=json.loads(p.read_text(encoding='utf-8-sig')) if p.is_file() and p.stat().st_size<12000 else None
for key in ['pure','native','recovery','ui']:r[key+'_outcome']=os.environ.get(key.upper()+'_OUTCOME')
for p in sorted(root.iterdir()):
 if p.suffix in ('.ps1','.cmd','.cs') or p.name=='receipt.py':r['sha256'][p.name]=hashlib.sha256(p.read_bytes()).hexdigest()
p=r['pure'];c=r['cidrs'];n=r['native'];v=r['recovery']
ok=all(r[k+'_outcome']=='success' for k in ['pure','native','recovery','ui'])
ok=ok and isinstance(p,dict) and p.get('passed') is True and p.get('checks')==257
ok=ok and isinstance(c,dict) and c.get('passed') is True and c.get('checks')==30
ok=ok and isinstance(n,dict) and n.get('passed') is True and n.get('checks')==40 and n.get('worker_exits')==12 and n.get('probe_pairs')==6 and n.get('fault_recoveries')==2 and n.get('remaining_objects')==0 and n.get('unrelated_policy_equal') is True and n.get('foreign_display_changes')==0
ok=ok and isinstance(v,dict) and v.get('passed') is True and v.get('sets')==6 and v.get('cleaned_sets')==6 and v.get('fresh_process_recoveries')==2 and v.get('remaining_objects')==0 and v.get('unrelated_policy_equal') is True and v.get('foreign_display_changes')==0 and v.get('rejected_existing_rule') is True and v.get('rejected_owned_drift') is True
if ok:
 ok=all(n.get(k) is False for k in ['ipv6_packet_tested','remote_access_packet_tested','real_sstp_tested','disconnect_tested','reboot_tested','user_device_tested','ready_for_production']) and v.get('user_device_tested') is False
 ok=ok and n.get('source_commit')==r['source_commit'] and n.get('run_id')==r['run_id']
r['passed']=bool(ok);(root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'passed':r['passed'],'outcomes':{k:r[k+'_outcome'] for k in ['pure','native','recovery','ui']},'recovery':v}))
sys.exit(0 if ok else 1)
