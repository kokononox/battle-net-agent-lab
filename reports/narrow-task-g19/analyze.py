import json,pathlib,hashlib,csv,io
P=pathlib.Path(__file__).resolve().parent
rows=[]; evidence=[]
for attempt,run,scenarios in [('g19','40177205940',['no_setup','real_setup']),('g19a','40177616830',['no_setup','real_setup']),('g19b','40177877397',['real_setup'])]:
 for scenario in scenarios:
  name=f'{attempt}-{scenario}'; src=pathlib.Path('/data/raw')/('bnet-narrow-'+attempt)/(scenario+'.json'); raw=src.read_bytes();v=json.loads(raw);m=json.loads(src.with_name(scenario+'-manifest.json').read_text());assert hashlib.sha256(raw).hexdigest()==m['sha256'] and len(raw)==m['raw_bytes'];assert v['run_id']==run and v['scenario']==scenario
  initial=attempt=='g19'; c=v.get('classification') or {};d=v.get('driver') or {};r=v.get('recovery') or {};b=v.get('bits') or {}
  if initial:
   # Known old reporter defect: missing after inventory was represented as removals.
   # Publish only failure projection, never bogus differences as observations.
   out={k:v.get(k) for k in ['schema','run_id','source_commit','scenario','status','driver','system_baseline','classifier_unit_tests','classifier_live_tests','recovery_gate_tests','svc_trust']};out['excluded_fields_reason']='Initial reporter lacked after snapshot: registration differences/counts are invalid and intentionally omitted.'
  else:
   assert v['registration_diff_complete'];out=v
   assert c['raw_changes']-c['classified_reschedules']+c['binding_change_blockers']==c['blocked_changes']
   assert all(v[k]['all_passed'] for k in ['classifier_unit_tests','classifier_live_tests','recovery_gate_tests'])
  (P/(name+'.json')).write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n')
  (P/(name+'-source-manifest.json')).write_text(json.dumps(m,indent=2)+'\n')
  row={'attempt':name,'run_id':run,'target_launched':d.get('target_launched') is True,'observation_seconds':d.get('observation_seconds') if d.get('target_launched') else None,'failure_stage':d.get('failure_stage'),'raw_changes':None if initial else c.get('raw_changes'),'allowed_reschedules':None if initial else c.get('classified_reschedules'),'blocked_changes':None if initial else c.get('blocked_changes'),'firewall_restored':r.get('firewall_restored') is True,'bits_samples':b.get('watch_samples'),'bits_complete':b.get('watch_complete') is True}
  rows.append(row);evidence.append({'attempt':name,'source_commit':v['source_commit'],'log_report_sha256':m['sha256'],'published_projection':initial,'status':v['status']})
s=io.StringIO();w=csv.DictWriter(s,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows);(P/'attempts.csv').write_text(s.getvalue());(P/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
print(json.dumps(rows,ensure_ascii=False))
