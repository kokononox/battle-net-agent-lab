import json,hashlib,pathlib,csv,sys
OUT=pathlib.Path('/data/analysis/bnet-control-g18')
inputs=[('control','/data/raw/bnet-control-g18/no_setup.json'),('aborted_real','/data/raw/bnet-control-g18/real_setup.json'),('repeat_real','/data/raw/bnet-control-g18a/real_setup.json')]
if '--published' in sys.argv:
 BASE=pathlib.Path(__file__).resolve().parent;OUT=pathlib.Path.cwd()/'g18-analysis';OUT.mkdir(exist_ok=True)
 inputs=[('control',str(BASE/'control.json')),('aborted_real',str(BASE/'aborted-real.json')),('repeat_real',str(BASE/'repeat-real.json'))]
rows=[];records={};checks=[]
for label,path in inputs:
 p=pathlib.Path(path)
 if not p.exists():continue
 raw=p.read_bytes();r=json.loads(raw);meta=json.loads(p.with_name(p.stem+'-manifest.json').read_text());assert hashlib.sha256(raw).hexdigest()==meta['sha256'] and len(raw)==meta['raw_bytes']
 d=r.get('driver',{});o=r.get('owner',{});b=r.get('bits',{});rec=r.get('recovery',{});diffs=r.get('registration_differences',[])
 observed=d.get('gate_verified_before_launch') is True and d.get('gate_verified_after_observation') is True and b.get('watch_complete') is True
 if r['scenario']=='no_setup':observed=observed and r['installer_launched'] is False and d.get('target_launch_attempted') is False and d.get('observation_seconds')==90
 else:observed=observed and r['installer_launched'] is True and o.get('observation_seconds')==90 and all(o.get(k) is True for k in ['assigned_before_resume','job_active_zero_before_close','root_exited']) and d.get('owner_exit_confirmed') is True
 # Independent count path checks the source's summarized registration delta.
 sc=sum(x.get('kind')=='services' for x in diffs);tc=sum(x.get('kind')=='tasks' for x in diffs)
 assert len(diffs)==sc+tc
 declared=r.get('registration_changes_by_kind',{});assert declared.get('services')==sc and declared.get('tasks')==tc
 expected=rec.get('registration_changes') if rec else r.get('system_prelaunch',{}).get('registration_changes')
 assert expected==len(diffs),(label,expected,len(diffs))
 row={'arm':label,'scenario':r['scenario'],'run_id':r['run_id'],'source_commit':r['source_commit'],'installer_launched':r['installer_launched'],'observation_complete':bool(observed),'service_deltas':sc,'task_deltas':tc,'bits_watch_complete':b.get('watch_complete'),'bits_observed_jobs':b.get('distinct_observed_jobs'),'bits_samples':b.get('watch_samples'),'restoration_qualified':r['status'] in {'offline_bootstrap_observed_and_restored','offline_no_setup_control_observed_and_restored'},'status':r['status'],'error_code':d.get('error_code')}
 rows.append(row);records[label]=r;checks.append({'arm':label,'report_sha256':meta['sha256'],'source':'sanitized_live_log_zlib_parts_not_artifact','manifest_verified':True,'registration_totals_cross_checked':True})
# Preserve every attempt; an aborted arm is not treated as a 90-second installer observation.
comparison={'grain':'one fresh hosted VM attempt per row','source_scope':'same G18 harness; repetition changes only workflow matrix, not executable harness source','rows':rows,'validation':checks,'findings':{},'comparison_plan':[{'finding':'Windows task definition drift can occur without Setup execution','disposition':'prose','reason':'categorical engineering counterexample, not a quantitative trend or comparable population rate'},{'finding':'BITS inventory completeness and observed job absence','disposition':'prose','reason':'sampled absence requires a coverage caveat; a count chart could imply comprehensive transfer coverage'}]}
if 'control' in records:
 c=records['control'];comparison['findings']['without_setup_task_changes']=[{'id_sha256':x['identity_sha256'],'identifier':x['identifier'],'fields':x.get('changed_xml_fields',[])} for x in c.get('registration_differences',[])];comparison['findings']['control_observed_without_setup']=next(x['observation_complete'] for x in rows if x['arm']=='control')
if 'aborted_real' in records:
 a=records['aborted_real'];comparison['findings']['before_setup_task_changes']=[{'id_sha256':x['identity_sha256'],'identifier':x['identifier'],'fields':x.get('changed_xml_fields',[])} for x in a.get('registration_differences',[])];comparison['findings']['aborted_arm_not_install_observation']=a['installer_launched'] is False and a.get('driver',{}).get('target_launch_attempted') is False
if 'control' in records and 'repeat_real' in records:
 c=records['control'];a=records['repeat_real']
 left={(x['identity_sha256'],tuple(x.get('changed_xml_fields',[]))) for x in c.get('registration_differences',[])}
 shared=[{'identifier':x['identifier'],'id_sha256':x['identity_sha256'],'fields':x.get('changed_xml_fields',[])} for x in a.get('registration_differences',[]) if (x['identity_sha256'],tuple(x.get('changed_xml_fields',[]))) in left]
 comparison['findings']['shared_exact_task_identity_and_fields']=shared
 assert len(shared)==1 and shared[0]['identifier']=='SvcRestartTask'
 assert c['installer_launched'] is False and a['installer_launched'] is True
 assert c['bits']['watch_complete'] and a['bits']['watch_complete']
 assert c['bits']['distinct_observed_jobs']==a['bits']['distinct_observed_jobs']==0
 comparison['findings']['no_bits_jobs_observed_in_completed_arms']=True
 comparison['findings']['absence_is_sampled_not_continuous']=True
 comparison['findings']['prior_g17_bits_config_change_cause_still_unknown']=True
(OUT/'evidence.json').write_text(json.dumps(comparison,indent=2))
with (OUT/'attempts.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
print(json.dumps(rows,indent=2))
