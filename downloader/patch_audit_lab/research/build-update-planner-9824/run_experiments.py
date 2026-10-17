"""Reproduce planner + previous 144 regressions, with prepared owned fixtures.
No game scan, downloads, migration or writes inside any supplied input root.
"""
import argparse,hashlib,json,os,re,subprocess,sys
from pathlib import Path
import source_binding as b
import retail_storage_poc as safety
import build_update_plan as planner

LAB=Path(__file__).resolve().parents[2]
def save(p,obj):p.write_text(json.dumps(obj,indent=2)+'\n')
def execute(args,env,timeout=300):
 r=subprocess.run([sys.executable,'-B',*map(str,args)],cwd=LAB,env=env,capture_output=True,text=True,timeout=timeout)
 b.need(r.returncode==0,'planner_reproduction_command_failed');return r

def run(x):
 inputs=[x.workspace_template,x.snapshot_cycle_template,x.direct_cycle_template,x.real_payload_fixture,x.portable]
 inputs=[b.safe(p) for p in inputs];out=safety.safe_new(x.out_new)
 b.need(all(not (p==out or p in out.parents or out in p.parents) for p in inputs),'evidence_input_overlap')
 w=b.Watch()
 for folder in inputs:
  for p in folder.rglob('*'):
   if p.is_file():w.file(p)
 out.mkdir();env=dict(os.environ,PYTHONPATH=str(LAB))
 old=LAB/'research/sample-updater-9824/run_experiments.py'
 args=[old,'--workspace-template',inputs[0],'--snapshot-cycle-template',inputs[1],
       '--direct-cycle-template',inputs[2],'--real-payload-fixture',inputs[3],
       '--insert-oracle',x.insert_oracle,'--out-new',out/'regression']
 r=execute(args,env);(out/'REGRESSION-RUN.log').write_text(r.stdout+r.stderr)
 committed=out/'regression/smoke-workspace'
 env.update(SAMPLE_UPDATER_TEMPLATE=str(inputs[0]),PLANNER_COMMITTED_WORKSPACE=str(committed))
 r=execute(['-m','unittest','discover','-s','planner_tests','-v'],env)
 log=r.stdout+r.stderr;(out/'PLANNER-TESTS.log').write_text(log)
 b.need(re.findall(r'Ran (\d+) tests',log)==['44'] and log.rstrip().endswith('OK'),'planner_test_count')
 commands=[('PORTABLE-PLAN.json',[LAB/'build_update_plan.py','portable','--root',inputs[4]]),
           ('SOURCE-WORKSPACE-PLAN.json',[LAB/'retail_sample_updater.py','build-plan','--workspace',inputs[0]]),
           ('COMMITTED-WORKSPACE-PLAN.json',[LAB/'retail_sample_updater.py','build-plan','--workspace',committed])]
 reports={}
 for name,args in commands:
  r=execute(args,env);b.need(not r.stderr,'planner_cli_stderr');obj=json.loads(r.stdout);save(out/name,obj);reports[name]=obj
 # Independent expected result for this exact fixture, not a global estimate.
 for name in ('PORTABLE-PLAN.json','SOURCE-WORKSPACE-PLAN.json'):
  q=reports[name];b.need(q['target_objects_evaluated']==1 and q['actions']=={'patch':1} and q['conditional_payload_bytes']==0,'source_plan_mismatch')
  b.need(q['rows'][0]['selected_patch']['patch_size']==117 and q['rows'][0]['patch_already_verified_locally'],'saved_patch_cost_mismatch')
 q=reports['COMMITTED-WORKSPACE-PLAN.json'];b.need(q['actions']=={'reuse':1} and q['conditional_payload_bytes']==0,'reuse_plan_mismatch')
 for q in reports.values():b.need(q['required_network_download_bytes'] is None and not q['full_game_build_plan'] and not q['apply_authorized'],'planner_scope_claim')
 w.check();reg=json.loads((out/'regression/TEST-RESULTS.json').read_text())
 b.need(reg['tests_run']==144 and reg['failures']==reg['errors']==reg['skipped']==0,'regression_result')
 sources=['build_update_plan.py','retail_sample_updater.py','planner_tests/test_build_update_plan.py',str(Path(__file__).resolve().relative_to(LAB))]
 result={'format':'readonly-update-planner-test-results-1','tests_run':188,'prior_tests_rerun':144,'new_planner_tests':44,
         'failures':0,'errors':0,'skipped':0,'real_portable_verified_again':True,
         'source_only_owned_workspace_action':'patch_using_already_saved_verified_bytes',
         'committed_owned_workspace_action':'reuse_after_fresh_native_lookup_direct_read_and_payload_check',
         'saved_content_plan_adapter_tests':'synthetic_SQLite_schema_fixtures;not_real_user_full_plan',
         'complete_real_download_manifest_available':False,'installed_user_build_detected':False,
         'conditional_bytes_zero_only_because_fixture_patch_is_already_local':True,
         'all_supplied_input_file_fingerprints_unchanged':True,'network_requests':0,
         'network_downloader_added':False,'generic_patch_executor_added':False,
         'full_build_or_multiple_real_payloads_tested':False,'historical_814_suite_rerun':False,
         'windows_or_power_loss_tested':False,'installation_ready':False,
         'sources_sha256':{n:hashlib.sha256((LAB/n).read_bytes()).hexdigest() for n in sources},
         'artifacts_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.iterdir()) if p.is_file()}}
 save(out/'TEST-RESULTS.json',result);return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('workspace-template','snapshot-cycle-template','direct-cycle-template','real-payload-fixture','portable','insert-oracle','out-new'):p.add_argument('--'+n,type=Path,required=True)
 x=p.parse_args();r=run(x);print(json.dumps({k:r[k] for k in ('tests_run','failures','errors','skipped','installation_ready')},indent=2))
