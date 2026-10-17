"""Run 237 prior tests + 25 diagnostic tests and validate standalone failures.
Windows errors are injected on Linux: this does not establish a Windows fix.
"""
import argparse,hashlib,json,os,re,shutil,subprocess,sys
from pathlib import Path
import source_binding as b
import retail_storage_poc as safety
LAB=Path(__file__).resolve().parents[2]
def save(p,o):p.write_text(json.dumps(o,indent=2)+'\n')
def run(x):
 out=safety.safe_new(x.out_new)
 inputs=[b.safe(getattr(x,n)) for n in ('workspace_template','snapshot_cycle_template','direct_cycle_template','real_payload_fixture','portable')]
 b.need(all(not(p==out or p in out.parents or out in p.parents) for p in inputs),'diagnostic_evidence_overlap');out.mkdir()
 env=dict(os.environ,PYTHONPATH=str(LAB));old=LAB/'research/local-update-review-9824/run_experiments.py'
 args=[sys.executable,'-B',str(old)]
 for name in ('workspace-template','snapshot-cycle-template','direct-cycle-template','real-payload-fixture','portable','insert-oracle'):
  args+=['--'+name,str(getattr(x,name.replace('-','_')))]
 args+=['--out-new',str(out/'regression-237')]
 proc=subprocess.run(args,cwd=LAB,env=env,capture_output=True,text=True,timeout=300)
 (out/'REGRESSION-RUN.log').write_text(proc.stdout+proc.stderr);b.need(proc.returncode==0,'diagnostic_prior_regression_failed')
 reg=json.loads((out/'regression-237/TEST-RESULTS.json').read_text());b.need(reg['tests_run']==237 and reg['errors']==reg['failures']==reg['skipped']==0,'diagnostic_regression_count')
 env.update(REVIEW_PORTABLE=str(inputs[4]),REVIEW_SOURCE_ARCHIVE=str(inputs[0]/'cycle/data.000'))
 proc=subprocess.run([sys.executable,'-B','-m','unittest','discover','-s','diagnostic_tests','-v'],cwd=LAB,env=env,capture_output=True,text=True,timeout=120)
 log=proc.stdout+proc.stderr;(out/'DIAGNOSTIC-TESTS.log').write_text(log)
 b.need(proc.returncode==0 and re.findall(r'Ran (\d+) tests',log)==['25'] and log.rstrip().endswith('OK'),'diagnostic_new_tests_failed')
 bundle=out/'Local-Update-Review-Diagnostics.zip';shutil.copyfile(out/'regression-237/Local-Update-Review.zip',bundle)
 root=out/'regression-237/bundle-smoke/Local-Update-Review';isolated=dict(os.environ);isolated.pop('PYTHONPATH',None)
 invalid=out/'DOES-NOT-EXIST-PRIVATE-PATH'
 proc=subprocess.run([sys.executable,'-B',str(root/'local_update_review.py'),'--lab',str(invalid),'--audit-dir',str(root/'pinned_metadata')],cwd=root,env=isolated,capture_output=True,text=True,timeout=30)
 q=json.loads(proc.stdout)
 b.need(proc.returncode==1 and not proc.stderr and q['stage']=='bind_saved_checkpoint' and q['diagnostics_version']=='local-review-diag-2' and q['errno']==2 and q['safe_trace'],'diagnostic_bundle_failure_smoke')
 b.need(str(out) not in proc.stdout and str(invalid) not in proc.stdout,'diagnostic_private_path_leak')
 save(out/'BUNDLE-ERROR-SMOKE.json',{'input_kind':'deliberately_nonexistent_local_fixture_path;not_user_error','runtime':'Linux_Python3.13','returncode':1,'output':q,'private_paths_omitted':True,'Windows_cause_reproduced':False})
 names=['local_update_review.py','local_review_launcher.py','diagnostic_tests/test_safe_diagnostics.py','research/local-update-review-9824/README-fa.md',str(Path(__file__).resolve().relative_to(LAB))]
 result={'format':'safe-os-diagnostics-test-results-1','diagnostics_version':'local-review-diag-2','tests_run':262,'prior_tests_rerun':237,'new_diagnostic_tests':25,
         'failures':0,'errors':0,'skipped':0,'windows_errors_injected_on_linux':True,'real_Windows_execution_tested':False,
         'user_oserror_root_cause_known':False,'user_oserror_fixed_claimed':False,'validators_or_read_limits_relaxed':False,
         'raw_exception_messages_or_private_paths_logged':False,'standalone_success_modes_rerun':2,'standalone_failure_mode_passed':True,
         'game_or_Lab_writes':False,'network_requests':0,'installation_ready':False,'bundle_bytes':bundle.stat().st_size,'bundle_sha256':hashlib.sha256(bundle.read_bytes()).hexdigest(),
         'sources_sha256':{n:hashlib.sha256((LAB/n).read_bytes()).hexdigest() for n in names},
         'artifacts_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file() and p!=bundle}}
 save(out/'TEST-RESULTS.json',result);return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('workspace-template','snapshot-cycle-template','direct-cycle-template','real-payload-fixture','portable','insert-oracle','out-new'):p.add_argument('--'+n,type=Path,required=True)
 x=p.parse_args();r=run(x);print(json.dumps({k:r[k] for k in ('tests_run','failures','errors','bundle_bytes','user_oserror_root_cause_known')},indent=2))
