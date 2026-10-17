"""319 local tests; isolated prepare/two-batch/explain CLI; never user game IO."""
import argparse,hashlib,json,os,re,shutil,subprocess,sys,zipfile
from pathlib import Path
import source_binding as b
import retail_storage_poc as safety
import local_update_review as review
import review_report_explain as explain
LAB=Path(__file__).resolve().parents[2]
def save(p,obj):p.write_text(json.dumps(obj,indent=2)+'\n')
def run(x):
 out=safety.safe_new(x.out_new);inputs=[b.safe(getattr(x,n)) for n in ('workspace_template','snapshot_cycle_template','direct_cycle_template','real_payload_fixture','portable')]
 b.need(all(not(p==out or p in out.parents or out in p.parents) for p in inputs),'continuation_evidence_overlap');out.mkdir()
 env=dict(os.environ,PYTHONPATH=str(LAB));args=[sys.executable,'-B',str(LAB/'research/windows-report-publication-9824/run_experiments.py')]
 for n in ('workspace-template','snapshot-cycle-template','direct-cycle-template','real-payload-fixture','portable','insert-oracle'):args+=['--'+n,str(getattr(x,n.replace('-','_')))]
 args+=['--out-new',str(out/'regression-278')]
 proc=subprocess.run(args,cwd=LAB,env=env,capture_output=True,text=True,timeout=300)
 (out/'REGRESSION-RUN.log').write_text(proc.stdout+proc.stderr);b.need(proc.returncode==0,'continuation_prior_regression_failed')
 reg=json.loads((out/'regression-278/TEST-RESULTS.json').read_text());b.need(reg['tests_run']==278 and reg['failures']==reg['errors']==reg['skipped']==0,'continuation_prior_count')
 committed=out/'regression-278/regression-237/regression-188/regression/smoke-workspace/cycle/data.000'
 env.update(REVIEW_PORTABLE=str(inputs[4]),REVIEW_SOURCE_ARCHIVE=str(inputs[0]/'cycle/data.000'),REVIEW_COMMITTED_ARCHIVE=str(committed))
 proc=subprocess.run([sys.executable,'-B','-m','unittest','discover','-s','continuation_tests','-v'],cwd=LAB,env=env,capture_output=True,text=True,timeout=180)
 log=proc.stdout+proc.stderr;(out/'CONTINUATION-TESTS.log').write_text(log)
 b.need(proc.returncode==0 and re.findall(r'Ran (\d+) tests',log)==['41'] and log.rstrip().endswith('OK') and 'ResourceWarning' not in log,'continuation_new_tests_failed')
 bundle=out/'Local-Review-Safe-Continuation.zip';shutil.copyfile(out/'regression-278/Local-Update-Review-Windows-Fix.zip',bundle)
 root=out/'regression-278/regression-237/bundle-smoke/Local-Update-Review';isolated=dict(os.environ);isolated.pop('PYTHONPATH',None)
 with zipfile.ZipFile(bundle) as z:
  manifest=json.loads(z.read('Local-Update-Review/BUNDLE-MANIFEST.json'))
  for name,info in manifest['files'].items():
   data=z.read('Local-Update-Review/'+name);b.need(len(data)==info['bytes'] and hashlib.sha256(data).hexdigest()==info['sha256'],'continuation_bundle_hash')
  b.need(b'prepare_review_launcher.py' in z.read('Local-Update-Review/RUN-LOCAL-REVIEW.cmd'),'continuation_default_is_metadata_only')
 fixture=out/'regression-278/regression-237/fixtures/committed';labs=list(fixture.glob('*/LAB-ONLY.json'));b.need(len(labs)==1,'continuation_fixture_lab')
 before={str(p):b.fp(p.stat()) for p in fixture.rglob('*') if p.is_file()}
 def command(extra,output):
  argv=[sys.executable,'-B',str(root/'local_update_review.py'),'--lab',str(labs[0].parent),'--audit-dir',str(root/'pinned_metadata'),*map(str,extra),'--out-new',str(output)]
  proc=subprocess.run(argv,cwd=root,env=isolated,capture_output=True,text=True,timeout=90)
  b.need(proc.returncode==0 and not proc.stderr,'continuation_isolated_cli_failed');q=json.loads(proc.stdout)
  report=output/'LOCAL-UPDATE-REVIEW-to-share.json';b.need(json.loads(report.read_text())==q,'continuation_report_identity');return q,report
 prepared,p0=command(['--prepare-checkpoint'],out/'isolated-prepare')
 b.need(prepared['local_verification']['archive_payload_bytes_read']==0 and prepared['continuation']['status']=='prepared_metadata_only','continuation_prepare_zero_reads')
 first,p1=command(['--continue-from',p0,'--max-reads','1'],out/'isolated-first-batch')
 second,p2=command(['--continue-from',p1,'--max-reads','1'],out/'isolated-second-batch')
 b.need(first['actions']==second['actions']=={'reuse':1} and first['rows'][0]['target_ekey']!=second['rows'][0]['target_ekey'],'continuation_unique_targets')
 b.need(first['continuation']['has_more_saved_targets'] and not second['continuation']['has_more_saved_targets'] and second['local_verification']['archive_payload_bytes_read']==158,'continuation_two_batches')
 proc=subprocess.run([sys.executable,'-B',str(root/'review_report_explain.py'),'--report',str(p1)],cwd=root,env=isolated,capture_output=True,text=True,timeout=30)
 b.need(proc.returncode==0 and not proc.stderr and json.loads(proc.stdout)['archive_payload_bytes_read_by_explainer']==0,'continuation_explain_standalone')
 b.need(before=={str(p):b.fp(p.stat()) for p in fixture.rglob('*') if p.is_file()},'continuation_fixture_changed')
 save(out/'BUNDLE-CONTINUATION-SMOKE.json',{'runtime':'Linux_Python3.13','PYTHONPATH_removed':True,'input':'generated_DBs_with_two_real_owned_payloads_NOT_user_inventory','prepare_archive_payload_bytes':0,'first_batch_actions':first['actions'],'second_batch_actions':second['actions'],'distinct_targets_verified':True,'batch_archive_payload_bytes':[first['local_verification']['archive_payload_bytes_read'],second['local_verification']['archive_payload_bytes_read']],'prior_success_proofs_imported':False,'end_of_traversal_not_install_proof':True,'no_fixture_fingerprints_changed':True,'Windows_execution':False})
 user=False
 if x.report is not None:
  w=b.Watch();raw=w.read(x.report,limit=4*1024**2);value=explain.explain(b.json_object(raw));w.check()
  save(out/'UPLOADED-REPORT-EXPLANATION.json',{'source_sha256':hashlib.sha256(raw).hexdigest(),'interpretation':value});user=True
 names=['build_update_plan.py','local_update_review.py','local_review_launcher.py','review_checkpoint.py','review_report_explain.py','prepare_review_launcher.py','continue_review_launcher.py','RUN-LOCAL-REVIEW.cmd','PREPARE-CONTINUATION.cmd','CONTINUE-ONE-BATCH.cmd','diagnostic_tests/test_safe_diagnostics.py','publication_tests/test_windows_publication.py','continuation_tests/test_review_continuation.py','research/local-update-review-9824/run_experiments.py','research/local-update-review-9824/README-fa.md',str(Path(__file__).resolve().relative_to(LAB))]
 result={'format':'safe-position-continuation-test-results-1','diagnostics_version':review.DIAGNOSTICS_VERSION,'tests_run':319,'prior_tests_rerun':278,'new_tests':41,'failures':0,'errors':0,'skipped':0,
  'default_CMD_prepares_metadata_only':True,'prepare_archive_payload_bytes':0,'legacy_reports_rejected_as_bound_cursor':True,'cursor_is_position_only_not_proof_cache':True,'deferred_budget_target_not_skipped':True,'old_proof_flags_never_imported':True,'automatic_next_batch':False,
  'input_read_limits_relaxed':False,'native_Windows_execution_tested':False,'real_user_Lab_tested':False,'uploaded_public_report_interpreted_without_Lab':user,
  'profile_guessed_or_recomputed':False,'actual_required_install_set_known':False,'game_build_info_read_or_modified':False,'game_or_user_Lab_writes':False,'network_requests':0,'installation_ready':False,
  'isolated_CLI_prepare_and_two_batch_modes_passed':3,'isolated_CLI_explainer_passed':True,
  'bundle_bytes':bundle.stat().st_size,'bundle_sha256':hashlib.sha256(bundle.read_bytes()).hexdigest(),
  'sources_sha256':{n:hashlib.sha256((LAB/n).read_bytes()).hexdigest() for n in names},
  'artifacts_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file() and p!=bundle}}
 save(out/'TEST-RESULTS.json',result);return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('workspace-template','snapshot-cycle-template','direct-cycle-template','real-payload-fixture','portable','insert-oracle','out-new'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--report',type=Path);x=p.parse_args();q=run(x);print(json.dumps({k:q[k] for k in ('tests_run','failures','errors','skipped','bundle_bytes','installation_ready')},indent=2))
