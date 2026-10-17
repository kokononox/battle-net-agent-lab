"""Rerun 237 + 25 tests, add Windows publication contract tests, build ZIP.
Native Windows/filesystem behaviour is NOT executed by this Linux runner.
"""
import argparse,hashlib,json,os,re,shutil,subprocess,sys
from pathlib import Path
import source_binding as b
import retail_storage_poc as safety
import local_update_review as review
LAB=Path(__file__).resolve().parents[2]
def save(p,obj):p.write_text(json.dumps(obj,indent=2)+'\n')
def run(x):
 out=safety.safe_new(x.out_new);inputs=[b.safe(getattr(x,n)) for n in ('workspace_template','snapshot_cycle_template','direct_cycle_template','real_payload_fixture','portable')]
 b.need(all(not(p==out or p in out.parents or out in p.parents) for p in inputs),'publication_evidence_overlap');out.mkdir()
 env=dict(os.environ,PYTHONPATH=str(LAB));args=[sys.executable,'-B',str(LAB/'research/local-update-review-9824/run_experiments.py')]
 for n in ('workspace-template','snapshot-cycle-template','direct-cycle-template','real-payload-fixture','portable','insert-oracle'):args+=['--'+n,str(getattr(x,n.replace('-','_')))]
 args+=['--out-new',str(out/'regression-237')]
 proc=subprocess.run(args,cwd=LAB,env=env,capture_output=True,text=True,timeout=300)
 (out/'REGRESSION-RUN.log').write_text(proc.stdout+proc.stderr);b.need(proc.returncode==0,'publication_regression_failed')
 reg=json.loads((out/'regression-237/TEST-RESULTS.json').read_text());b.need(reg['tests_run']==237 and reg['failures']==reg['errors']==reg['skipped']==0,'publication_prior_count')
 env.update(REVIEW_PORTABLE=str(inputs[4]),REVIEW_SOURCE_ARCHIVE=str(inputs[0]/'cycle/data.000'));counts={}
 for folder,wanted in [('diagnostic_tests',25),('publication_tests',16)]:
  proc=subprocess.run([sys.executable,'-B','-m','unittest','discover','-s',folder,'-v'],cwd=LAB,env=env,capture_output=True,text=True,timeout=120)
  log=proc.stdout+proc.stderr;(out/(folder.upper()+'.log')).write_text(log)
  b.need(proc.returncode==0 and re.findall(r'Ran (\d+) tests',log)==[str(wanted)] and log.rstrip().endswith('OK') and 'ResourceWarning' not in log,'publication_tests_failed');counts[folder]=wanted
 bundle=out/'Local-Update-Review-Windows-Fix.zip';shutil.copyfile(out/'regression-237/Local-Update-Review.zip',bundle)
 root=out/'regression-237/bundle-smoke/Local-Update-Review';isolated=dict(os.environ);isolated.pop('PYTHONPATH',None)
 # In addition to the original standalone two read-only modes, publish a report
 # using the actual Linux primitive. Input DBs and archive here are owned fixtures.
 fixture=out/'regression-237/fixtures/source'
 labs=list(fixture.glob('*/LAB-ONLY.json'));b.need(len(labs)==1,'publication_fixture_lab')
 output=out/'isolated-published-report';argv=[sys.executable,'-B',str(root/'local_update_review.py'),'--lab',str(labs[0].parent),'--audit-dir',str(root/'pinned_metadata'),'--out-new',str(output)]
 proc=subprocess.run(argv,cwd=root,env=isolated,capture_output=True,text=True,timeout=60)
 b.need(proc.returncode==0 and not proc.stderr,'publication_standalone_cli_failed');q=json.loads(proc.stdout)
 final=output/'LOCAL-UPDATE-REVIEW-to-share.json';b.need(json.loads(final.read_text())==q and q['actions']=={'full_download':1,'reuse':1},'publication_standalone_report')
 save(out/'BUNDLE-PUBLICATION-SMOKE.json',{'runtime':'Linux_Python3.13','repository_PYTHONPATH_removed':True,'report_matches_stdout':True,'actions':q['actions'],'archive_payload_bytes_read':q['local_verification']['archive_payload_bytes_read'],'Windows_execution':False})
 proc=subprocess.run([sys.executable,'-B',str(root/'local_update_review.py'),'--lab',str(out/'NONEXISTENT-PRIVATE-PATH'),'--audit-dir',str(root/'pinned_metadata')],cwd=root,env=isolated,capture_output=True,text=True,timeout=30)
 error=json.loads(proc.stdout);b.need(proc.returncode==1 and not proc.stderr and error['diagnostics_version']==review.DIAGNOSTICS_VERSION and error['stage']=='bind_saved_checkpoint' and str(out) not in proc.stdout,'publication_bundle_diagnostic_smoke')
 save(out/'BUNDLE-ERROR-SMOKE.json',error)
 names=['local_update_review.py','diagnostic_tests/test_safe_diagnostics.py','publication_tests/test_windows_publication.py','research/local-update-review-9824/README-fa.md',str(Path(__file__).resolve().relative_to(LAB))]
 result={'format':'windows-report-publication-fix-results-1','diagnostics_version':review.DIAGNOSTICS_VERSION,'tests_run':237+sum(counts.values()),'prior_tests_rerun':262,'new_publication_tests':16,'failures':0,'errors':0,'skipped':0,
  'user_reported_failing_call':'os.link(temp,final)','user_reported_stage':'publish_report_noreplace','user_reported_errno':22,'user_reported_winerror':1,
  'underlying_filesystem_type_or_reason_known':False,'windows_uses_rename_without_replacement':True,'posix_keeps_hardlink_noreplace':True,'unsafe_overwriting_fallback_added':False,
  'Windows_rename_contract_modeled_on_Linux':True,'native_Windows_execution_tested':False,'user_Windows_success_confirmed':False,
  'input_safety_or_read_limits_relaxed':False,'original_game_or_user_Lab_accessed':False,'network_requests':0,'installation_ready':False,
  'standalone_read_modes_passed':2,'standalone_report_publication_Linux_passed':True,'standalone_diagnostic_error_passed':True,
  'bundle_bytes':bundle.stat().st_size,'bundle_sha256':hashlib.sha256(bundle.read_bytes()).hexdigest(),
  'sources_sha256':{n:hashlib.sha256((LAB/n).read_bytes()).hexdigest() for n in names},
  'artifacts_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file() and p!=bundle}}
 save(out/'TEST-RESULTS.json',result);return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('workspace-template','snapshot-cycle-template','direct-cycle-template','real-payload-fixture','portable','insert-oracle','out-new'):p.add_argument('--'+n,type=Path,required=True)
 x=p.parse_args();r=run(x);print(json.dumps({k:r[k] for k in ('tests_run','failures','errors','bundle_bytes','native_Windows_execution_tested')},indent=2))
