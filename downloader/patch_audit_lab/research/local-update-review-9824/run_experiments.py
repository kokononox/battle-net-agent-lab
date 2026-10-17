"""237 tests + synthetic saved-DB / real-payload CLI + standalone bundle smoke.
All input roots remain unchanged. Never a proof of the user's installed game.
"""
import argparse,hashlib,json,os,re,subprocess,sys,zipfile
from pathlib import Path
import source_binding as b
import retail_storage_poc as safety
import local_update_review as review
LAB=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(LAB/'local_review_tests'))
from fixtures import Fixture

MODULES=('local_update_review.py','local_review_launcher.py','build_update_plan.py',
         'patch_audit.py','source_binding.py','source_check.py','refs_source_check.py',
         'portable_run.py','encoding_target.py','staging_sample.py','cdn_catalog.py','RUN-LOCAL-REVIEW.cmd',
         'review_checkpoint.py','review_report_explain.py','prepare_review_launcher.py',
         'continue_review_launcher.py','PREPARE-CONTINUATION.cmd','CONTINUE-ONE-BATCH.cmd')
def save(p,o):p.write_text(json.dumps(o,indent=2)+'\n')
def command(args,env,cwd=LAB):
 r=subprocess.run([sys.executable,'-B',*map(str,args)],env=env,cwd=cwd,capture_output=True,text=True,timeout=300)
 b.need(r.returncode==0,'local_review_reproduction_command');return r

def bundle(out,portable):
 files={n:(LAB/n).read_bytes() for n in MODULES}
 for n in files:
  if n.endswith('.cmd'):files[n]=files[n].replace(b'\r\n',b'\n').replace(b'\n',b'\r\n')
 for n in ['build.config',*[f'manifest.pa.base64.part{i}' for i in range(3)]]:files['pinned_metadata/'+n]=(portable/'pinned_metadata'/n).read_bytes()
 files['README-fa.md']=(LAB/'research/local-update-review-9824/README-fa.md').read_bytes()
 manifest={'format':'readonly-local-review-bundle-1','game_writer_or_agent_binary_included':False,
           'python_requires':'3.10+','tested_runtime':'Python3.13_Linux;Windows_launcher_not_run',
           'files':{n:{'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for n,data in files.items()}}
 files['BUNDLE-MANIFEST.json']=(json.dumps(manifest,indent=2)+'\n').encode()
 path=out/'Local-Update-Review.zip'
 with zipfile.ZipFile(path,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
  for n in sorted(files):z.writestr('Local-Update-Review/'+n,files[n])
 save(out/'BUNDLE-MANIFEST.json',manifest)
 # This is our own whitelist-built archive, not an arbitrary uploaded ZIP.
 with zipfile.ZipFile(path) as z:
  b.need(set(z.namelist())=={'Local-Update-Review/'+n for n in files},'bundle_member_set')
  z.extractall(out/'bundle-smoke')
 root=out/'bundle-smoke/Local-Update-Review'
 for n,data in files.items():b.need((root/n).read_bytes()==data,'bundle_extraction_identity')
 return path,root

def run(x):
 inputs=[b.safe(getattr(x,n)) for n in ('workspace_template','snapshot_cycle_template','direct_cycle_template','real_payload_fixture','portable')]
 out=safety.safe_new(x.out_new);b.need(all(not(p==out or p in out.parents or out in p.parents) for p in inputs),'review_evidence_overlap')
 w=b.Watch()
 for folder in inputs:
  for p in folder.rglob('*'):
   if p.is_file():w.file(p)
 out.mkdir();env=dict(os.environ,PYTHONPATH=str(LAB));old=LAB/'research/build-update-planner-9824/run_experiments.py'
 args=[old,'--workspace-template',inputs[0],'--snapshot-cycle-template',inputs[1],'--direct-cycle-template',inputs[2],
       '--real-payload-fixture',inputs[3],'--portable',inputs[4],'--insert-oracle',x.insert_oracle,'--out-new',out/'regression-188']
 proc=command(args,env);(out/'REGRESSION-RUN.log').write_text(proc.stdout+proc.stderr)
 committed=out/'regression-188/regression/smoke-workspace/cycle/data.000'
 env.update(REVIEW_PORTABLE=str(inputs[4]),REVIEW_SOURCE_ARCHIVE=str(inputs[0]/'cycle/data.000'),REVIEW_COMMITTED_ARCHIVE=str(committed))
 proc=command(['-m','unittest','discover','-s','local_review_tests','-v'],env)
 log=proc.stdout+proc.stderr;(out/'LOCAL-REVIEW-TESTS.log').write_text(log)
 b.need(re.findall(r'Ran (\d+) tests',log)==['49'] and log.rstrip().endswith('OK') and 'ResourceWarning' not in log,'local_review_test_count')
 options,pa,binding=b.load_metadata(inputs[4]/'pinned_metadata',w)
 fixture_root=out/'fixtures';fixture_root.mkdir();source_root=fixture_root/'source';source_root.mkdir();done_root=fixture_root/'committed';done_root.mkdir()
 source=Fixture(source_root,binding,(inputs[0]/'cycle/data.000').read_bytes())
 done=Fixture(done_root,binding,committed.read_bytes(),committed=True)
 demos=[]
 for label,f,extra,expected,bytes_read in [('source_without_portable',source,[],{'full_download':1,'reuse':1},158),
      ('source_with_portable',source,['--portable',inputs[4]],{'patch':1,'reuse':1},158),
      ('committed_two_objects',done,[],{'reuse':2},316)]:
  r=command([LAB/'local_update_review.py','--lab',f.lab,'--audit-dir',inputs[4]/'pinned_metadata',*extra],env)
  q=json.loads(r.stdout);b.need(not r.stderr and q['actions']==expected and q['local_verification']['archive_payload_bytes_read']==bytes_read,'fixture_cli_result')
  demos.append({'case':label,'input_kind':'GENERATED_saved_DBs_and_real_pair_in_owned_archive_NOT_user_inventory','result':q})
 save(out/'FIXTURE-CLI-RESULTS.json',demos)
 package,root=bundle(out,inputs[4]);isolated=dict(os.environ);isolated.pop('PYTHONPATH',None);smoke=[]
 for extra,expected in [([] ,{'full_download':1,'reuse':1}),(['--portable',inputs[4]],{'patch':1,'reuse':1})]:
  proc=command([root/'local_update_review.py','--lab',source.lab,'--audit-dir',root/'pinned_metadata',*extra],isolated,cwd=root)
  q=json.loads(proc.stdout);b.need(not proc.stderr and q['actions']==expected,'standalone_bundle_smoke')
  smoke.append({'with_portable':bool(extra),'actions':q['actions'],'archive_payload_bytes_read':q['local_verification']['archive_payload_bytes_read'],'returncode':0})
 save(out/'BUNDLE-SMOKE.json',{'runtime':'Linux_Python3.13','repository_PYTHONPATH_removed':True,'tests':smoke,'windows_CMD_or_picker_tested':False})
 w.check();reg=json.loads((out/'regression-188/TEST-RESULTS.json').read_text());b.need(reg['tests_run']==188 and reg['failures']==reg['errors']==reg['skipped']==0,'review_regression_result')
 names=['local_update_review.py','local_review_launcher.py','RUN-LOCAL-REVIEW.cmd','build_update_plan.py','local_review_tests/fixtures.py','local_review_tests/test_local_update_review.py',str(Path(__file__).resolve().relative_to(LAB))]
 result={'format':'fresh-local-review-test-results-1','tests_run':237,'prior_tests_rerun':188,'new_local_review_tests':49,'failures':0,'errors':0,'skipped':0,
         'fresh_review_real_payloads':2,'saved_database_and_required_set_are_synthetic':True,'real_user_lab_tested':False,
         'complete_target_download_manifest_available':False,'installed_build_detected':False,
         'all_supplied_input_fingerprints_unchanged':True,'no_game_or_input_writes':True,'network_requests':0,
         'generic_patch_execution_or_network_downloader_added':False,'multiple_real_targets_updated_in_game':False,
         'windows_or_power_loss_tested':False,'historical_814_suite_rerun':False,'installation_ready':False,
         'standalone_bundle_CLI_modes_passed':2,'bundle_sha256':hashlib.sha256(package.read_bytes()).hexdigest(),'bundle_bytes':package.stat().st_size,
         'sources_sha256':{n:hashlib.sha256((LAB/n).read_bytes()).hexdigest() for n in names},
         'artifacts_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.iterdir()) if p.is_file() and p!=package}}
 save(out/'TEST-RESULTS.json',result);return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('workspace-template','snapshot-cycle-template','direct-cycle-template','real-payload-fixture','portable','insert-oracle','out-new'):p.add_argument('--'+n,type=Path,required=True)
 x=p.parse_args();r=run(x);print(json.dumps({k:r[k] for k in ('tests_run','failures','errors','skipped','bundle_bytes','installation_ready')},indent=2))
