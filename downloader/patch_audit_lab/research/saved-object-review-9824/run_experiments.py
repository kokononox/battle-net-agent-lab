"""Build and test saved-object-review-1; baseline366 + scope98 + object63.
Synthetic fixtures only; raw user Download and native Windows NOT executed.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,subprocess,sys,zipfile
import source_binding as b
import saved_object_review as o
import saved_scope_review as s
LAB=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(LAB/'local_review_tests'))
from fixtures import Fixture,contents

def save(path,obj):path.write_text(json.dumps(obj,indent=2)+'\n')
def run(x):
 out=Path(x.out_new).resolve();b.need(not out.exists(),'new_evidence_required');out.mkdir()
 portable=b.safe(x.portable);audit=portable/'pinned_metadata';source=b.safe(x.source_archive,True)
 prior=b.safe(x.regression_results,True);reg=json.loads(prior.read_text())
 b.need(reg['tests_run']==366 and reg['failures']==reg['errors']==reg['skipped']==0,'prior_regression_failed')
 for name,digest in reg['sources_sha256'].items():b.need(hashlib.sha256((LAB/name).read_bytes()).hexdigest()==digest,'prior_source_changed')
 env=dict(os.environ,PYTHONPATH=str(LAB),SCOPE_PORTABLE=str(portable),SCOPE_SOURCE_ARCHIVE=str(source))
 for directory,expected,logname in [('scope_review_tests',98,'SCOPE-TESTS.log'),('object_review_tests',63,'OBJECT-TESTS.log')]:
  proc=subprocess.run([sys.executable,'-B','-m','unittest','discover','-s',directory,'-v'],cwd=LAB,env=env,capture_output=True,text=True,timeout=180)
  log=proc.stdout+proc.stderr;(out/logname).write_text(log)
  b.need(proc.returncode==0 and re.findall(r'Ran (\d+) tests',log)==[str(expected)] and log.rstrip().endswith('OK') and 'ResourceWarning' not in log,'object_or_scope_tests_failed')
 names=('saved_object_review.py','saved_object_launcher.py','CHECK-SAVED-OBJECTS.cmd','saved_scope_review.py','pinned_download_model.py','installed_profile_probe.py','source_binding.py','patch_audit.py','cdn_catalog.py')
 files={name:(LAB/name).read_bytes() for name in names}
 name='CHECK-SAVED-OBJECTS.cmd';files[name]=files[name].replace(b'\r\n',b'\n').replace(b'\n',b'\r\n')
 for name in ('build.config',*(f'manifest.pa.base64.part{i}' for i in range(3))):files['pinned_metadata/'+name]=(audit/name).read_bytes()
 files['README-fa.md']=(LAB/'research/saved-object-review-9824/README-fa.md').read_bytes()
 manifest={'format':'readonly-saved-object-bundle-1','version':o.VERSION,'base_scope_version':s.VERSION,
  'archive_payload_budget_bytes':0,'saved_download_metadata_cumulative_max_bytes':o.MAX_METADATA_READ,
  'saved_download_max_passes':2,'private_work_database_max_bytes':o.MAX_WORK_DB_BYTES,
  'stdlib_only':True,'Python_requires':'3.10+','native_Windows_execution_tested':False,
  'files':{name:{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} for name,raw in files.items()}}
 files['BUNDLE-MANIFEST.json']=(json.dumps(manifest,indent=2)+'\n').encode()
 bundle=out/'Saved-Object-Review-v1.zip'
 with zipfile.ZipFile(bundle,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
  for name,raw in sorted(files.items()):z.writestr('Saved-Object-Review-v1/'+name,raw)
 with zipfile.ZipFile(bundle) as z:
  b.need(set(z.namelist())=={'Saved-Object-Review-v1/'+name for name in files},'object_bundle_members');z.extractall(out/'isolated')
 root=out/'isolated/Saved-Object-Review-v1'
 for name,raw in files.items():b.need((root/name).read_bytes()==raw,'object_bundle_bytes')
 iso=dict(os.environ);iso.pop('PYTHONPATH',None)
 w=b.Watch();metadata=b.load_metadata(audit,w);raw=w.read(audit/'build.config');key=hashlib.md5(raw).hexdigest()
 game=out/'synthetic-game';cfg=game/'Data/config'/key[:2]/key[2:4]/key;cfg.parent.mkdir(parents=True);cfg.write_bytes(raw)
 (game/'.build.info').write_text('Active|BuildKey|Version|Tags|Product|KeyRing\n1|'+key+'|12.1.5.70391|Windows x86_64 EU enUS? acct-PRIVATE? geoip-PRIVATE?|wow|PRIVATE_KEYRING\n')
 froot=out/'synthetic-Lab';froot.mkdir();f=Fixture(froot,metadata[2],source.read_bytes());f.storage.rename(game/'Data/data');f.storage=game/'Data/data';f.archive=f.storage/'data.000'
 f.edit(f.ev,'UPDATE evidence SET source_path=?',(str(f.archive),));f.refresh_snapshot();before=(contents(f.lab),contents(game))
 args=[sys.executable,'-B',str(root/'saved_object_review.py'),'--lab',str(f.lab),'--audit-dir',str(root/'pinned_metadata'),'--game-root',str(game),'--out-new',str(out/'isolated-report')]
 proc=subprocess.run(args,cwd=root,env=iso,capture_output=True,text=True,timeout=120);q=json.loads(proc.stdout)
 b.need(proc.returncode==0 and not proc.stderr and q['status']=='bound_download_metadata_unavailable' and q['scope_review_version']==o.VERSION,'object_isolated_cli')
 b.need(json.loads((out/'isolated-report/Report/SCOPE-REVIEW-to-share.json').read_text())==q,'object_isolated_report')
 b.need('PRIVATE' not in proc.stdout and str(out) not in proc.stdout and q['scope']['archive_payload_bytes_read']==0 and before==(contents(f.lab),contents(game)),'object_isolated_privacy_or_mutation')
 b.need(not list((out/'isolated-report').glob('private-work-*')),'object_isolated_private_work')
 save(out/'ISOLATED-SUMMARY.json',{'runtime':'Linux_Python3.13','repository_PYTHONPATH_removed':True,'input_kind':'synthetic_Lab_game;real_pinned_config;exact_Download_cache_absent','missing_metadata_remains_unknown':True,'archive_payload_bytes_read':0,'inputs_unchanged':True,'report_separate_new_output':True,'native_Windows_execution':False})
 # Stress imports runtime modules from extracted ZIP ONLY, not repository root.
 stressenv=dict(iso,PYTHONPATH=str(root))
 proc=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('stress_metadata.py')),str(out/'synthetic-stress')],cwd=root,env=stressenv,capture_output=True,text=True,timeout=650)
 (out/'STRESS-RUN.log').write_text(proc.stdout+proc.stderr)
 b.need(proc.returncode==0 and not proc.stderr,'object_large_stress_failed');big=json.loads(proc.stdout)
 b.need(big['records']==big['unique_selected_ekeys']==2_881_619 and big['production_pin_rejected_synthetic_bytes'] and big['private_work_removed'],'object_large_stress_summary')
 save(out/'LARGE-SYNTHETIC-SUMMARY.json',big);w.check()
 sourcenames=[*names,'scope_review_tests/test_pinned_download_model.py','scope_review_tests/test_saved_scope_review.py','scope_review_tests/test_tag_observation.py','object_review_tests/test_saved_object_review.py','research/saved-object-review-9824/README-fa.md','research/saved-object-review-9824/stress_metadata.py',str(Path(__file__).resolve().relative_to(LAB))]
 q={'format':'saved-object-review-test-results-1','version':o.VERSION,'tests_run':527,'prior_tests_rerun':366,'scope_tests_rerun_unmodified':98,'new_object_tests':63,
  'independent_random_dedup_oracle_cases':128,'independent_random_inventory_oracle_cases':24,'failures':0,'errors':0,'skipped':0,
  'baseline_runner_unmodified':True,'baseline_report_sha256':hashlib.sha256(prior.read_bytes()).hexdigest(),
  'private_selection_hook_only_after_supported_pinned_identity':True,'generic_whitelists_not_expanded':True,
  'raw_hash_revalidated_both_passes':True,'cumulative_metadata_budget_bytes':o.MAX_METADATA_READ,'private_work_database_max_bytes':o.MAX_WORK_DB_BYTES,
  'source_inventory_readonly_existing_index_only':True,'missing_inventory_entry_is_unknown_NOT_missing_or_corrupt':True,
  'unique_object_duplicate_size_scope':'selected_records_only','unique_encoded_size_total_computed':False,
  'archive_payload_bytes_read_by_new_tool':0,'network_requests':0,'game_or_user_Lab_modified':False,'actual_user_Lab_or_target_Download_tested':False,
  'native_Windows_execution_tested':False,'Windows_no_replace_contract_modeled_on_Linux':True,'synthetic_large_manifest_records':big['records'],
  'synthetic_large_unique_ekeys':big['unique_selected_ekeys'],'installation_ready':False,'required_network_download_bytes':None,
  'bundle_bytes':bundle.stat().st_size,'bundle_sha256':hashlib.sha256(bundle.read_bytes()).hexdigest(),
  'sources_sha256':{name:hashlib.sha256((LAB/name).read_bytes()).hexdigest() for name in sourcenames},
  'artifacts_sha256':{path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in out.iterdir() if path.is_file()}}
 save(out/'TEST-RESULTS.json',q);return q
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('portable','source-archive','regression-results','out-new'):p.add_argument('--'+name,type=Path,required=True)
 q=run(p.parse_args());print(json.dumps({k:q[k] for k in ('tests_run','failures','errors','bundle_bytes','installation_ready')},indent=2))
