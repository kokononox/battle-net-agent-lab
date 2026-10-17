"""Pinned model: raw identity/header/catalogue checks; 366 baseline +98 scope tests.
All input game/Lab/Download fixtures synthetic or owned; no actual user Lab.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,subprocess,sys,zipfile
import source_binding as b
import saved_scope_review as s
LAB=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(LAB/'local_review_tests'))
from fixtures import Fixture,contents

def save(p,q):p.write_text(json.dumps(q,indent=2)+'\n')
def run(x):
 out=Path(x.out_new).resolve();b.need(not out.exists(),'new_evidence_required');out.mkdir()
 portable=b.safe(x.portable);audit=portable/'pinned_metadata';source=b.safe(x.source_archive,True)
 prior=b.safe(x.regression_results,True);reg=json.loads(prior.read_text())
 b.need(reg['tests_run']==366 and reg['failures']==reg['errors']==reg['skipped']==0,'prior_regression_failed')
 for n,h in reg['sources_sha256'].items():b.need(hashlib.sha256((LAB/n).read_bytes()).hexdigest()==h,'prior_source_changed')
 env=dict(os.environ,PYTHONPATH=str(LAB),SCOPE_PORTABLE=str(portable),SCOPE_SOURCE_ARCHIVE=str(source))
 proc=subprocess.run([sys.executable,'-B','-m','unittest','discover','-s','scope_review_tests','-v'],cwd=LAB,env=env,capture_output=True,text=True,timeout=120)
 log=proc.stdout+proc.stderr;(out/'SCOPE-TESTS.log').write_text(log)
 b.need(proc.returncode==0 and re.findall(r'Ran (\d+) tests',log)==['98'] and log.rstrip().endswith('OK') and 'ResourceWarning' not in log,'scope_tests_failed')
 names=('saved_scope_review.py','pinned_download_model.py','saved_scope_launcher.py','CHECK-SAVED-SCOPE.cmd','installed_profile_probe.py','source_binding.py','patch_audit.py','cdn_catalog.py')
 files={n:(LAB/n).read_bytes() for n in names}
 files['CHECK-SAVED-SCOPE.cmd']=files['CHECK-SAVED-SCOPE.cmd'].replace(b'\r\n',b'\n').replace(b'\n',b'\r\n')
 for n in ('build.config',*(f'manifest.pa.base64.part{i}' for i in range(3))):files['pinned_metadata/'+n]=(audit/n).read_bytes()
 files['README-fa.md']=(LAB/'research/saved-scope-pinned-model-9824/README-fa.md').read_bytes()
 m={'format':'readonly-saved-scope-bundle-4','version':s.VERSION,'archive_payload_budget_bytes':0,
    'saved_download_metadata_max_bytes':s.MAX_MANIFEST,'raw_metadata_checksums_include_padding':True,
    'native_Windows_execution_tested':False,'files':{n:{'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()} for n,v in files.items()}}
 files['BUNDLE-MANIFEST.json']=(json.dumps(m,indent=2)+'\n').encode();bundle=out/'Saved-Scope-Review-v4.zip'
 with zipfile.ZipFile(bundle,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
  for n,v in sorted(files.items()):z.writestr('Saved-Scope-Review-v4/'+n,v)
 with zipfile.ZipFile(bundle) as z:
  b.need(set(z.namelist())=={'Saved-Scope-Review-v4/'+n for n in files},'bundle_members');z.extractall(out/'isolated')
 root=out/'isolated/Saved-Scope-Review-v4'
 for n,v in files.items():b.need((root/n).read_bytes()==v,'bundle_bytes')
 iso=dict(os.environ);iso.pop('PYTHONPATH',None)
 # Isolated real-pinned-config / synthetic saved Lab, with no Download cache.
 w=b.Watch();metadata=b.load_metadata(audit,w);raw=w.read(audit/'build.config');key=hashlib.md5(raw).hexdigest()
 game=out/'synthetic-game';cfg=game/'Data/config'/key[:2]/key[2:4]/key;cfg.parent.mkdir(parents=True);cfg.write_bytes(raw)
 (game/'.build.info').write_text('Active|BuildKey|Version|Tags|Product|KeyRing\n1|'+key+'|12.1.5.70391|Windows x86_64 EU enUS? acct-PRIVATE? geoip-PRIVATE?|wow|PRIVATE_KEYRING\n')
 froot=out/'synthetic-Lab';froot.mkdir();f=Fixture(froot,metadata[2],source.read_bytes());f.storage.rename(game/'Data/data');f.storage=game/'Data/data';f.archive=f.storage/'data.000'
 f.edit(f.ev,'UPDATE evidence SET source_path=?',(str(f.archive),));f.refresh_snapshot();before=(contents(f.lab),contents(game))
 args=[sys.executable,'-B',str(root/'saved_scope_review.py'),'--lab',str(f.lab),'--audit-dir',str(root/'pinned_metadata'),'--game-root',str(game),'--out-new',str(out/'isolated-report')]
 proc=subprocess.run(args,cwd=root,env=iso,capture_output=True,text=True,timeout=120);q=json.loads(proc.stdout)
 b.need(proc.returncode==0 and not proc.stderr and q['status']=='bound_download_metadata_unavailable' and q['scope_review_version']=='saved-scope-review-4','isolated_cli')
 b.need(json.loads((out/'isolated-report/SCOPE-REVIEW-to-share.json').read_text())==q,'isolated_report')
 b.need('PRIVATE' not in proc.stdout and str(out) not in proc.stdout and q['scope']['archive_payload_bytes_read']==0 and before==(contents(f.lab),contents(game)),'isolated_privacy_or_mutation')
 save(out/'ISOLATED-SUMMARY.json',{'runtime':'Linux_Python3.13','repository_PYTHONPATH_removed':True,'input_kind':'synthetic_Lab_game;real_pinned_config','missing_metadata_remains_unknown':True,'archive_payload_bytes_read':0,'inputs_unchanged':True,'native_Windows_execution':False})
 # Stream same-shape synthetic 2,881,619 records + all31 tags + padding SET.
 # Test model overrides cryptographic identities ONLY in this synthetic test.
 # Repeated EKeys intentional; only record selection, no unique-object claim.
 import pinned_download_model as pin
 n=2_881_619;width=(n+7)//8;pad=(-n)%8;tags=pin.PINNED_MODEL.tags
 stress=out/'synthetic-padded-download.metadata';record=b'\x01'*16+(7).to_bytes(5,'big')+b'\x02'
 with stress.open('xb') as dst:
  dst.write(b'DL\x01\x10\0'+n.to_bytes(4,'big')+len(tags).to_bytes(2,'big'))
  block=record*4096
  for _ in range(n//4096):dst.write(block)
  dst.write(record*(n%4096))
  for name,kind in tags:dst.write(name.encode()+b'\0'+kind.to_bytes(2,'big')+b'\xff'*width)
 code="""import sys,time,json,hashlib,resource
from dataclasses import replace
import pinned_download_model as m
from pathlib import Path
import saved_scope_review as s
p=Path(sys.argv[1]);t=time.monotonic();md5=hashlib.md5();sha=hashlib.sha256()
with p.open('rb') as f:
 while raw:=f.read(1024**2):md5.update(raw);sha.update(raw)
synthetic=replace(m.PINNED_MODEL,identity='synthetic-same-shape-NOT-user-manifest',ckey=md5.hexdigest(),sha256=sha.hexdigest())
with p.open('rb') as f:
 r=s.ManifestReader(f,p.stat().st_size,lambda:None)
 q=s.parse_manifest(r,{'platform':'Windows','architecture':'x86_64','region':'EU','locales':['enUS']},observe_unresolved=True,pinned_model=synthetic)
h=hashlib.md5()
with p.open('rb') as f:
 while raw:=f.read(1024**2):h.update(raw)
assert r.md5.hexdigest()==h.hexdigest()
try:
 with p.open('rb') as f:
  rr=s.ManifestReader(f,p.stat().st_size,lambda:None)
  s.parse_manifest(rr,{'platform':'Windows','architecture':'x86_64','region':'EU','locales':['enUS']},observe_unresolved=True,pinned_model=m.PINNED_MODEL)
except s.b.BindingError as ex:
 assert str(ex)=='pinned_model_ckey_mismatch'
else:raise AssertionError('production pin accepted same-shape synthetic bytes')
print(json.dumps({'records':q['manifest_records'],'selected_records':q['diagnostic_selected_records'],'model_supported':q['selection_model_supported'],'blockers':q['tag_schema']['blockers'],'observed_tags':len(q['tag_schema']['observed_tags']),'pinned_model_verified':q['pinned_tag_model']['raw_identity_header_and_ordered_catalogue_revalidated'],'production_pin_rejected_same_shape_synthetic_ckey':True,'additional_production_pin_rejection_pass':True,'synthetic_model_identity':synthetic.identity,'padding_bits_per_bitmap':q['unused_padding_bits_per_bitmap'],'tags_with_nonzero_padding':q['tags_with_nonzero_unused_padding_bits'],'nonzero_padding_bits_ignored':q['nonzero_unused_padding_bits_ignored'],'raw_checksum_includes_padding':True,'parser_metadata_bytes_read':r.used,'extra_independent_test_hash_pass':True,'elapsed_seconds':round(time.monotonic()-t,3),'process_peak_rss_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'synthetic_repeated_ekeys':True,'unique_objects_computed':False,'archive_payload_bytes_read':0,'runtime':'Linux_Python3.13'}))
"""
 proc=subprocess.run([sys.executable,'-B','-c',code,str(stress)],cwd=root,env=iso,capture_output=True,text=True,timeout=120);big=json.loads(proc.stdout)
 b.need(proc.returncode==0 and not proc.stderr and big['records']==n and big['selected_records']==n and big['model_supported'] is True and big['observed_tags']==31 and big['pinned_model_verified'] is True and big['nonzero_padding_bits_ignored']==pad*len(tags),'large_padding_test')
 save(out/'LARGE-PINNED-MODEL-SUMMARY.json',big);w.check()
 sourcenames=['saved_scope_review.py','pinned_download_model.py','scope_review_tests/test_pinned_download_model.py','scope_review_tests/test_saved_scope_review.py','scope_review_tests/test_tag_observation.py','research/saved-scope-pinned-model-9824/README-fa.md',str(Path(__file__).resolve().relative_to(LAB))]
 q={'format':'saved-scope-pinned-model-test-results-1','version':s.VERSION,'tests_run':464,'prior_tests_rerun':366,'current_scope_tests':98,
    'prior_scope_test_count':72,'additional_scope_tests':26,'generic_unknown_schema_still_produces_no_record_selection':True,'actual_pinned_target_manifest_executed_here':False,'generic_whitelists_not_expanded':True,'pinned_raw_MD5_SHA256_size_header_ordered_catalogue_all_required':True,'optional_and_kind5_tags_not_used_for_exclusion':True,'independent_random_mask_oracle_cases':64,
    'failures':0,'errors':0,'skipped':0,'baseline_runner_unmodified':True,'baseline_report_sha256':hashlib.sha256(prior.read_bytes()).hexdigest(),
    'raw_padding_preserved_in_MD5_and_SHA256':True,'padding_only_mutation_still_rejected_by_expected_CKey':True,
    'unknown_tag_or_kind_blocks_selection_but_allows_CKey_verified_schema_observation':True,'unknown_binary_versions_still_rejected':True,'new_tool_archive_payload_bytes_read':0,'network_requests':0,
    'game_or_user_Lab_modified':False,'actual_user_Lab_or_target_Download_tested':False,'native_Windows_execution_tested':False,
    'Windows_no_replace_contract_modeled_on_Linux':True,'synthetic_large_manifest_records':n,'installation_ready':False,
    'required_network_download_bytes':None,'bundle_bytes':bundle.stat().st_size,'bundle_sha256':hashlib.sha256(bundle.read_bytes()).hexdigest(),
    'sources_sha256':{n:hashlib.sha256((LAB/n).read_bytes()).hexdigest() for n in sourcenames},
    'artifacts_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file() and p!=stress}}
 save(out/'TEST-RESULTS.json',q);return q
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('portable','source-archive','regression-results','out-new'):p.add_argument('--'+name,type=Path,required=True)
 q=run(p.parse_args());print(json.dumps({k:q[k] for k in ('tests_run','failures','errors','bundle_bytes','installation_ready')},indent=2))
