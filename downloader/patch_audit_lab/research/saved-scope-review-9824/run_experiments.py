"""Build/test saved-scope diagnostic. All fixtures synthetic/owned, NEVER user Lab.
Run after unmodified prior 366-test runner; verify its current source hashes.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,subprocess,sys,time,zipfile
import source_binding as b
import saved_scope_review as scope
LAB=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(LAB/'local_review_tests'))
from fixtures import Fixture,contents

def save(path,q):path.write_text(json.dumps(q,indent=2)+'\n')
def run(x):
    out=Path(x.out_new).resolve();b.need(not out.exists(),'scope_new_evidence_required');out.mkdir()
    portable=b.safe(x.portable);audit=portable/'pinned_metadata';source=b.safe(x.source_archive,True)
    reg_path=b.safe(x.regression_results,True);reg=json.loads(reg_path.read_text())
    b.need(reg['tests_run']==366 and reg['failures']==reg['errors']==reg['skipped']==0,'scope_prior_test_result_invalid')
    for name,digest in reg['sources_sha256'].items():b.need(hashlib.sha256((LAB/name).read_bytes()).hexdigest()==digest,'scope_prior_source_changed')
    env=dict(os.environ,PYTHONPATH=str(LAB),SCOPE_PORTABLE=str(portable),SCOPE_SOURCE_ARCHIVE=str(source))
    proc=subprocess.run([sys.executable,'-B','-m','unittest','discover','-s','scope_review_tests','-v'],env=env,cwd=LAB,capture_output=True,text=True,timeout=120)
    log=proc.stdout+proc.stderr;(out/'SCOPE-TESTS.log').write_text(log)
    b.need(proc.returncode==0 and re.findall(r'Ran (\d+) tests',log)==['53'] and log.rstrip().endswith('OK') and 'ResourceWarning' not in log,'scope_new_tests_failed')
    # No previous tools modified. Build only the dependency whitelist.
    names=('saved_scope_review.py','saved_scope_launcher.py','CHECK-SAVED-SCOPE.cmd',
           'installed_profile_probe.py','source_binding.py','patch_audit.py','cdn_catalog.py')
    files={n:(LAB/n).read_bytes() for n in names}
    files['CHECK-SAVED-SCOPE.cmd']=files['CHECK-SAVED-SCOPE.cmd'].replace(b'\r\n',b'\n').replace(b'\n',b'\r\n')
    for name in ('build.config',*(f'manifest.pa.base64.part{i}' for i in range(3))):files['pinned_metadata/'+name]=(audit/name).read_bytes()
    files['README-fa.md']=(LAB/'research/saved-scope-review-9824/README-fa.md').read_bytes()
    manifest={'format':'readonly-saved-scope-bundle-1','version':scope.VERSION,'Python_requires':'3.10+',
         'archive_payload_budget_bytes':0,'saved_decoded_download_metadata_max_bytes':scope.MAX_MANIFEST,
         'no_Agent_game_payload_or_credentials_bundled':True,'network_functions_invoked':False,
         'native_Windows_execution_tested':False,
         'files':{n:{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} for n,raw in files.items()}}
    files['BUNDLE-MANIFEST.json']=(json.dumps(manifest,indent=2)+'\n').encode()
    bundle=out/'Saved-Scope-Review.zip'
    with zipfile.ZipFile(bundle,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,raw in sorted(files.items()):z.writestr('Saved-Scope-Review/'+name,raw)
    with zipfile.ZipFile(bundle) as z:
        b.need(set(z.namelist())=={'Saved-Scope-Review/'+n for n in files},'scope_bundle_members');z.extractall(out/'isolated-bundle')
    root=out/'isolated-bundle/Saved-Scope-Review'
    for name,raw in files.items():b.need((root/name).read_bytes()==raw,'scope_bundle_bytes')
    # Real pinned config/audit, SYNTHETIC .build.info/Lab/storage. Exact decoded
    # Download is deliberately absent; no target-manifest identity fabricated.
    w=b.Watch();metadata=b.load_metadata(audit,w);raw=w.read(audit/'build.config');key=hashlib.md5(raw).hexdigest()
    game=out/'synthetic-game';cfg=game/'Data/config'/key[:2]/key[2:4]/key;cfg.parent.mkdir(parents=True);cfg.write_bytes(raw)
    (game/'.build.info').write_text('Active|BuildKey|Version|Tags|Product|KeyRing\n1|'+key+'|12.1.5.70391|Windows x86_64 EU enUS? acct-PRIVATE_ACCOUNT? geoip-PRIVATE_GEO?|wow|PRIVATE_KEYRING\n')
    fixture_dir=out/'synthetic-Lab-input';fixture_dir.mkdir();f=Fixture(fixture_dir,metadata[2],source.read_bytes())
    f.storage.rename(game/'Data/data');f.storage=game/'Data/data';f.archive=f.storage/'data.000';f.edit(f.ev,'UPDATE evidence SET source_path=?',(str(f.archive),));f.refresh_snapshot()
    before={**contents(f.lab),**{'game/'+n:v for n,v in contents(game).items()}}
    isolated=dict(os.environ);isolated.pop('PYTHONPATH',None)
    args=[sys.executable,'-B',str(root/'saved_scope_review.py'),'--lab',str(f.lab),'--audit-dir',str(root/'pinned_metadata'),'--game-root',str(game),'--out-new',str(out/'isolated-report')]
    proc=subprocess.run(args,cwd=root,env=isolated,capture_output=True,text=True,timeout=120);q=json.loads(proc.stdout)
    b.need(proc.returncode==0 and not proc.stderr and q['status']=='bound_download_metadata_unavailable' and q['selected_game_matches_saved_snapshot_storage'] is True,'scope_isolated_cli')
    b.need(json.loads((out/'isolated-report/SCOPE-REVIEW-to-share.json').read_text())==q,'scope_isolated_publish')
    b.need('PRIVATE' not in proc.stdout and str(out) not in proc.stdout and q['scope']['archive_payload_bytes_read']==0,'scope_isolated_privacy')
    b.need(before=={**contents(f.lab),**{'game/'+n:v for n,v in contents(game).items()}},'scope_isolated_inputs_changed')
    save(out/'ISOLATED-SUMMARY.json',{'runtime':'Linux_Python3.13','PYTHONPATH_removed':True,'input_kind':'synthetic_Lab_storage_build_info;real_pinned_config_and_audit',
        'status':q['status'],'selected_game_matches_saved_snapshot_storage':True,'exact_saved_decoded_download_unavailable_not_game_corruption':True,
        'archive_payload_bytes_read':0,'source_fingerprints_and_bytes_unchanged':True,'native_Windows_execution':False})
    # Model a large manifest with the real observed number of RECORDS. Repeated
    # EKeys intentional: this verifies bit counts, NOT unique-object consistency.
    n=2_881_619;width=(n+7)//8;padding=width*8-n;valid=((1<<n)-1)<<padding
    stress=out/'synthetic-large-download.metadata';record=b'\x01'*16+(7).to_bytes(5,'big')+b'\x02'+bytes(3)
    tags=[('Windows',1,valid),('x86_64',2,valid),('enUS',3,valid),('EU',4,valid),('code',0,valid)]
    with stress.open('xb') as dst:
        dst.write(b'DL\x03\x10\x00'+n.to_bytes(4,'big')+len(tags).to_bytes(2,'big')+b'\x03'+bytes(4))
        block=record*4096
        for _ in range(n//4096):dst.write(block)
        dst.write(record*(n%4096))
        for name,kind,mask in tags:dst.write(name.encode()+b'\0'+kind.to_bytes(2,'big')+mask.to_bytes(width,'big'))
    code="""import sys,time,json,resource
from pathlib import Path
import saved_scope_review as s
p=Path(sys.argv[1]);t=time.monotonic()
with p.open('rb') as f:
 r=s.ManifestReader(f,p.stat().st_size,lambda:None)
 q=s.parse_manifest(r,{'platform':'Windows','architecture':'x86_64','region':'EU','locales':['enUS']})
print(json.dumps({'records':q['manifest_records'],'selected_records':q['diagnostic_selected_records'],'metadata_bytes_read':r.used,'elapsed_seconds':round(time.monotonic()-t,3),'process_peak_rss_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'unique_objects_computed':False,'synthetic_repeated_ekeys':True,'archive_payload_bytes_read':0,'runtime':'Linux_Python3.13'}))
"""
    proc=subprocess.run([sys.executable,'-B','-c',code,str(stress)],cwd=root,env=isolated,capture_output=True,text=True,timeout=120)
    big=json.loads(proc.stdout);b.need(proc.returncode==0 and not proc.stderr and big['records']==big['selected_records']==n and big['metadata_bytes_read']==stress.stat().st_size,'scope_large_metadata_test')
    save(out/'LARGE-METADATA-SUMMARY.json',big);w.check()
    source_names=[*names,'scope_review_tests/test_saved_scope_review.py','research/saved-scope-review-9824/README-fa.md',str(Path(__file__).resolve().relative_to(LAB))]
    report={'format':'saved-scope-test-results-1','scope_review_version':scope.VERSION,'tests_run':419,'prior_tests_rerun':366,'new_tests':53,
        'failures':0,'errors':0,'skipped':0,'prior_regression_report_sha256':hashlib.sha256(reg_path.read_bytes()).hexdigest(),
        'prior_regression_source_hashes_checked':True,'previous_366_runner_used_unmodified':True,
        'new_tool_archive_payload_reads':0,'network_requests':0,'game_or_user_Lab_writes':False,
        'actual_user_Lab_or_target_Download_manifest_tested':False,'native_Windows_execution_tested':False,
        'Windows_no_replace_contract_modeled_on_Linux':True,'isolated_bundle_CLI_missing_metadata_mode_passed':True,
        'synthetic_large_manifest_records':n,'synthetic_parser_and_projection_tests_passed':True,
        'actual_required_install_set_known':False,'required_network_download_bytes':None,'installation_ready':False,
        'bundle_bytes':bundle.stat().st_size,'bundle_sha256':hashlib.sha256(bundle.read_bytes()).hexdigest(),
        'sources_sha256':{n:hashlib.sha256((LAB/n).read_bytes()).hexdigest() for n in source_names},
        'artifacts_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file() and p!=stress}}
    save(out/'TEST-RESULTS.json',report);return report
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('portable','source-archive','regression-results','out-new'):p.add_argument('--'+name,type=Path,required=True)
    q=run(p.parse_args());print(json.dumps({k:q[k] for k in ('tests_run','failures','errors','bundle_bytes','installation_ready')},indent=2))
