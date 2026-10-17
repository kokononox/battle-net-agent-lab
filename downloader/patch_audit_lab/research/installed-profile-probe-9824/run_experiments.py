"""Rerun 319 tests + 47 two-file probe tests, build isolated small profile ZIP."""
import argparse,hashlib,json,os,re,subprocess,sys,zipfile
from pathlib import Path
import source_binding as b
import retail_storage_poc as safety
import installed_profile_probe as probe
LAB=Path(__file__).resolve().parents[2]
def save(p,q):p.write_text(json.dumps(q,indent=2)+'\n')
def run(x):
 out=safety.safe_new(x.out_new);inputs=[b.safe(getattr(x,n)) for n in ('workspace_template','snapshot_cycle_template','direct_cycle_template','real_payload_fixture','portable')]
 b.need(all(not(p==out or p in out.parents or out in p.parents) for p in inputs),'profile_evidence_overlap');out.mkdir();env=dict(os.environ,PYTHONPATH=str(LAB))
 args=[sys.executable,'-B',str(LAB/'research/safe-continuation-9824/run_experiments.py')]
 for n in ('workspace-template','snapshot-cycle-template','direct-cycle-template','real-payload-fixture','portable','insert-oracle'):args+=['--'+n,str(getattr(x,n.replace('-','_')))]
 args+=['--out-new',str(out/'regression-319')]
 proc=subprocess.run(args,cwd=LAB,env=env,capture_output=True,text=True,timeout=360)
 (out/'REGRESSION-RUN.log').write_text(proc.stdout+proc.stderr);b.need(proc.returncode==0,'profile_prior_regression_failed')
 reg=json.loads((out/'regression-319/TEST-RESULTS.json').read_text());b.need(reg['tests_run']==319 and reg['failures']==reg['errors']==reg['skipped']==0,'profile_prior_test_count')
 config=inputs[4]/'pinned_metadata/build.config';w=b.Watch();raw=w.read(config);env.update(PROBE_REAL_CONFIG=str(config))
 proc=subprocess.run([sys.executable,'-B','-m','unittest','discover','-s','profile_probe_tests','-v'],cwd=LAB,env=env,capture_output=True,text=True,timeout=120)
 log=proc.stdout+proc.stderr;(out/'PROFILE-TESTS.log').write_text(log)
 b.need(proc.returncode==0 and re.findall(r'Ran (\d+) tests',log)==['47'] and log.rstrip().endswith('OK') and 'ResourceWarning' not in log,'profile_new_tests_failed')
 files={n:(LAB/n).read_bytes() for n in ('installed_profile_probe.py','installed_profile_launcher.py','CHECK-INSTALLED-PROFILE.cmd')}
 n='CHECK-INSTALLED-PROFILE.cmd';files[n]=files[n].replace(b'\r\n',b'\n').replace(b'\n',b'\r\n')
 files['README-fa.md']=(LAB/'research/installed-profile-probe-9824/README-fa.md').read_bytes()
 manifest={'format':'readonly-two-file-profile-bundle-1','stdlib_only':True,'Python_requires':'3.10+',
           'no_game_or_config_payload_bundled':True,'no_Lab_scanner_or_downloader_modules':True,
           'native_Windows_execution_tested':False,
           'files':{n:{'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()} for n,v in files.items()}}
 files['BUNDLE-MANIFEST.json']=(json.dumps(manifest,indent=2)+'\n').encode();bundle=out/'Installed-Profile-Check.zip'
 with zipfile.ZipFile(bundle,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
  for n,v in sorted(files.items()):z.writestr('Installed-Profile-Check/'+n,v)
 with zipfile.ZipFile(bundle) as z:
  b.need(set(z.namelist())=={'Installed-Profile-Check/'+n for n in files},'profile_bundle_members');z.extractall(out/'isolated-bundle')
 root=out/'isolated-bundle/Installed-Profile-Check'
 for n,v in files.items():b.need((root/n).read_bytes()==v,'profile_bundle_identity')
 # Synthetic game root with the one real, MD5-pinned config. NOT the user game.
 game=out/'synthetic-game';game.mkdir();key=hashlib.md5(raw).hexdigest();path=game/'Data/config'/key[:2]/key[2:4]/key;path.parent.mkdir(parents=True);path.write_bytes(raw)
 info=('Active!DEC:1|Build Key!HEX:16|Version!STRING:0|Tags!STRING:0|Product!STRING:0|KeyRing!STRING:0\n1|'+key+'|12.1.5.70391|Windows x86_64 EU enUS? acct-PRIVATE_ACCOUNT? geoip-PRIVATE_LOCATION?|wow|PRIVATE_KEYRING\n').encode();(game/'.build.info').write_bytes(info)
 before={str(p):b.fp(p.stat()) for p in game.rglob('*') if p.is_file()};isolated=dict(os.environ);isolated.pop('PYTHONPATH',None)
 def cli(output=None):
  argv=[sys.executable,'-B',str(root/'installed_profile_probe.py'),'--game-root',str(game)]
  if output is not None:argv+=['--out-new',str(output)]
  return subprocess.run(argv,cwd=root,env=isolated,capture_output=True,text=True,timeout=60)
 proc=cli(out/'isolated-profile-output');q=json.loads(proc.stdout)
 b.need(proc.returncode==0 and not proc.stderr and q['profile']=={'platform':'Windows','architecture':'x86_64','region':'EU','locales':['enUS']},'profile_isolated_success')
 b.need(q['scope']['game_metadata_files_read']==2 and q['scope']['game_metadata_bytes_read']==len(info)+len(raw) and q['scope']['archive_payload_bytes_read']==0,'profile_isolated_read_limits')
 b.need(json.loads((out/'isolated-profile-output/INSTALLED-PROFILE-to-share.json').read_text())==q,'profile_isolated_published_report')
 b.need('PRIVATE_' not in proc.stdout and str(game) not in proc.stdout and before=={str(p):b.fp(p.stat()) for p in game.rglob('*') if p.is_file()},'profile_isolated_privacy_or_mutation')
 save(out/'ISOLATED-SUCCESS-SUMMARY.json',{'runtime':'Linux_Python3.13','PYTHONPATH_removed':True,'input':'synthetic_build_info_and_root;real_pinned_config_only','profile':q['profile'],'game_metadata_files_read':2,'archive_payload_bytes_read':0,'source_fingerprints_unchanged':True,'raw_paths_and_private_values_omitted':True,'native_Windows_execution':False})
 (game/'.build.info').write_bytes(info.replace(b'enUS?',b'enUS? UNKNOWN_PRIVATE_TAG?'));proc=cli();unknown=json.loads(proc.stdout)
 b.need(proc.returncode==0 and not proc.stderr and unknown['profile'] is None and unknown['profile_error']=='unknown_installed_tag_no_guess' and 'PRIVATE' not in proc.stdout,'profile_isolated_unknown')
 path.unlink();proc=cli();error=json.loads(proc.stdout)
 b.need(proc.returncode==1 and not proc.stderr and error['stage']=='read_named_build_config' and str(game) not in proc.stdout,'profile_isolated_failure')
 save(out/'ISOLATED-FAIL-CLOSED-SUMMARY.json',{'unknown_profile_status':unknown['status'],'unknown_profile_error':unknown['profile_error'],'unknown_profile_was_not_guessed':True,'missing_config_error':error,'no_scan_or_fallback':True})
 w.check();names=['installed_profile_probe.py','installed_profile_launcher.py','CHECK-INSTALLED-PROFILE.cmd','profile_probe_tests/test_installed_profile_probe.py','research/installed-profile-probe-9824/README-fa.md',str(Path(__file__).resolve().relative_to(LAB))]
 q={'format':'installed-profile-probe-test-results-1','probe_version':probe.VERSION,'tests_run':366,'prior_tests_rerun':319,'new_tests':47,'failures':0,'errors':0,'skipped':0,
    'game_content_files_allowed':2,'max_build_info_bytes':probe.MAX_INFO,'max_named_config_bytes':probe.MAX_CONFIG,'archive_payload_bytes_read':0,'archives_enumerated':False,'Lab_access_added':False,
    'read_access_authorized_by_user':True,'game_or_user_Lab_writes':False,'network_requests':0,'account_paths_keyring_or_raw_tags_exported':False,
    'actual_user_game_or_Lab_tested':False,'native_Windows_execution_tested':False,'Windows_contract_modeled_on_Linux':True,
    'isolated_CLI_modes_passed':3,'installed_profile_in_synthetic_fixture_only':True,'actual_required_install_set_known':False,'target_Download_tag_projection_computed':False,'installation_ready':False,
    'bundle_bytes':bundle.stat().st_size,'bundle_sha256':hashlib.sha256(bundle.read_bytes()).hexdigest(),
    'sources_sha256':{n:hashlib.sha256((LAB/n).read_bytes()).hexdigest() for n in names},
    'artifacts_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file() and p!=bundle}}
 save(out/'TEST-RESULTS.json',q);return q
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('workspace-template','snapshot-cycle-template','direct-cycle-template','real-payload-fixture','portable','insert-oracle','out-new'):p.add_argument('--'+n,type=Path,required=True)
 x=p.parse_args();q=run(x);print(json.dumps({k:q[k] for k in ('tests_run','failures','errors','skipped','bundle_bytes','installation_ready')},indent=2))
