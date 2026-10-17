"""CLI smoke + all 144 available tests; no new network or game discovery.
Use prepared owned templates. init separately verifies the full Portable bundle.
"""
import argparse,hashlib,json,os,re,shutil,subprocess,sys
from pathlib import Path
import patch_audit as a
import retail_sample_updater as app
import retail_storage_poc as safety
import source_binding as b
LAB=Path(__file__).resolve().parents[2]
def save(path,obj):path.write_text(json.dumps(obj,indent=2)+'\n')
def run(template,snapshot_template,direct_template,payload,insert_oracle,out):
 template,origin,oracles,_=app._load(template);snapshot_template=b.safe(snapshot_template);direct_template=b.safe(direct_template);payload=b.safe(payload);out=safety.safe_new(out)
 a.require(all(p not in out.parents for p in (template,snapshot_template,direct_template,payload,Path(origin['portable_root']))),'sample_evidence_inside_input')
 watch=b.Watch()
 for folder in (template,snapshot_template,direct_template,payload):
  for p in folder.rglob('*'):
   if p.is_file():watch.file(p)
 out.mkdir();smoke=out/'smoke-workspace';shutil.copytree(template,smoke)
 save(out/'INPUT-PROOF.json',origin);workflow=[]
 for mode,extra in [('plan',[]),('update',[]),('status',[]),('export',['--out-new',str(out/'smoke-target.decoded')]),('update',[])]:
  proc=subprocess.run([sys.executable,'-B',str(LAB/'retail_sample_updater.py'),mode,'--workspace',str(smoke),*extra],cwd=LAB,env=dict(os.environ,PYTHONPATH=str(LAB)),capture_output=True,text=True,timeout=30)
  a.require(proc.returncode==0 and not proc.stderr,'sample_smoke_cli_failed');result=json.loads(proc.stdout);workflow.append({'command':mode,'exit_code':0,'result':result})
 a.require(workflow[-1]['result']['idempotent_noop'],'sample_smoke_noop');save(out/'CLI-WORKFLOW.json',workflow)
 env=dict(os.environ,PYTHONPATH=str(LAB),BIND_ORACLE=str(oracles[0]),LOOKUP_ORACLE=str(oracles[1]),SPAN_ORACLE=str(oracles[2]),DIRECT_ORACLE=str(oracles[3]),ARCHIVE_INSERT_ORACLE=str(insert_oracle),RETAIL_INSERT_FIXTURE=str(payload),RETAIL_INSERT_CYCLE_TEMPLATE=str(snapshot_template),RETAIL_DIRECT_CYCLE_TEMPLATE=str(direct_template),SAMPLE_UPDATER_TEMPLATE=str(template),INSERT_CYCLE_RECOVERY_REPORT=str(out/'RECOVERY-SNAPSHOT.json'),DIRECT_CYCLE_RECOVERY_REPORT=str(out/'RECOVERY-DIRECT.json'),SAMPLE_UPDATER_RECOVERY_REPORT=str(out/'RECOVERY-CLI.json'))
 proc=subprocess.run([sys.executable,'-B','-m','unittest','discover','-s','tests','-p','test_*.py','-v'],cwd=LAB,env=env,capture_output=True,text=True,timeout=300)
 log=proc.stdout+proc.stderr;(out/'TESTS.log').write_text(log);a.require(proc.returncode==0 and log.rstrip().endswith('OK') and re.findall(r'Ran (\d+) tests',log)==['144'],'sample_full_test_failure')
 for name in ('RECOVERY-SNAPSHOT.json','RECOVERY-DIRECT.json','RECOVERY-CLI.json'):
  rows=json.loads((out/name).read_text());a.require(len(rows)==9,'sample_recovery_missing')
  if name=='RECOVERY-CLI.json':a.require(all(r['cli_resume_committed'] and r['repeat_update_nonmutating_noop'] and r['exported_sha256']==app.encoding.TARGET_SHA256 for r in rows),'sample_cli_recovery_failed')
 watch.check();export=out/'smoke-target.decoded';a.require(a.sha256(export.read_bytes())==app.encoding.TARGET_SHA256,'sample_smoke_export_identity')
 sources=['retail_sample_updater.py','tests/test_retail_sample_updater.py',str(Path(__file__).resolve().relative_to(LAB))]
 result={'format':'retail-sample-updater-test-results-1','profile':'offline-single-pinned-retail-pair','tests_run':144,'failures':0,'errors':0,'skipped':0,'prior_117_tests_rerun':True,'new_sample_app_tests':27,'cli_process_stop_recoveries':9,'direct_cycle_process_stop_recoveries':9,'snapshot_regression_recoveries':9,'cli_commands_smoke_tested':['plan','update','status','export','update_noop'],'runner_requires_preinitialized_workspace':True,'full_portable_verification_at_init':True,'encoding_not_rehashed_by_runner':True,'export_bytes':export.stat().st_size,'export_sha256':a.sha256(export.read_bytes()),'export_ckey':a.md5(export.read_bytes()),'export_read_from_live_committed_cycle':True,'template_and_prior_fixtures_unchanged':True,'network_download_supported':False,'network_requests':0,'full_build_or_multiple_payloads_tested':False,'windows_or_power_loss_tested':False,'historical_814_test_suite_rerun':False,'installation_ready':False,'sources_sha256':{n:hashlib.sha256((LAB/n).read_bytes()).hexdigest() for n in sources},'artifacts_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.iterdir()) if p.is_file() and p.name!='smoke-target.decoded'}}
 save(out/'TEST-RESULTS.json',result);return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('workspace-template','snapshot-cycle-template','direct-cycle-template','real-payload-fixture','insert-oracle','out-new'):p.add_argument('--'+name,type=Path,required=True)
 x=p.parse_args();r=run(x.workspace_template,x.snapshot_cycle_template,x.direct_cycle_template,x.real_payload_fixture,x.insert_oracle,x.out_new);print(json.dumps({k:r[k] for k in ('tests_run','failures','errors','export_bytes','network_download_supported','installation_ready')},indent=2))
