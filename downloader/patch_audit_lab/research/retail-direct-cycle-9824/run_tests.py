"""Reproduce all 117 available insert/direct tests into a NEW owned evidence root."""
import argparse,hashlib,json,os,re,shutil,subprocess,sys
from pathlib import Path
import patch_audit as a
import retail_direct_cycle as direct
import retail_insert_cycle as snapshot
import retail_storage_poc as safety
import source_binding as b
LAB=Path(__file__).resolve().parents[2]
def save(path,obj):path.write_text(json.dumps(obj,indent=2)+'\n')
def run(prior,payload,out,oracles,insert_oracle):
 direct.identities(*oracles);snapshot.identities(*oracles[:3],insert_oracle)
 prior=b.safe(prior);payload=b.safe(payload);out=safety.safe_new(out)
 a.require(all(p not in out.parents for p in (prior,payload)),'direct_evidence_inside_input')
 watch=b.Watch()
 for folder in (prior,payload):
  for p in folder.iterdir():watch.file(p)
 out.mkdir();old_template=out/'snapshot-template';template=out/'direct-template'
 snapshot.create(prior,old_template,*oracles[:3],insert_oracle);initial=direct.create(prior,template,*oracles);save(out/'INITIAL.json',initial)
 for folder in (old_template,template):
  for p in folder.iterdir():watch.file(p)
 normal=out/'normal';shutil.copytree(template,normal);save(out/'COMMITTED.json',direct.advance(normal,*oracles))
 unchanged=b.Watch()
 for p in normal.iterdir():unchanged.file(p)
 noop=direct.advance(normal,*oracles);a.require(noop['idempotent_noop'],'direct_final_noop');unchanged.check();save(out/'NOOP.json',noop)
 env=dict(os.environ,PYTHONPATH=str(LAB),BIND_ORACLE=str(oracles[0]),LOOKUP_ORACLE=str(oracles[1]),SPAN_ORACLE=str(oracles[2]),DIRECT_ORACLE=str(oracles[3]),ARCHIVE_INSERT_ORACLE=str(insert_oracle),RETAIL_INSERT_FIXTURE=str(payload),RETAIL_INSERT_CYCLE_TEMPLATE=str(old_template),RETAIL_DIRECT_CYCLE_TEMPLATE=str(template),INSERT_CYCLE_RECOVERY_REPORT=str(out/'RECOVERY-SNAPSHOT-REGRESSION.json'),DIRECT_CYCLE_RECOVERY_REPORT=str(out/'RECOVERY-DIRECT.json'))
 proc=subprocess.run([sys.executable,'-B','-m','unittest','discover','-s','tests','-p','test_*insert*.py','-v'],cwd=LAB,env=env,capture_output=True,text=True,timeout=240)
 log=proc.stdout+proc.stderr;(out/'TESTS.log').write_text(log);a.require(proc.returncode==0 and log.rstrip().endswith('OK') and re.findall(r'Ran (\d+) tests',log)==['117'],'direct_test_failure')
 for name in ('RECOVERY-DIRECT.json','RECOVERY-SNAPSHOT-REGRESSION.json'):
  rows=json.loads((out/name).read_text());a.require(len(rows)==9 and all(r['child_exit']==91 and r['resumed_committed'] and r['idempotent_noop_after_resume'] for r in rows),'direct_recovery_failure')
  if name=='RECOVERY-DIRECT.json':a.require(all(r['native_io_on_locked_live_archive'] and r['snapshots_created']==0 for r in rows),'direct_recovery_snapshot_forbidden')
 watch.check();shutil.copy(oracles[3].parent/'BUILD-RECEIPT.json',out/'DIRECT-BUILD-RECEIPT.json')
 sources=['owned_v8_lock.py','agent_archive_direct.py','retail_direct_cycle.py','retail_v8_cycle.py','tests/test_agent_direct_insert.py','tests/test_retail_direct_insert_cycle.py','research/archive-direct-9824/native/build.py','research/archive-direct-9824/native/harness.s',str(Path(__file__).resolve().relative_to(LAB))]
 result={'format':'retail-live-direct-cycle-tests-1','tests_run':117,'failures':0,'errors':0,'skipped':0,'prior_73_tests_rerun':True,'new_direct_cycle_tests':24,'new_direct_boundary_tests':20,'direct_process_stop_recoveries':9,'snapshot_regression_recoveries':9,'live_inode_not_copy':True,'read_only_fd_checked_by_host_and_native':True,'createfile_adapter_is_dup_not_windows_open':True,'locked_fd_inherited_by_native_child':True,'new_markers_or_snapshots_created_by_direct_gate':0,'normal_publish_then_noop_verified':True,'prior_payload_and_templates_unchanged':True,'scope':'one pinned real Retail pair in strict owned Linux V8 fixture','power_loss_or_windows_tested':False,'historical_814_test_suite_rerun':False,'installation_ready':False,'sources_sha256':{n:hashlib.sha256((LAB/n).read_bytes()).hexdigest() for n in sources},'artifacts_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.iterdir()) if p.is_file()}}
 save(out/'TEST-RESULTS.json',result);return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('prior-owned-cycle','real-payload-fixture','out-new','bind-oracle','lookup-oracle','span-oracle','direct-oracle','insert-oracle'):p.add_argument('--'+name,type=Path,required=True)
 x=p.parse_args();r=run(x.prior_owned_cycle,x.real_payload_fixture,x.out_new,[x.bind_oracle,x.lookup_oracle,x.span_oracle,x.direct_oracle],x.insert_oracle);print(json.dumps({k:r[k] for k in ('tests_run','failures','errors','direct_process_stop_recoveries','installation_ready')},indent=2))
