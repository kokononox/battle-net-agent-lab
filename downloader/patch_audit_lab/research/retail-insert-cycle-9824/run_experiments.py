"""Reproduce gated cycle + nine process-stop recoveries on NEW owned outputs.
Requires a committed owned V7 research cycle, never an installation directory.
Use --real-payload-fixture to rerun the prior 49 insert tests as well.
"""
import argparse,hashlib,json,os,re,shutil,subprocess,sys
from pathlib import Path
import patch_audit as a
import source_binding as b
import retail_insert_cycle as cycle
import retail_storage_poc as safety

LAB=Path(__file__).resolve().parents[2]
def save(path,obj):path.write_text(json.dumps(obj,indent=2)+'\n')
def run(prior,out,oracles,real_payload_fixture=None):
 cycle.identities(*oracles);prior=b.safe(prior);out=safety.safe_new(out)
 a.require(prior not in out.parents,'insert_cycle_output_in_prior')
 watch=b.Watch()
 for p in prior.iterdir():watch.file(p)
 if real_payload_fixture is not None:
  real_payload_fixture=b.safe(real_payload_fixture)
  a.require(real_payload_fixture not in out.parents,'insert_cycle_output_in_payload_fixture')
  for p in real_payload_fixture.iterdir():watch.file(p)
 out.mkdir();template=out/'template';initial=cycle.create(prior,template,*oracles);save(out/'INITIAL.json',initial)
 for p in template.iterdir():watch.file(p)
 normal=out/'normal';shutil.copytree(template,normal);committed=cycle.advance(normal,*oracles);save(out/'COMMITTED.json',committed)
 normal_watch=b.Watch()
 for p in normal.iterdir():normal_watch.file(p)
 again=cycle.advance(normal,*oracles);a.require(again['idempotent_noop'],'insert_cycle_normal_noop');normal_watch.check()
 env=dict(os.environ,PYTHONPATH=str(LAB),BIND_ORACLE=str(oracles[0]),LOOKUP_ORACLE=str(oracles[1]),SPAN_ORACLE=str(oracles[2]),ARCHIVE_INSERT_ORACLE=str(oracles[3]),RETAIL_INSERT_CYCLE_TEMPLATE=str(template),INSERT_CYCLE_RECOVERY_REPORT=str(out/'RECOVERY.json'))
 pattern='test_retail_insert_cycle.py'
 if real_payload_fixture is not None:env['RETAIL_INSERT_FIXTURE']=str(real_payload_fixture);pattern='test_*insert*.py'
 proc=subprocess.run([sys.executable,'-B','-m','unittest','discover','-s','tests','-p',pattern,'-v'],cwd=LAB,env=env,capture_output=True,text=True,timeout=180)
 log=proc.stdout+proc.stderr;(out/'TESTS.log').write_text(log)
 a.require(proc.returncode==0 and log.rstrip().endswith('OK'),'insert_cycle_tests_failed')
 counts=re.findall(r'Ran (\d+) tests',log);a.require(len(counts)==1,'insert_cycle_test_log');n=int(counts[0]);a.require(n==(73 if real_payload_fixture is not None else 24),'insert_cycle_expected_test_count')
 recovery=json.loads((out/'RECOVERY.json').read_text());a.require([r['phase'] for r in recovery]==list(cycle.base.PHASES) and all(r['child_exit']==91 and r['resumed_committed'] and r['idempotent_noop_after_resume'] for r in recovery),'insert_cycle_recovery_incomplete')
 for name,oracle in zip(('BIND','LOOKUP','SPAN','INSERT'),oracles):shutil.copy(oracle.parent/'BUILD-RECEIPT.json',out/(name+'-BUILD-RECEIPT.json'))
 watch.check()
 result={'format':'retail-original-insert-cycle-tests-1','tests_run':n,'failures':0,'errors':0,'skipped':0,'new_cycle_tests':24,'prior_49_insert_tests_rerun':real_payload_fixture is not None,'process_exit_failpoints_tested':list(cycle.base.PHASES),'successful_resumes':9,'idempotent_after_resume':9,'process_exit_code':91,'normal_publication_and_noop_verified':True,'candidate_and_published_gates_observed_in_test':True,'candidate_gate_failure_prevents_control_publication_tested':True,'postpublication_gate_failure_recovery_tested':True,'original_lookup_range_consumed_by_native_cache':True,'native_reads_per_gate':4,'cache_processes_per_gate':1,'archive_open_calls_per_gate':1,'constructor_calls_per_gate':1,'native_io_on_identical_temporary_snapshot':True,'prior_and_template_and_optional_payload_fixture_identities_unchanged':True,'extra_marker_written_into_strict_cycle':False,'historical_814_test_suite_rerun':False,'synthetic_1024_matrix_rerun':False,'power_loss_tested':False,'windows_execution_tested':False,'blte_decode_implementation':'independent Python','source_ckey_is_derived_not_independent':True,'portable_encoding_not_rehashed_by_this_runner':True,'network_requests':0,'installation_ready':False,'source_sha256':{str(p.relative_to(LAB)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [LAB/'retail_insert_cycle.py',LAB/'tests/test_retail_insert_cycle.py',Path(__file__).resolve()]},'artifacts_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.iterdir()) if p.is_file()}}
 save(out/'TEST-RESULTS.json',result);return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prior-owned-cycle',type=Path,required=True);p.add_argument('--out-new',type=Path,required=True);p.add_argument('--real-payload-fixture',type=Path)
 for n in ('bind','lookup','span','insert'):p.add_argument('--'+n+'-oracle',type=Path,required=True)
 x=p.parse_args();result=run(x.prior_owned_cycle,x.out_new,[x.bind_oracle,x.lookup_oracle,x.span_oracle,x.insert_oracle],x.real_payload_fixture);print(json.dumps({k:result[k] for k in ('tests_run','failures','errors','successful_resumes','installation_ready')},indent=2))
