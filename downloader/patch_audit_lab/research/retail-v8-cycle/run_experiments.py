"""Run bounded original range parity and real-sample V8 publication/resume copies."""
import argparse,hashlib,json,random,shutil,subprocess,sys
from pathlib import Path
from unittest.mock import patch
import agent_value_range as value
import agent_bind_contract as bind
import retail_v8_cycle as cycle
import retail_update_cycle as oldcycle
import retail_storage_poc as safety
import patch_audit as a

def hashes(root):return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()}
def run(prior,out,bind_oracle,value_oracle):
 out=safety.safe_new(out);out.mkdir();prior_before=hashes(prior);rng=random.Random(98247216);vectors=0;wrap_accepted_policy_rejected=0
 def compare(*args):
  nonlocal vectors,wrap_accepted_policy_rejected
  r=value.compare(value_oracle,*args);vectors+=1
  if r['valid'] and not value.strict_policy(*args):wrap_accepted_policy_rejected+=1
 for start in (0,1,30,187,188,189,1<<32,value.MASK):
  for length in (0,1,30,158,188,value.MASK):
   for extent in (0,1,30,188,1<<32,value.MASK):
    for base in (0,480,668,value.MASK):compare(start,length,base,extent)
 for i in range(1024):compare(*(rng.getrandbits(64) for j in range(4)))
 matrix={'format':'original-agent-value-range-matrix-1','vectors':vectors,'all_native_model_matched':True,'original_fragment_bytes':105,'external_helpers':0,'accepted_by_primitive_rejected_by_our_nonwrapping_policy':wrap_accepted_policy_rejected,'primitive_ignores_base_qword':True,'full_agent_readpath_or_reachability_proven':False,'product_bug_claim':False,'windows_executed':False}
 template=out/'initial';initial=cycle.create(prior,template,bind_oracle);before=hashes(template);main=out/'completed';shutil.copytree(template,main);result=cycle.advance(main,bind_oracle);after=hashes(main);source_unchanged=(main/'data.000').read_bytes()[:668]==(template/'data.000').read_bytes();indexes_unchanged=all(after[n]==h for n,h in before.items() if n.endswith('.idx'));final_before=hashes(main);noop=cycle.advance(main,bind_oracle);a.require(noop['idempotent_noop'] and final_before==hashes(main),'v8_experiment_idempotent')
 crashes=[]
 for phase in cycle.PHASES:
  root=out/('exit-'+phase);shutil.copytree(template,root);p=subprocess.run([sys.executable,'-B',str(Path(cycle.__file__)),'advance','--root',str(root),'--oracle',str(bind_oracle),'--test-exit-after',phase],capture_output=True,timeout=20);a.require(p.returncode==91,'v8_expected_exit91');completed=cycle.advance(root,bind_oracle);a.require(completed['target_published'] and completed['original_agent_inner_bind_verified'],'v8_resume_success');snapshot=hashes(root);a.require(cycle.advance(root,bind_oracle)['idempotent_noop'] and hashes(root)==snapshot,'v8_resume_idempotent');crashes.append({'phase':phase,'hard_exit':91,'resume_published_target':True,'native_bind_and_fullkey_gate_verified':True,'idempotent_no_write':True,'data_sha256':hashes(root)['data.000']})
 fault=out/'injected-map-error';shutil.copytree(template,fault);actual=bind.compare
 def mapping_fault(binary,raw,bucket,**kw):return actual(binary,raw,bucket,map_error=73,**kw) if bytes.fromhex(cycle.TARGET) in raw else actual(binary,raw,bucket,**kw)
 caught=None
 try:
  with patch.object(bind,'compare',side_effect=mapping_fault):cycle.advance(fault,bind_oracle)
 except a.AuditError as e:caught=str(e)
 a.require(caught=='v8_actual_bind_failed','v8_injected_map_error_expected');a.require((fault/'shmem').read_bytes()==oldcycle.control(False),'v8_bind_error_keeps_control');a.require(json.loads((fault/cycle.JOURNAL).read_text())['state']=='prepared','v8_bind_error_keeps_prepared')
 recovered=cycle.advance(fault,bind_oracle);a.require(recovered['target_published'],'v8_bind_error_resume')
 a.require(prior_before==hashes(prior),'v8_prior_unchanged')
 result={'format':'real-retail-v8-cycle-experiment-1','initial':initial,'completed':result,'all_16_initial_indexes_unchanged':indexes_unchanged,'source_and_prefix_bytes_unchanged':source_unchanged,'data_sha256':after['data.000'],'hard_exit_resume_cases':crashes,'injected_mapping_failure':{'original_bind_executed':True,'only_mapping_helper_returns_injected_73':True,'caught':caught,'old_control_kept':True,'journal_kept_prepared':True,'real_resume_succeeded':True},'prior_owned_v7_store_hashes_unchanged':True,'idempotent_no_write':True,'publication':'custom Linux renameat2 no-replace for index, os.replace whole control, fsync; not Agent Windows publication','journal':'custom research protocol, not Agent journal','power_loss_proven':False,'full_agent_value_and_object_io_proven':False,'game_lab_original_portable_or_release_modified':False,'installation_ready':False}
 (out/'VALUE-MATRIX.json').write_text(json.dumps(matrix,indent=2)+'\n');(out/'CYCLE-EXPERIMENT.json').write_text(json.dumps(result,indent=2)+'\n');return {'value_vectors':vectors,'resume_boundaries':len(crashes),'native_bind_gate':True,'mapping_failure_prevented_publish':True,'installation_ready':False}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prior-owned-cycle',type=Path,required=True);p.add_argument('--out-new',type=Path,required=True);p.add_argument('--bind-oracle',type=Path,required=True);p.add_argument('--value-oracle',type=Path,required=True);x=p.parse_args();print(json.dumps(run(x.prior_owned_cycle,x.out_new,x.bind_oracle,x.value_oracle)))
