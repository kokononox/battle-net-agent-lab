"""Reproduce mandatory original archive-read and span gates around custom Linux publication."""
import argparse,json,shutil,subprocess,sys
from pathlib import Path
from unittest.mock import patch
import agent_span_reader as span
import retail_io_cycle as cycle
import agent_archive_io as io
import retail_v8_cycle as base
import retail_update_cycle as legacy
import retail_storage_poc as safety
import patch_audit as a

def hashes(root):return {p.name:a.sha256(p.read_bytes()) for p in root.iterdir() if p.is_file()}
def run(prior,out,bind_oracle,lookup_oracle,span_oracle,io_oracle):
 out=safety.safe_new(out);out.mkdir();before=hashes(prior)
 template=out/'initial';initial=cycle.create(prior,template,bind_oracle,lookup_oracle,span_oracle,io_oracle);root=out/'completed';shutil.copytree(template,root);initial_hashes=hashes(root);completed=cycle.advance(root,bind_oracle,lookup_oracle,span_oracle,io_oracle);final_hashes=hashes(root);again=cycle.advance(root,bind_oracle,lookup_oracle,span_oracle,io_oracle);a.require(again['idempotent_noop'] and final_hashes==hashes(root),'lookup_cycle_noop')
 crashes=[]
 for phase in base.PHASES:
  p=out/('exit-'+phase);shutil.copytree(template,p);process=subprocess.run([sys.executable,'-B',str(Path(cycle.__file__)),'advance','--root',str(p),'--bind-oracle',str(bind_oracle),'--lookup-oracle',str(lookup_oracle),'--span-oracle',str(span_oracle),'--io-oracle',str(io_oracle),'--test-exit-after',phase],capture_output=True,timeout=25);a.require(process.returncode==91,'lookup_cycle_expected_hard_exit');resumed=cycle.advance(p,bind_oracle,lookup_oracle,span_oracle,io_oracle);a.require(resumed['target_published'] and resumed['mandatory_original_span_header_and_address_gate'],'lookup_cycle_resume');snapshot=hashes(p);a.require(cycle.advance(p,bind_oracle,lookup_oracle,span_oracle,io_oracle)['idempotent_noop'] and snapshot==hashes(p),'lookup_cycle_resumed_noop');crashes.append({'phase':phase,'exit_code':91,'resumed_with_original_lookup_and_span_gates':True,'idempotent_no_write':True,'data_sha256':hashes(p)['data.000']})
 fault=out/'injected-header-checksum';shutil.copytree(template,fault);original=span.compare;seen=[]
 def corrupt(oracle,h,address,*args,**kw):
  if address==668:
   h=bytearray(h);h[26]^=1;result=original(oracle,bytes(h),address,*args,**kw);seen.append(result['valid']);return result
  return original(oracle,h,address,*args,**kw)
 error=None
 try:
  with patch.object(span,'compare',side_effect=corrupt):cycle.advance(fault,bind_oracle,lookup_oracle,span_oracle,io_oracle)
 except a.AuditError as e:error=str(e)
 a.require(error=='io_reader_original_header_rejected' and seen==[False],'span_cycle_actual_header_rejected');a.require((fault/'shmem').read_bytes()==legacy.control(False) and json.loads((fault/base.JOURNAL).read_text())['state']=='prepared','span_cycle_old_control_kept');a.require(cycle.advance(fault,bind_oracle,lookup_oracle,span_oracle,io_oracle)['target_published'],'span_cycle_recovery');a.require(before==hashes(prior),'span_cycle_prior_unchanged')
 fault2=out/'injected-read-error';shutil.copytree(template,fault2);original_io=io.compare;seen_io=[]
 def read_error(oracle,path,address,length,*args,**kw):
  if address==668:
   r,data=original_io(oracle,path,address,length,read_error=5);seen_io.append(r['status']);return r,data
  return original_io(oracle,path,address,length,*args,**kw)
 error2=None
 try:
  with patch.object(io,'compare',side_effect=read_error):cycle.advance(fault2,bind_oracle,lookup_oracle,span_oracle,io_oracle)
 except a.AuditError as e:error2=str(e)
 a.require(error2=='io_reader_exact_read_required' and seen_io==[8],'io_cycle_original_read_error');a.require((fault2/'shmem').read_bytes()==legacy.control(False) and json.loads((fault2/base.JOURNAL).read_text())['state']=='prepared','io_cycle_old_control');a.require(cycle.advance(fault2,bind_oracle,lookup_oracle,span_oracle,io_oracle)['target_published'],'io_cycle_error_recovery')
 result={'format':'retail-original-archive-io-cycle-experiment-1','initial':initial,'completed':completed,'source_prefix_unchanged':(root/'data.000').read_bytes()[:668]==(template/'data.000').read_bytes(),'all_initial_indexes_unchanged':all(final_hashes[n]==h for n,h in initial_hashes.items() if n.endswith('.idx')),'final_data_sha256':final_hashes['data.000'],'hard_exit_resume_cases':crashes,'injected_header_checksum':{'boundary':'header input only at original parser; actual research file unchanged','original_parser_returned_false':True,'caller_rejected_before_control_publish':True,'journal_prepared_preserved':True,'resume_with_real_header_succeeded':True},'idempotent_rechecks_gates_and_does_not_write':True,'prior_owned_store_hashes_unchanged':True,'original_lookup_archive_read_and_span_gates_mandatory':True,'injected_read_error':{'boundary':'ReadFile adapter error5, original wrapper propagation to8; no research file mutation','original_result':8,'caller_blocks_publish_old_control_and_prepared_journal_kept':True,'recovered_after_removing_injection':True},'original_open_manager_executed':False,'windows_agent_archive_io_or_seh_executed':False,'custom_linux_publication_not_windows_protocol':True,'power_loss_proven':False,'installation_ready':False,'game_lab_original_portable_release_changed':False}
 (out/'CYCLE-EXPERIMENT.json').write_text(json.dumps(result,indent=2)+'\n');return {'hard_exit_resume_boundaries':9,'actual_original_header_rejection_blocks_publish':True,'installation_ready':False}

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prior-owned-cycle',type=Path,required=True);p.add_argument('--out-new',type=Path,required=True);p.add_argument('--bind-oracle',type=Path,required=True);p.add_argument('--lookup-oracle',type=Path,required=True);p.add_argument('--span-oracle',type=Path,required=True);p.add_argument('--io-oracle',type=Path,required=True);x=p.parse_args();print(json.dumps(run(x.prior_owned_cycle,x.out_new,x.bind_oracle,x.lookup_oracle,x.span_oracle,x.io_oracle)))
