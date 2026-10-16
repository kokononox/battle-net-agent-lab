"""Reproduce bounded original normal-path lookup/merge and enhanced cycle gates."""
import argparse,json,random,shutil,subprocess,sys
from pathlib import Path
from unittest.mock import patch
import agent_lookup_merge as m
import agent_bind_contract as b
import retail_lookup_cycle as cycle
import retail_v8_cycle as base
import retail_update_cycle as legacy
import retail_storage_poc as safety
import patch_audit as a

def hashes(root):return {p.name:a.sha256(p.read_bytes()) for p in root.iterdir() if p.is_file()}
def run(prior,out,bind_oracle,lookup_oracle):
 out=safety.safe_new(out);out.mkdir();before=hashes(prior);rng=random.Random(982473);k=base.SOURCE;r=b.record(k,480,188);vectors=0;hist={};explicit=[]
 def compare(raw,bucket=5,query=k,start=0,length=m.MASK):
  nonlocal vectors
  result=m.compare(lookup_oracle,raw,bucket,query,start,length);vectors+=1;status=str(result['lookup']['status']);hist[status]=hist.get(status,0)+1;return result['lookup']
 for i in range(3000):
  primary=[r] if rng.randrange(2) else []
  if primary and rng.randrange(4)==0:primary.append(b.record(k,480+rng.randrange(100),rng.randrange(80)))
  tail=[]
  for j in range(rng.randrange(7-len(primary)+1)):
   key=k if rng.randrange(4) else '22'*16;tail.append((b.record(key,rng.randrange(450,730),rng.randrange(70)),rng.randrange(1,8)))
  compare(m.build_index(primary,tail,5),start=rng.randrange(220),length=rng.choice((0,m.MASK,1,30,100)))
 for bucket in range(16):
  for flag in range(1,8):compare(m.build_index([r],[(r,flag)],bucket),bucket)
 cases=[('primary',[r],[],0,m.MASK,0),('suffix',[r],[],30,m.MASK,0),('tail_only',[],[(r,1)],0,m.MASK,0),('clear',[r],[(r,3)],0,m.MASK,2),('range_outside',[r],[],189,m.MASK,4),('hole',[r],[(b.record(k,500,20),7)],0,m.MASK,3),('hole_prefix',[r],[(b.record(k,500,20),7)],0,20,0),('hole_suffix',[r],[(b.record(k,500,20),7)],40,m.MASK,0),('hole_refill',[r],[(b.record(k,500,20),7),(b.record(k,500,20),6)],0,m.MASK,0),('duplicate_gap',[r,b.record(k,480,20),b.record(k,520,148)],[],0,m.MASK,3)]
 for label,primary,tail,start,length,status in cases:
  result=compare(m.build_index(primary,tail,5),start=start,length=length);a.require(result['status']==status,'lookup_explicit_status');explicit.append({'case':label,**result})
 matrix={'format':'original-lookup-merge-matrix-1','vectors':vectors,'random_vectors':3000,'all_native_model_matched':True,'all_buckets_and_flags_1_to_7':True,'status_histogram':hist,'explicit_cases':explicit,'matching_record_limit':7,'total_primary_limit':1024,'total_tail_limit':64,'normal_path_frame_and_destructors_mocked':True,'semantic_lookup_iterator_merge_range_are_original':True,'whole_agent_io_or_windows_executed':False}
 template=out/'initial';initial=cycle.create(prior,template,bind_oracle,lookup_oracle);root=out/'completed';shutil.copytree(template,root);initial_hashes=hashes(root);completed=cycle.advance(root,bind_oracle,lookup_oracle);final_hashes=hashes(root);again=cycle.advance(root,bind_oracle,lookup_oracle);a.require(again['idempotent_noop'] and final_hashes==hashes(root),'lookup_cycle_noop')
 crashes=[]
 for phase in base.PHASES:
  p=out/('exit-'+phase);shutil.copytree(template,p);process=subprocess.run([sys.executable,'-B',str(Path(cycle.__file__)),'advance','--root',str(p),'--bind-oracle',str(bind_oracle),'--lookup-oracle',str(lookup_oracle),'--test-exit-after',phase],capture_output=True,timeout=25);a.require(process.returncode==91,'lookup_cycle_expected_hard_exit');resumed=cycle.advance(p,bind_oracle,lookup_oracle);a.require(resumed['target_published'] and resumed['mandatory_original_lookup_merge_range_gate'],'lookup_cycle_resume');snapshot=hashes(p);a.require(cycle.advance(p,bind_oracle,lookup_oracle)['idempotent_noop'] and snapshot==hashes(p),'lookup_cycle_resumed_noop');crashes.append({'phase':phase,'exit_code':91,'resumed_with_original_lookup_gate':True,'idempotent_no_write':True,'data_sha256':hashes(p)['data.000']})
 fault=out/'injected-lookup-gap';shutil.copytree(template,fault);original=m.compare;seen=[]
 def gap(oracle,raw,bucket,query,*args,**kw):
  if query==base.TARGET:
   raw=m.build_index([b.record(query,668,188)],[(b.record(query,700,20),7)],bucket);result=original(oracle,raw,bucket,query,*args,**kw);seen.append(result['lookup']['status']);return result
  return original(oracle,raw,bucket,query,*args,**kw)
 error=None
 try:
  with patch.object(m,'compare',side_effect=gap):cycle.advance(fault,bind_oracle,lookup_oracle)
 except a.AuditError as e:error=str(e)
 a.require(error=='lookup_cycle_actual_lookup_failed' and seen==[3],'lookup_cycle_injected_real_status3');a.require((fault/'shmem').read_bytes()==legacy.control(False) and json.loads((fault/base.JOURNAL).read_text())['state']=='prepared','lookup_cycle_gap_keeps_control');a.require(cycle.advance(fault,bind_oracle,lookup_oracle)['target_published'],'lookup_cycle_gap_resume');a.require(before==hashes(prior),'lookup_cycle_prior_unchanged')
 result={'format':'retail-original-lookup-cycle-experiment-1','initial':initial,'completed':completed,'source_prefix_unchanged':(root/'data.000').read_bytes()[:668]==(template/'data.000').read_bytes(),'all_initial_indexes_unchanged':all(final_hashes[n]==h for n,h in initial_hashes.items() if n.endswith('.idx')),'final_data_sha256':final_hashes['data.000'],'hard_exit_resume_cases':crashes,'injected_gap':{'boundary':'lookup input only: well-formed synthetic tail deletion interval, no mutation of game or actual candidate index','semantic_functions_original_not_mocked':True,'native_lookup_status':3,'caller_rejected_before_control_publish':True,'journal_prepared_preserved':True,'resume_with_real_index_succeeded':True},'idempotent_rechecks_lookup_and_does_not_write':True,'prior_owned_store_hashes_unchanged':True,'returned_agent_range_drives_independent_python_readback':True,'windows_agent_archive_io_or_seh_executed':False,'custom_linux_publication_not_windows_protocol':True,'power_loss_proven':False,'installation_ready':False,'game_lab_original_portable_release_changed':False}
 (out/'MATRIX-RESULTS.json').write_text(json.dumps(matrix,indent=2)+'\n');(out/'CYCLE-EXPERIMENT.json').write_text(json.dumps(result,indent=2)+'\n');return {'matrix_vectors':vectors,'explicit_cases':len(explicit),'hard_exit_resume_boundaries':9,'original_lookup_returns_real_source_target_ranges':True,'lookup_gap_status3_prevented_publish':True,'installation_ready':False}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prior-owned-cycle',type=Path,required=True);p.add_argument('--out-new',type=Path,required=True);p.add_argument('--bind-oracle',type=Path,required=True);p.add_argument('--lookup-oracle',type=Path,required=True);x=p.parse_args();print(json.dumps(run(x.prior_owned_cycle,x.out_new,x.bind_oracle,x.lookup_oracle)))
