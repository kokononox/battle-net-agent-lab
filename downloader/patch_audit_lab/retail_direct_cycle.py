"""Owned V8 direct-file gate; original lookup/cache/span, pinned live inode.
No snapshot. Requires the active POSIX lock exported by retail_v8_cycle.
No general updater, Windows, native BLTE, or power-loss claims.
"""
import argparse,json
from pathlib import Path
import agent_archive_direct as direct
import agent_span_reader as span
import retail_insert_probe as payload
import retail_lookup_cycle as lookup
import retail_v8_cycle as base
import owned_v8_lock as locks
import patch_audit as a

def identities(bind_oracle,lookup_oracle,span_oracle,direct_oracle):
 base.oracle_identity(bind_oracle);lookup.oracle_identity(lookup_oracle);span.oracle_identity(span_oracle);direct.oracle_identity(direct_oracle)

def gate(root,view,lookup_oracle,span_oracle,direct_oracle,candidate=False):
 locks.require(root);proof=lookup.gate(root,view,lookup_oracle,candidate);objects=proof['lookup_gate_objects']
 a.require(1<=len(objects)<=2 and all(obj['returned_span']==188 for obj in objects),'direct_cycle_lookup_profile')
 addresses=([obj['returned_offset'] for obj in objects]*4)[:4]
 rows=direct.compare(direct_oracle,root,addresses,188);reads=payload.validate_rows(span_oracle,addresses,rows)
 a.require(all(x['trace']['create_calls']==1 and x['trace']['constructor_calls']==1 for x in reads),'direct_cycle_cache_reuse')
 proof.update(mandatory_original_insert_cache_span_gate=True,mandatory_live_archive_gate=True,original_constructor_allocation_insertion_executed=True,original_span_header_and_address_getters_executed=True,lookup_returned_addresses_consumed_by_native_io=True,native_read_addresses=addresses,native_read_span=188,cache_processes=1,native_reads_in_process=4,open_calls=1,constructor_calls=1,create_adapter_calls=1,create_adapter_uses_dup_not_pathname_open=True,insert_gate_objects=reads,direct_live_read=rows.proof,native_io_on_snapshot_not_live_archive=False,native_io_on_locked_live_archive=True,temporary_marker_outside_cycle=False,extra_marker_created=False,blte_decode_implementation='independent Python',full_agent_archive_io_executed=False,windows_io_executed=False)
 proof['agent_qword_semantics']='bounded original lookup base/extent consumed by original cache reading pinned live owned-file inode; Windows/high-level object reader unproven'
 return proof

def create(prior,out,bind_oracle,lookup_oracle,span_oracle,direct_oracle):
 identities(bind_oracle,lookup_oracle,span_oracle,direct_oracle);base.create(prior,out,bind_oracle);return status(out,bind_oracle,lookup_oracle,span_oracle,direct_oracle)
def status(root,bind_oracle,lookup_oracle,span_oracle,direct_oracle):
 identities(bind_oracle,lookup_oracle,span_oracle,direct_oracle);return base.status(root,bind_oracle,additional_gate=lambda p,v,c:gate(p,v,lookup_oracle,span_oracle,direct_oracle,c))
def advance(root,bind_oracle,lookup_oracle,span_oracle,direct_oracle,fail_after=None):
 identities(bind_oracle,lookup_oracle,span_oracle,direct_oracle);return base.advance(root,bind_oracle,fail_after,additional_gate=lambda p,v,c:gate(p,v,lookup_oracle,span_oracle,direct_oracle,c))
def main():
 p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='mode',required=True)
 for mode in ('create','status','advance'):
  q=sub.add_parser(mode)
  for name in ('bind','lookup','span','direct'):q.add_argument('--'+name+'-oracle',type=Path,required=True)
  if mode=='create':q.add_argument('--prior-owned-cycle',type=Path,required=True);q.add_argument('--out-new',type=Path,required=True)
  else:q.add_argument('--root',type=Path,required=True)
  if mode=='advance':q.add_argument('--test-exit-after',choices=base.PHASES)
 x=p.parse_args();args=[x.bind_oracle,x.lookup_oracle,x.span_oracle,x.direct_oracle]
 result=create(x.prior_owned_cycle,x.out_new,*args) if x.mode=='create' else status(x.root,*args) if x.mode=='status' else advance(x.root,*args,fail_after=x.test_exit_after)
 print(json.dumps(result,indent=2))
if __name__=='__main__':main()
