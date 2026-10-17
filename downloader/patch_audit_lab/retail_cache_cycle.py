"""Research V8 cycle with mandatory original lookup, archive-read and span gates.
Linux custom publication; original manager/cache executed; constructor insertion and OS adapted.
"""
import argparse,json
from pathlib import Path
import retail_lookup_cycle as lookup_cycle
import retail_v8_cycle as base
import agent_span_reader as span
import agent_archive_cache as io

def gate(root,view,lookup_oracle,span_oracle,cache_oracle,candidate=False):
 result=lookup_cycle.gate(root,view,lookup_oracle,candidate);proofs=[]
 for obj in result['lookup_gate_objects']:
  key=obj['ekey'];ck=base.SOURCE_CK if key==base.SOURCE else base.old.CK
  proofs.append(io.read_numbered(cache_oracle,span_oracle,{0:root/'data.000'},obj['returned_offset'],obj['returned_span'],key,33940,ck))
 result.update(mandatory_original_span_header_and_address_gate=True,span_gate_objects=proofs,original_archive_read_gate_mandatory=True,original_open_manager_executed=True,original_cache_gate_mandatory=True,original_constructor_allocation_insertion_executed=False,windows_io_executed=False)
 return result

def identities(lookup_oracle,span_oracle,cache_oracle):lookup_cycle.oracle_identity(lookup_oracle);span.oracle_identity(span_oracle);io.oracle_identity(cache_oracle)
def create(prior,out,bind_oracle,lookup_oracle,span_oracle,cache_oracle):
 identities(lookup_oracle,span_oracle,cache_oracle);base.create(prior,out,bind_oracle);return status(out,bind_oracle,lookup_oracle,span_oracle,cache_oracle)
def status(root,bind_oracle,lookup_oracle,span_oracle,cache_oracle):
 identities(lookup_oracle,span_oracle,cache_oracle);return base.status(root,bind_oracle,additional_gate=lambda p,v,c:gate(p,v,lookup_oracle,span_oracle,cache_oracle,c))
def advance(root,bind_oracle,lookup_oracle,span_oracle,cache_oracle,fail_after=None):
 identities(lookup_oracle,span_oracle,cache_oracle);return base.advance(root,bind_oracle,fail_after,additional_gate=lambda p,v,c:gate(p,v,lookup_oracle,span_oracle,cache_oracle,c))
def main():
 p=argparse.ArgumentParser(description=__doc__);subs=p.add_subparsers(dest='mode',required=True)
 for mode in ('create','status','advance'):
  q=subs.add_parser(mode);q.add_argument('--bind-oracle',type=Path,required=True);q.add_argument('--lookup-oracle',type=Path,required=True);q.add_argument('--span-oracle',type=Path,required=True);q.add_argument('--cache-oracle',type=Path,required=True)
  if mode=='create':q.add_argument('--prior-owned-cycle',type=Path,required=True);q.add_argument('--out-new',type=Path,required=True)
  else:q.add_argument('--root',type=Path,required=True)
  if mode=='advance':q.add_argument('--test-exit-after',choices=base.PHASES)
 x=p.parse_args();r=create(x.prior_owned_cycle,x.out_new,x.bind_oracle,x.lookup_oracle,x.span_oracle,x.cache_oracle) if x.mode=='create' else status(x.root,x.bind_oracle,x.lookup_oracle,x.span_oracle,x.cache_oracle) if x.mode=='status' else advance(x.root,x.bind_oracle,x.lookup_oracle,x.span_oracle,x.cache_oracle,x.test_exit_after);print(json.dumps(r,indent=2))
if __name__=='__main__':main()
