"""Owned V8 cycle: mandatory original lookup -> insertion/cache -> span gate.
Native I/O reads a byte-identical, read-only temporary snapshot of data.000.
Linux custom publication/resume only; no Windows installation writer.
"""
import argparse,json,tempfile
from pathlib import Path
import agent_archive_insert as insert
import agent_span_reader as span
import retail_insert_probe as payload
import retail_lookup_cycle as lookup
import retail_v8_cycle as base
import source_binding as b
import patch_audit as a
import synthetic_casc_store as fs

def identities(bind_oracle,lookup_oracle,span_oracle,insert_oracle):
 base.oracle_identity(bind_oracle);lookup.oracle_identity(lookup_oracle);span.oracle_identity(span_oracle);insert.oracle_identity(insert_oracle)

def gate(root,view,lookup_oracle,span_oracle,insert_oracle,candidate=False):
 proof=lookup.gate(root,view,lookup_oracle,candidate)
 objects=proof['lookup_gate_objects'];a.require(1<=len(objects)<=2,'insert_cycle_object_count')
 a.require(all(x['returned_span']==188 for x in objects),'insert_cycle_span_profile')
 addresses=[x['returned_offset'] for x in objects]
 # Repeat the actual returned ranges within ONE cache process, without preseed.
 addresses=(addresses*4)[:4]
 watch=b.Watch();raw=watch.read(root/'data.000',1024)
 a.require(raw==view['data'],'insert_cycle_live_snapshot_mismatch')
 with tempfile.TemporaryDirectory(prefix='retail-insert-gate-') as folder:
  snapshot=Path(folder).resolve()
  fs.write_new(snapshot/insert.MARKER,base.old.canonical({'format':'archive-insert-owned-fixture-1'}))
  fs.write_new(snapshot/'data.000',raw)
  rows=insert.compare(insert_oracle,snapshot,addresses,188)
  reads=payload.validate_rows(span_oracle,addresses,rows)
 watch.check()
 a.require(all(x['trace']['create_calls']==1 and x['trace']['constructor_calls']==1 for x in reads),'insert_cycle_cache_not_reused')
 proof.update({'mandatory_original_insert_cache_span_gate':True,'original_constructor_allocation_insertion_executed':True,'original_span_header_and_address_getters_executed':True,'lookup_returned_addresses_consumed_by_native_io':True,'native_read_addresses':addresses,'native_read_span':188,'cache_processes':1,'native_reads_in_process':4,'open_calls':1,'constructor_calls':1,'insert_gate_objects':reads,'snapshot_sha256':a.sha256(raw),'snapshot_matches_locked_cycle_archive':True,'native_io_on_snapshot_not_live_archive':True,'cycle_archive_identity_unchanged_by_gate':True,'temporary_marker_outside_cycle':True,'blte_decode_implementation':'independent Python','full_agent_archive_io_executed':False,'windows_io_executed':False})
 # Preserve lookup's limitation string but make this bridge's added scope explicit.
 proof['agent_qword_semantics']='bounded native lookup returned base/extent consumed by native cache on identical snapshot; Windows/high-level object reader unproven'
 return proof

def create(prior,out,bind_oracle,lookup_oracle,span_oracle,insert_oracle):
 identities(bind_oracle,lookup_oracle,span_oracle,insert_oracle)
 base.create(prior,out,bind_oracle)
 return status(out,bind_oracle,lookup_oracle,span_oracle,insert_oracle)

def status(root,bind_oracle,lookup_oracle,span_oracle,insert_oracle):
 identities(bind_oracle,lookup_oracle,span_oracle,insert_oracle)
 return base.status(root,bind_oracle,additional_gate=lambda p,v,c:gate(p,v,lookup_oracle,span_oracle,insert_oracle,c))

def advance(root,bind_oracle,lookup_oracle,span_oracle,insert_oracle,fail_after=None):
 identities(bind_oracle,lookup_oracle,span_oracle,insert_oracle)
 return base.advance(root,bind_oracle,fail_after,additional_gate=lambda p,v,c:gate(p,v,lookup_oracle,span_oracle,insert_oracle,c))

def main():
 p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='mode',required=True)
 for mode in ('create','status','advance'):
  q=sub.add_parser(mode)
  for name in ('bind','lookup','span','insert'):q.add_argument('--'+name+'-oracle',type=Path,required=True)
  if mode=='create':q.add_argument('--prior-owned-cycle',type=Path,required=True);q.add_argument('--out-new',type=Path,required=True)
  else:q.add_argument('--root',type=Path,required=True)
  if mode=='advance':q.add_argument('--test-exit-after',choices=base.PHASES)
 x=p.parse_args();args=[x.bind_oracle,x.lookup_oracle,x.span_oracle,x.insert_oracle]
 result=create(x.prior_owned_cycle,x.out_new,*args) if x.mode=='create' else status(x.root,*args) if x.mode=='status' else advance(x.root,*args,fail_after=x.test_exit_after)
 print(json.dumps(result,indent=2))
if __name__=='__main__':main()
