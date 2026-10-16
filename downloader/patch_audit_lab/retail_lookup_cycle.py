"""Enhanced V8 research cycle: mandatory original normal-path lookup/merge gate.

Linux publication remains custom; actual Agent archive file I/O is not executed.
"""
import argparse,json,struct
from pathlib import Path
import agent_lookup_merge as lookup
import agent_static_audit as identity
import retail_v8_cycle as base
import retail_update_cycle as legacy
import synthetic_casc_store as fs
import synthetic_casc_format as fmt
import patch_audit as a
import source_binding as b

def oracle_identity(oracle):
 oracle=b.safe(oracle,True);receipt=oracle.parent/'BUILD-RECEIPT.json';a.require(receipt.is_file(),'lookup_cycle_missing_build_receipt');r=b.json_object(fs.read(receipt,131072))
 a.require(r.get('format')=='agent-lookup-merge-build-1' and r.get('agent_sha256')==identity.AGENT_SHA256 and r.get('original_bytes_verified_in_elf') is True and r.get('normal_path_lookup_iterator_merge_range_executed') is True and r.get('no_rwx') is True and r.get('nx_stack') is True,'lookup_cycle_build_receipt')
 a.require(a.sha256(fs.read(oracle,2*1024**2))==r.get('binary_sha256'),'lookup_cycle_oracle_digest');return True

def gate(root,view,oracle,candidate=False):
 oracle_identity(oracle);visible=view['updated'] or candidate;ctl=fs.read(root/'shmem',65536);seq=struct.unpack_from('<16I',ctl,0x110);objects=[]
 for key,ckey,expected_offset in ((base.SOURCE,base.SOURCE_CK,480),(base.TARGET,base.old.CK,668)):
  if key==base.TARGET and not visible:continue
  bucket=fmt.bucket(key);sequence=2 if candidate and key==base.TARGET else seq[bucket];raw=fs.read(root/legacy.idx(bucket,sequence),lookup.bind.LIMIT)
  proof=lookup.compare(oracle,raw,bucket,key);found=proof['lookup'];a.require(proof['bind']['status']==0 and found['performed'] and found['status']==0,'lookup_cycle_actual_lookup_failed')
  offset,size=found['range'];a.require((offset,size)==(expected_offset,188),'lookup_cycle_returned_range_policy')
  decoded,_=fmt.read_span(view['data'][offset:offset+size],key,33940,ckey,0,offset)
  objects.append({'ekey':key,'returned_offset':offset,'returned_span':size,'original_lookup_merge_status':0,'decoded_bytes':len(decoded),'full_ekey_span_checksums_and_ckey_verified':True})
 return {'agent_qword_semantics':'base/extent consumed by original bounded lookup; archive segmentation and Agent file I/O unproven','mandatory_original_lookup_merge_range_gate':True,'original_lookup_normal_path_not_mocked':True,'returned_agent_range_used_for_independent_span_read':True,'lookup_gate_objects':objects,'full_agent_archive_io_executed':False,'windows_seh_executed':False}

def create(prior,out,bind_oracle,lookup_oracle):
 oracle_identity(lookup_oracle);base.create(prior,out,bind_oracle);return status(out,bind_oracle,lookup_oracle)

def status(root,bind_oracle,lookup_oracle):
 oracle_identity(lookup_oracle);return base.status(root,bind_oracle,additional_gate=lambda p,v,c:gate(p,v,lookup_oracle,c))

def advance(root,bind_oracle,lookup_oracle,fail_after=None):
 oracle_identity(lookup_oracle);return base.advance(root,bind_oracle,fail_after,additional_gate=lambda p,v,c:gate(p,v,lookup_oracle,c))

def main():
 p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='mode',required=True)
 for mode in ('create','status','advance'):
  s=sub.add_parser(mode);s.add_argument('--bind-oracle',type=Path,required=True);s.add_argument('--lookup-oracle',type=Path,required=True)
  if mode=='create':s.add_argument('--prior-owned-cycle',type=Path,required=True);s.add_argument('--out-new',type=Path,required=True)
  else:s.add_argument('--root',type=Path,required=True)
  if mode=='advance':s.add_argument('--test-exit-after',choices=base.PHASES)
 x=p.parse_args();r=create(x.prior_owned_cycle,x.out_new,x.bind_oracle,x.lookup_oracle) if x.mode=='create' else status(x.root,x.bind_oracle,x.lookup_oracle) if x.mode=='status' else advance(x.root,x.bind_oracle,x.lookup_oracle,x.test_exit_after);print(json.dumps(r,indent=2))
if __name__=='__main__':main()
