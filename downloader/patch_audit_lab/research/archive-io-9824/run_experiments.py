"""Reproduce original archive-read semantics against explicit read-only files.
No complete Agent, original open manager, Windows IO, scan or network.
"""
import argparse,json,random,struct
from pathlib import Path
import agent_archive_io as io
import agent_lookup_merge as lookup
import agent_bind_contract as bind
import synthetic_casc_format as fmt
import retail_storage_poc as safety
import source_binding as b
import patch_audit as a
K='914fcad4f4fcf4abb0ba52b197bb066f';CK='98ad7b81687304aa0e99cf326200adfe';T='faedca88d0a0ab30dae5519239582d31';TC='3d42bf2e42127f313b0ec64cb440cde9'
def header(ar,off,key):
 h=bytes.fromhex(key)[::-1]+struct.pack('<I',188)+bytes(2);h+=struct.pack('<I',fmt.hashlittle2(h,0x3d6be971)[0]);return h+fmt.checksum_b(h,ar,off)
def run(oracle,span_oracle,lookup_oracle,prior,out):
 out=safety.safe_new(out);w=b.Watch();raw=w.read(prior/'data.000',2048);a.require(a.sha256(raw)=='0bc16095b26bc8d1e0c8d3aaba86502e9938f932ccf093e0c135531f1f2861b1','io_prior_identity');out.mkdir();sample=out/'raw-sample.bin';sample.write_bytes(bytes(range(256))*4);rng=random.Random(982470);counts={'vectors':0,'successful_status':0,'range_reject':0,'open_error':0,'read_error':0,'short_success':0}
 def check(addr,n,mode=0,read_error=0,open_error=0):
  r,data=io.compare(oracle,sample,addr,n,mode,read_error,open_error);counts['vectors']+=1
  kind='successful_status' if r['status']==0 else 'range_reject' if r['status']==10 and r['open_calls']==0 else 'open_error' if not r['read_calls'] else 'read_error';counts[kind]+=1
  if r['status']==0 and n and len(data)<n:counts['short_success']+=1
  return r
 for ar in (0,1,3,4,255,1022,1023,1024):
  for off in (0,480,668,1020,1024,(1<<30)-188,(1<<30)-1):
   for n in (0,1,188,4096):check((ar<<30)+off,n)
 for i in range(1500):check((rng.choice((0,3,4,1022,1023,1024))<<30)+rng.choice((rng.randrange(1200),(1<<30)-rng.randrange(4096))),rng.randrange(4097),rng.randrange(2),rng.choice((0,0,5,38,995)),rng.choice((0,0,7)))
 for addr in (1<<62,(1<<62)+480,(1<<64)-1):check(addr,188)
 observations={'archive_1023_rejected_before_open':check((1023<<30)+480,188)['open_calls']==0,'archive_1022_accepted':check((1022<<30)+480,188)['archive']==1022,'primitive_high_address_alias_observed':check((1<<62)+480,188)['status']==0,'short_read_returns_success_status':check(1020,20)['status']==0,'short_read_actual_count':check(1020,20)['actual_bytes'],'read_error5_maps_to8':check(480,188,read_error=5)['status']==8,'open_error7_preserved':check(480,188,open_error=7)['status']==7,'error38_is_success_zero_bytes_in_this_adapter':check(480,188,read_error=38)['status']==0}
 proofs=[]
 for ar in (0,3,4,1022):
  copied=bytearray(856)
  for off,key in ((480,K),(668,T)):copied[off:off+188]=header(ar,off,key)+raw[off+30:off+188]
  path=out/f'data.{ar:03d}';path.write_bytes(copied)
  for off,key,ck in ((480,K,CK),(668,T,TC)):
   index=lookup.build_index([bind.record(key,(ar<<30)+off,188)],[],fmt.bucket(key));found=lookup.compare(lookup_oracle,index,fmt.bucket(key),key)['lookup'];a.require(found['status']==0,'io_original_lookup');addr,size=found['range'];proof=io.read_numbered(oracle,span_oracle,{ar:path},addr,size,key,33940,ck);proof['original_lookup_returned_range']=found['range'];proofs.append(proof)
 w.check();result={'format':'agent-archive-io-experiments-1','matrix':counts,'all_native_model_equal':True,'observations':observations,'real_object_readbacks':proofs,'header_only_numbered_copies_zero_prefix_not_complete_storage':True,'source_fixture_unchanged':True,'source_ckey_derived_not_independent':True,'target_ckey_independent_encoding':True,'original_open_manager_executed':False,'ReadFile_boundary':'actual Linux pread64 on explicit read-only descriptor; injected errors labelled separately','windows_io_executed':False,'whole_agent_executed':False,'installation_ready':False};(out/'EXPERIMENT-RESULTS.json').write_text(json.dumps(result,indent=2)+'\n');return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('io-oracle','span-oracle','lookup-oracle','prior-owned-store','out-new'):p.add_argument('--'+n,type=Path,required=True)
 x=p.parse_args();r=run(x.io_oracle,x.span_oracle,x.lookup_oracle,x.prior_owned_store,x.out_new);print(json.dumps({'matrix':r['matrix'],'readbacks':len(r['real_object_readbacks'])}))
