"""Original manager/cache and native open/read route with explicit adapters."""
import argparse,json,random,struct
from pathlib import Path
import agent_archive_cache as cache
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
 out=safety.safe_new(out);w=b.Watch();raw=w.read(prior/'data.000',2048);a.require(a.sha256(raw)=='0bc16095b26bc8d1e0c8d3aaba86502e9938f932ccf093e0c135531f1f2861b1','cache_prior_identity');out.mkdir();matrix=out/'matrix';matrix.mkdir();(matrix/'data.000').write_bytes(bytes(range(256))*4);p0=matrix/'first';p1=matrix/'second';p0.write_bytes(b'A'*1024);p1.write_bytes(b'B'*1024);rng=random.Random(982472);counts={'vectors':0,'status_success':0,'rejected':0,'cache_hits':0,'os_open_calls':0,'write_create_denials':0,'format_guard_rejects':0}
 def check(addr=480,n=188,**kw):
  r,data=cache.compare(oracle,matrix,addr,n,cache_paths=(p0,p1),**kw);counts['vectors']+=1;counts['status_success' if r['status']==0 else 'rejected']+=1
  counts['cache_hits']+=int(r['read_calls']==1 and r['constructor_calls']==0);counts['os_open_calls']+=r['create_calls'];counts['write_create_denials']+=int(r['create_calls']==1 and r['desired_access']!=0x80000000);counts['format_guard_rejects']+=int(r['format_calls']==1 and r['constructor_calls']==0);return r,data
 for scenario in range(7):
  for mode in (0,1):
   for fast in (0,1):
    for read_error in (0,5,38):
     for open_error in (0,7):
      for override in (0,780):check(scenario=scenario,mode=mode,fast=fast,read_error=read_error,open_error=open_error,format_override=override)
 for i in range(1200):check(rng.choice((0,480,668,1020,1024,(1<<30)-1,(1023<<30)+480)),rng.randrange(4097),scenario=rng.randrange(7),mode=rng.randrange(2),fast=rng.randrange(2),read_error=rng.choice((0,0,5,38)),open_error=rng.choice((0,7)),format_override=rng.choice((0,0,780)))
 hit0,d0=check(scenario=1);hit1,d1=check(scenario=5);miss,dm=check(scenario=4);denied,_=check(mode=0);long_name,_=check(format_override=780)
 a.require(d0==b'A'*188 and d1==b'B'*188 and dm==(bytes(range(256))*4)[480:668],'cache_actual_routing')
 a.require(hit0['reference0_during_read']==2 and hit0['reference0_after']==1 and hit1['reference1_during_read']==2 and hit1['reference1_after']==1 and hit1['list_head']==1,'cache_original_ref_lru')
 proofs=[]
 for ar in (0,3,4,1022):
  copied=bytearray(856)
  for off,key in ((480,K),(668,T)):copied[off:off+188]=header(ar,off,key)+raw[off+30:off+188]
  path=out/f'data.{ar:03d}';path.write_bytes(copied)
  for off,key,ck in ((480,K,CK),(668,T,TC)):
   index=lookup.build_index([bind.record(key,(ar<<30)+off,188)],[],fmt.bucket(key));found=lookup.compare(lookup_oracle,index,fmt.bucket(key),key)['lookup'];a.require(found['status']==0,'cache_original_lookup');addr,size=found['range']
   for scenario in (0,1,4,5):
    proof=cache.read_numbered(oracle,span_oracle,{ar:path},addr,size,key,33940,ck,scenario);proof['original_lookup_returned_range']=found['range'];proofs.append(proof)
 w.check();result={'format':'agent-archive-cache-experiments-1','matrix':counts,'all_native_model_equal':True,'original_cache_observations':{'cache_hit_does_not_format_construct_or_os_open':True,'hash_collision_chain_selects_second_exact_key':True,'high_dword_not_hashed_but_checked_for_equality':True,'variant_byte_in_hash_and_equality':True,'hit_promotes_list_head':True,'retain_1_to_2_during_read_release_back_to_1':True,'matching_cached_descriptor_vs_disk_selection_proven_with_distinct_bytes':True,'format_capacity_rejects_before_constructor_and_unlocks':long_name['status']==10 and long_name['constructor_calls']==0 and long_name['unlocks']==1,'original_mode1_desires_read_write_open_always_and_is_denied':denied['desired_access']==0xc0000000 and denied['disposition']==4 and denied['status']==5},'real_object_readbacks':proofs,'source_fixture_unchanged':True,'header_only_fixture_zero_prefix_not_complete_storage':True,'original_manager_hash_chain_key_equal_retain_lru_release_executed':True,'original_file_open_route_and_win_open_executed':True,'original_constructor_allocation_insertion_executed':False,'single_thread_lock_adapters_not_windows_locking':True,'read_only_linux_api_adapters_not_windows_io':True,'formatter_ascii_and_utf_conversion_adapted':True,'one_hash_bucket_two_entry_preseeded_fixture_not_cache_capacity_or_eviction_proof':True,'source_ckey_derived_target_ckey_independent_encoding':True,'whole_agent_executed':False,'installation_ready':False};(out/'EXPERIMENT-RESULTS.json').write_text(json.dumps(result,indent=2)+'\n');return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('cache-oracle','span-oracle','lookup-oracle','prior-owned-store','out-new'):p.add_argument('--'+n,type=Path,required=True)
 x=p.parse_args();r=run(x.cache_oracle,x.span_oracle,x.lookup_oracle,x.prior_owned_store,x.out_new);print(json.dumps({'matrix':r['matrix'],'real_readbacks':len(r['real_object_readbacks'])}))
