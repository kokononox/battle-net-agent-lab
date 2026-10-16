"""Original header/address experiment and explicit small numbered research copies.
No download, install scan, writer/publication or archive I/O by Agent.
"""
import argparse,json,random,struct
from pathlib import Path
import agent_span_reader as s
import agent_lookup_merge as lookup
import agent_bind_contract as bind
import retail_lookup_cycle as gate
import synthetic_casc_format as fmt
import retail_storage_poc as safety
import source_binding as b
import patch_audit as a
K='914fcad4f4fcf4abb0ba52b197bb066f';CK='98ad7b81687304aa0e99cf326200adfe'
T='faedca88d0a0ab30dae5519239582d31';TC='3d42bf2e42127f313b0ec64cb440cde9'
def header(ar,off,size,key=K,flag=0,reserved=0):
 h=bytes.fromhex(key)[::-1]+struct.pack('<I',size)+bytes((flag,reserved));h+=struct.pack('<I',fmt.hashlittle2(h,0x3d6be971)[0]);return h+fmt.checksum_b(h,ar,off)
def run(oracle,lookup_oracle,prior,out):
 oracle=s.oracle_identity(oracle);gate.oracle_identity(lookup_oracle);out=safety.safe_new(out);watch=b.Watch();raw=watch.read(prior/'data.000',2048)
 a.require(len(raw)==856 and a.sha256(raw)=='0bc16095b26bc8d1e0c8d3aaba86502e9938f932ccf093e0c135531f1f2861b1','span_experiment_prior_identity')
 rng=random.Random(9824713);counts={'vectors':0,'accepted':0,'rejected':0}
 def check(h,addr,available=30):
  v=s.compare(oracle,h,addr,available);counts['vectors']+=1;counts['accepted' if v['valid'] else 'rejected']+=1;return v
 for ar in (0,1,2,3,4,255,256,1023):
  for off in range(480,496):check(header(ar,off,188),(ar<<30)+off)
 for flag in range(256):check(header(0,480,188,flag=flag),480)
 for bit in range(240):
  h=bytearray(header(0,480,188));h[bit//8]^=1<<(bit%8);a.require(not check(bytes(h),480)['valid'],'span_single_bit_corruption')
 for i in range(2000):
  ar=rng.randrange(1024);off=rng.randrange(1<<30);size=rng.randrange(1<<32);key=rng.randbytes(16).hex();h=header(ar,off,size,key,rng.randrange(4),rng.randrange(256));addr=(ar<<30)+off
  if i%3==0:
   h=bytearray(h);h[rng.randrange(30)]^=1<<rng.randrange(8);h=bytes(h)
  check(h,addr,rng.choice((0,29,30,31,188,0xffffffff)))
 # Exercise original u64 getters and checksum arithmetic at extreme low-DWORDs.
 for addr in (0,0x3fffffff,0xffffffff,0x100000000,0x12345678ffffffff,(1<<64)-1):
  off=addr&0x3fffffff;ar=(addr>>30)&1023;check(header(ar,off,188),addr)
 # Counterexample: high bits are not authenticated by a 32-bit position checksum.
 high_alias=check(header(0,480,188),(4<<30)+480)
 a.require(high_alias['valid'] and high_alias['archive']==4,'span_high_alias_observation')
 counts.update(format='agent-span-reader-matrix-1',all_original_model_equal=True,single_bit_corruptions_rejected=240,helpers_mocked=0,high_bits_not_authenticated_by_header_alone=True)
 out.mkdir();files={};proofs=[]
 for ar in (0,3,4,1023):
  # Header fixtures only: no pretend complete prefix or full installation.
  copied=bytearray(856)
  for off,key,ck in ((480,K,CK),(668,T,TC)):
   copied[off:off+188]=header(ar,off,188,key)+raw[off+30:off+188]
  path=out/f'data.{ar:03d}';path.write_bytes(copied);files[ar]=path
 for ar in files:
  for off,key,ck in ((480,K,CK),(668,T,TC)):
   index=lookup.build_index([bind.record(key,(ar<<30)+off,188)],[],fmt.bucket(key));found=lookup.compare(lookup_oracle,index,fmt.bucket(key),key)['lookup'];a.require(found['performed'] and found['status']==0,'span_bridge_actual_lookup');addr,size=found['range'];proof=s.read_numbered(oracle,files,addr,size,key,33940,ck);proof.update(original_lookup_returned_range=found['range'],fixture='small header-only research copy; zero prefix, not a complete multiarchive storage');proofs.append(proof)
 watch.check();result={'format':'agent-span-reader-experiments-1','matrix':counts,'bridge_objects':proofs,'source_fixture_sha256_unchanged':a.sha256(watch.read(prior/'data.000',2048)),'original_parser_checks_available_header_only_not_full_span_or_payload':True,'source_ckey_is_derived_not_independent_expected':True,'target_ckey_independently_from_encoding':True,'file_io_and_blte_are_independent_python':True,'whole_agent_or_windows_io_executed':False,'game_lab_original_portable_release_changed':False,'installation_ready':False};watch.check()
 (out/'EXPERIMENT-RESULTS.json').write_text(json.dumps(result,indent=2)+'\n');return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--span-oracle',type=Path,required=True);p.add_argument('--lookup-oracle',type=Path,required=True);p.add_argument('--prior-owned-store',type=Path,required=True);p.add_argument('--out-new',type=Path,required=True);x=p.parse_args();r=run(x.span_oracle,x.lookup_oracle,x.prior_owned_store,x.out_new);print(json.dumps({'matrix':r['matrix'],'bridge_objects':len(r['bridge_objects']),'installation_ready':False},indent=2))
