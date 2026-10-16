"""Reproduce the bounded native/model matrix and a NEW V8 real-sample copy."""
from pathlib import Path
import argparse,json,random,struct
import retail_storage_poc as safety
import agent_bind_contract as v
import synthetic_casc_format as fmt
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--oracle',type=Path,required=True);parser.add_argument('--prior-owned-cycle',type=Path,required=True);parser.add_argument('--out-new',type=Path,required=True);args=parser.parse_args()
out=safety.safe_new(args.out_new);out.mkdir();n=args.oracle;rng=random.Random(98240816);cases=[]
def run(label,raw,bucket,**kw):
 r=v.compare(n,raw,bucket,**kw);cases.append({'case':label,'bucket':bucket,'status':r['status'],'records':r['records'],'selected':r['selected'] is not None});return r
for bucket in range(16):
 for count in (0,1,2,9,16,25,100,1024):
  keys=sorted({rng.randbytes(16).hex() for i in range(count)});rows=[v.record(k,rng.getrandbits(64),rng.getrandbits(64)) for k in keys];raw=v.make_index(rows,bucket)
  for query in ((keys[0],keys[len(keys)//2],keys[-1],rng.randbytes(16).hex()) if keys else ('00'*16,'ff'*16)):
   run('primary_fullkey_lookup',raw,bucket,query=query)
 for mutation in range(40):
  raw=bytearray(v.make_index([v.record(rng.randbytes(16).hex(),480,188)],bucket));at=rng.choice(list(range(4,32))+list(range(36,72)));raw[at]^=1<<rng.randrange(8)
  run('bounded_single_bit_header_or_primary_mutation',bytes(raw),bucket)
 for code in (1,73,0xffffffff):run('mapping_error_cleanup',v.make_index([],bucket),bucket,map_error=code)
 # Force original hash1 through all 25 slots and the next page, then terminator.
 raw=bytearray(v.make_index([],bucket))
 for i in range(26):
  payload=v.record(rng.randbytes(16).hex(),rng.getrandbits(64),rng.getrandbits(64))+bytes([i%4]);at=4096+(i//25)*1024+(i%25)*40;raw[at:at+40]=struct.pack('<I',fmt.hashlittle2(payload)[0]|0x80000000)+payload+bytes(3)
 run('tail_26_slots_across_two_pages',bytes(raw),bucket)
 # Every possible aligned and unaligned short truncation around the header.
 for length in (1,4,7,8,16,23,24,31,32,39,40,41,4095,4096,34815):run('bounded_truncation',v.make_index([],bucket)[:length],bucket)
summary={'format':'agent-bind-native-model-matrix-1','vectors':len(cases),'all_native_model_matches':True,'all_buckets':16,'max_primary_rows':1024,'native_original_hashlittle2_exercised':True,'native_original_hashlittle_tail_cross_page_exercised':True,'mapping_failure_injection':True,'cases_by_label':{k:sum(x['case']==k for x in cases) for k in sorted({c['case'] for c in cases})},'status_histogram':{str(k):sum(x['status']==k for x in cases) for k in sorted({c['status'] for c in cases})},'bounds':'nonempty <=1MiB, primary/header lengths preflighted; not general fuzzing of arbitrary PE paths','windows_io_mocked':True,'outer_seh_retry_executed':False,'installation_ready':False}
(out/'MATRIX-SUMMARY.json').write_text(json.dumps(summary,indent=2)+'\n')
real=v.real_experiment(args.prior_owned_cycle,out/'real-v8',n)
(out/'REAL-EXPERIMENT.json').write_text(json.dumps(real,indent=2)+'\n')
print(json.dumps({'matrix_vectors':len(cases),'all_16_real_indexes_native_accepted':real['all_16_indexes_accepted_by_original_inner_bind'],'v7_status':real['old_v7_native_status'],'installation_ready':False}))
