"""Reproduce bounded original-constructor/cache insertion on synthetic bytes only."""
import argparse,collections,hashlib,json,random
from pathlib import Path
import agent_archive_insert as n
import retail_storage_poc as safety
import patch_audit as a

def run(oracle,out):
 out=safety.safe_new(out);out.mkdir();fixture=out/'fixture';fixture.mkdir();(fixture/n.MARKER).write_text(json.dumps({'format':'archive-insert-owned-fixture-1'}))
 ars=[0,3,4,1022]
 for ar in ars:(fixture/f'data.{ar:03d}').write_bytes(bytes((i*17+ar)%256 for i in range(2048)))
 before={p.name:a.sha256(p.read_bytes()) for p in fixture.iterdir()};rng=random.Random(9824);stats=collections.Counter();cases=[]
 for i in range(1024):
  kind=i%8;ar=rng.choice(ars);ad=(ar<<30)+rng.randrange(480,1900);ads=[ad,ad+1,ad,ad+2];length=rng.randrange(1,256);kw={}
  if kind==1:kw={'read_error':5,'read_error_on':1}
  elif kind==2:kw={'open_error':5,'open_error_on':1}
  elif kind==3:kw={'open_error':32,'open_error_on':1}
  elif kind==4:kw={'read_error':38,'read_error_on':2}
  elif kind==5:
   other=rng.choice([x for x in ars if x!=ar]);ads=[ad,(other<<30)+(ad&0x3fffffff),ad,(other<<30)+(ad&0x3fffffff)]
  elif kind==6:kw={'fast':1}
  elif kind==7:kw={'mode':0}
  rows=n.compare(oracle,fixture,ads,length,**kw);stats['cases']+=1;stats['reads_requested']+=len(rows)
  for r,data in rows:
   stats['status_zero' if r['status']==0 else 'status_nonzero']+=1
   if r['status']==0 and r['actual_bytes']==length:stats['exact_success']+=1
   elif r['status']==0:stats['success_but_inexact']+=1
  cases.append({'case':i,'kind':kind,'addresses':ads,'length':length,'controls':kw,'trace':[{'status':r['status'],'bytes':r['actual_bytes'],'opens':r['create_calls'],'allocations':r['constructor_calls'],'table_count':r['reference0_after'],'reference_during':r['new_reference_during_read'],'reference_after':r['new_reference_after'],'data_sha256':a.sha256(data)} for r,data in rows]})
 after={p.name:a.sha256(p.read_bytes()) for p in fixture.iterdir()};a.require(before==after,'insert_fixture_unchanged');(out/'MATRIX.json').write_text(json.dumps(cases,indent=2)+'\n')
 receipt=json.loads((oracle.parent/'BUILD-RECEIPT.json').read_text());summary={'format':'archive-insert-experiments-1','input_kind':'deterministic synthetic byte fixtures, NOT the uploaded Retail fixture','stats':dict(stats),'all_model_comparisons_passed':True,'fixture_unchanged':True,'fixture_sha256':before,'matrix_sha256':a.sha256((out/'MATRIX.json').read_bytes()),'oracle_sha256':receipt['binary_sha256'],'original_code_bytes':receipt['original_code_bytes'],'original_fragment_count':len([v for v in receipt['fragments'] if v['kind']=='code']),'original_constructor_and_hash_insertion':True,'whole_agent_executed':False,'windows_executed':False,'retail_fixture_tested_this_session':False,'historical_full_suite_rerun':False,'installation_ready':False}
 (out/'EXPERIMENT-RESULTS.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2));return summary
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--oracle',type=Path,required=True);p.add_argument('--out-new',type=Path,required=True);x=p.parse_args();run(x.oracle,x.out_new)
