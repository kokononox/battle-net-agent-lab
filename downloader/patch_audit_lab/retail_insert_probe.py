"""Real portable Retail pair -> bounded original cache insertion + span parser.
Only freshly created marked research fixtures. No index/publication/Windows proof.
BLTE decoding and exact EKey/CKey validation remain independent Python.
"""
import argparse,json,struct
from pathlib import Path
import agent_archive_insert as insert
import agent_span_reader as span
import archive_prefix_poc as prefix
import encoding_target as encoding
import name_seed_model as names
import patch_audit as a
import portable_run
import refs_source_check as blte
import source_binding as b
import staging_sample as sample
import synthetic_casc_format as fmt
import synthetic_casc_store as fs
import retail_storage_poc as safety
SOURCE=sample.OPTION['source_ekey'];TARGET=safety.EK
SOURCE_CK=sample.OBSERVED['derived_source_ckey'];TARGET_CK=safety.CK

def prepare(portable,out):
 """Verify once from reviewed code, then create only a NEW owned 2-archive fixture."""
 portable=b.safe(portable);out=safety.safe_new(out)
 a.require(portable not in out.parents,'insert_probe_output_in_input')
 proof=portable_run.run(portable);watch=b.Watch()
 source=watch.read(portable/'source.blte');patch=watch.read(portable/'sample.zbsdiff')
 old,_=blte.decode_source(source,SOURCE,33940);decoded,_=sample.rebuild(old,patch)
 assessment,target=encoding.assess(decoded,{'ekey':TARGET,'encoded_size':158,'espec':'b:{256K*=z}'})
 a.require(assessment['exact_target_ekey_reproduced'] and target is not None and a.sha256(target)==safety.ENCODED_SHA,'insert_probe_exact_target')
 seed=bytes.fromhex(names.model('LAB-PC',r'C:\Games\World of Warcraft\Data')['seed'])
 files={insert.MARKER:safety.canonical({'format':'archive-insert-owned-fixture-1'})}
 for archive in (0,1):
  files[f'data.{archive:03d}']=prefix.prefix(seed,archive,1024)+fmt.make_span(source,SOURCE,33940,archive,480)+fmt.make_span(target,TARGET,33940,archive,668)
 watch.check();out.mkdir()
 for name,raw in files.items():fs.write_new(out/name,raw)
 fs.sync_dir(out)
 return {'format':'retail-insert-probe-input-1','portable_verification':proof,'fixture_files':{n:{'bytes':len(v),'sha256':a.sha256(v)} for n,v in files.items()},'source_ckey_is_derived_not_independent':True,'seed_is_explicit_research_input':True,'indexes_or_control_created':False,'installation_ready':False}

def validate_rows(span_oracle,addresses,rows):
 a.require(len(addresses)==len(rows),'insert_probe_row_count');insert.require_exact(rows,188);proofs=[]
 for address,(trace,chunk) in zip(addresses,rows):
  archive=address>>30;offset=address&0x3fffffff
  a.require(archive in (0,1) and offset in (480,668),'insert_probe_address_profile')
  key,ckey=(SOURCE,SOURCE_CK) if offset==480 else (TARGET,TARGET_CK)
  parsed=span.compare(span_oracle,chunk[:30],address,188)
  a.require(parsed['valid'],'insert_probe_original_header_rejected')
  record=bytes.fromhex(parsed['record']);stored_address,stored_size=struct.unpack_from('<QQ',record,16)
  a.require(record[:16].hex()==key and stored_address==address and stored_size==188 and record[32]==0,'insert_probe_header_identity')
  a.require(parsed['archive']==archive and parsed['payload_offset']==offset+30,'insert_probe_original_address')
  decoded,_=fmt.read_span(chunk,key,33940,ckey,archive,offset)
  expected_sha=sample.OBSERVED['encoded_sha256'] if offset==480 else safety.ENCODED_SHA
  a.require(a.sha256(chunk[30:])==expected_sha,'insert_probe_encoded_identity')
  a.require((trace['new_reference_during_read'],trace['new_reference_after'])==(2,1),'insert_probe_reference_lifetime')
  proofs.append({'address':address,'archive':archive,'offset':offset,'ekey':key,'ckey':a.md5(decoded),'decoded_bytes':len(decoded),'encoded_sha256':expected_sha,'trace':trace})
 return proofs

def probe(insert_oracle,span_oracle,root,addresses,**kw):
 rows=insert.compare(insert_oracle,root,addresses,188,**kw)
 return validate_rows(span_oracle,addresses,rows)

def run(portable,out,insert_oracle,span_oracle):
 insert.oracle_identity(insert_oracle);span.oracle_identity(span_oracle)
 prepared=prepare(portable,out)
 cases={
  'same_archive_source_target_source_target':[480,668,480,668],
  'two_archives_source_then_target':[480,(1<<30)+480,668,(1<<30)+668],
 }
 results={name:probe(insert_oracle,span_oracle,out,ads) for name,ads in cases.items()}
 for name,rows in results.items():
  expected=[1]*4 if name.startswith('same_') else [1,2,2,2]
  a.require([r['trace']['create_calls'] for r in rows]==expected and [r['trace']['constructor_calls'] for r in rows]==expected,'insert_probe_reuse')
 return {'format':'retail-original-insert-probe-1','inputs':prepared,'cases':results,'native_payload_reads':8,'original_insert_cache_and_span_parser_executed':True,'one_process_per_case_not_one_per_read':True,'blte_decode_implementation':'independent Python','source_target_addresses_are_explicit_not_native_lookup':True,'publication_resume_tested':False,'windows_agent_executed':False,'installation_ready':False}

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--portable',type=Path,required=True);p.add_argument('--out-new',type=Path,required=True);p.add_argument('--insert-oracle',type=Path,required=True);p.add_argument('--span-oracle',type=Path,required=True);x=p.parse_args()
 print(json.dumps(run(x.portable,x.out_new,x.insert_oracle,x.span_oracle),indent=2))
