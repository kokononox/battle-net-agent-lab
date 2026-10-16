"""Reproduce real-object, native rejection and isolated interruption receipts."""
from pathlib import Path
import json,sys,subprocess,hashlib,struct,tempfile
pkg=Path(__file__).resolve().parents[2];sys.path.insert(0,str(pkg))
import retail_storage_poc as p
import encoding_target as e
import synthetic_casc_format as fmt
import agent_allocator_model as alloc
import shmem_primary_readonly as observation
import patch_audit as a
import argparse
parser=argparse.ArgumentParser(description='Owned research fixtures only; no game installation or activation writes')
parser.add_argument('--fixture',required=True,type=Path);parser.add_argument('--native-oracle',required=True,type=Path);parser.add_argument('--report-new',required=True,type=Path)
args=parser.parse_args();fixture=p.b.safe(args.fixture);native=p.b.safe(args.native_oracle,True);out=p.safe_new(args.report_new)
a.require(fixture not in out.parents,'research_output_inside_fixture');out.mkdir()
# Fresh end-to-end run includes the whole original manifest and pinned Encoding.
real=p.run(fixture,out/'real-retail-poc',native)
(out/'REAL-RETAIL-READBACK.json').write_text(json.dumps(real,indent=2)+'\n')
decoded=(fixture/'target.decoded').read_bytes();encoded=e.encode(decoded,'b:{256K*=z}')
results={'format':'retail-storage-experiments-1','actual_retail_sample':True,'agent_executed':False,'windows_or_power_loss_tested':False,'installation_ready':False,'archive_prefix_placeholder':True,'native_vectors':[],'negative_native_cases':[],'process_exit_matrix':[],'memory_rollback_snapshots':[]}
with tempfile.TemporaryDirectory(prefix='retail-poc-evidence-') as tmp:
 root=Path(tmp)
 for archive in (0,3,4,1023):
  for shift in range(16):
   offset=480+shift;span=fmt.make_span(encoded,p.EK,len(decoded),archive,offset)
   data=root/f'data.{archive:03d}';index=root/p.expected_index();data.write_bytes(bytes(offset)+span);index.write_bytes(fmt.make_index([{'ekey':p.EK,'archive':archive,'offset':offset,'span':len(span)}],fmt.bucket(p.EK)))
   got=subprocess.run([str(native),str(index),str(data),p.EK,p.CK,str(archive)],capture_output=True,text=True,timeout=15)
   assert got.returncode==0,(archive,shift,got.stdout,got.stderr)
   results['native_vectors'].append({'archive':archive,'offset':offset,'accepted':True})
 generated=root/'corruption';p.materialize(generated,encoded,decoded);data=generated/'data.000';index=generated/p.expected_index();original=data.read_bytes();index_original=index.read_bytes()
 for label,at in [('full_ekey',480),('span_size',496),('hash_a',502),('checksum_b',506),('blte_signature',510),('chunk_data',550),('chunk_tail',667)]:
  raw=bytearray(original);raw[at]^=1;data.write_bytes(raw);got=subprocess.run([str(native),str(index),str(data),p.EK,p.CK],capture_output=True,text=True,timeout=15);assert got.returncode!=0
  results['negative_native_cases'].append({'case':label,**json.loads(got.stdout)})
 data.write_bytes(original[:-1]);got=subprocess.run([str(native),str(index),str(data),p.EK,p.CK],capture_output=True,text=True,timeout=15);assert got.returncode!=0;results['negative_native_cases'].append({'case':'truncated_data',**json.loads(got.stdout)})
 data.write_bytes(original);idx=bytearray(index_original);idx[-1]^=1;index.write_bytes(idx);got=subprocess.run([str(native),str(index),str(data),p.EK,p.CK],capture_output=True,text=True,timeout=15);assert got.returncode!=0;results['negative_native_cases'].append({'case':'index_checksum',**json.loads(got.stdout)});index.write_bytes(index_original)
 for label,ek,ck in [('same_prefix_wrong_full_ekey',p.EK[:18]+'00'*7,p.CK),('wrong_decoded_ckey',p.EK,'00'*16)]:
  got=subprocess.run([str(native),str(index),str(data),ek,ck],capture_output=True,text=True,timeout=15);assert got.returncode!=0;results['negative_native_cases'].append({'case':label,**json.loads(got.stdout)})
 inp=root/'input.decoded';inp.write_bytes(decoded)
 for phase in p.PHASES:
  dest=root/phase
  code="import sys;from pathlib import Path;import retail_storage_poc as p;import encoding_target as e;d=Path(sys.argv[2]).read_bytes();p.materialize(Path(sys.argv[1]),e.encode(d,'b:{256K*=z}'),d,sys.argv[3])"
  got=subprocess.run([sys.executable,'-B','-c',code,str(dest),str(inp),phase],cwd=pkg,capture_output=True,text=True,timeout=15);assert got.returncode==91,got.stderr
  valid=False
  try:p.verify(dest);valid=True
  except a.AuditError:pass
  assert valid==(phase=='receipt_written')
  results['process_exit_matrix'].append({'phase':phase,'exit_code':91,'fixture_complete':valid,'not_a_game_activation_test':True,'existing_data_preserved':(dest/'data.000').read_bytes()==original,'no_build_info_or_active_json':not (dest/'.build.info').exists() and not (dest/'active.json').exists()})
raw=alloc.make([(500,480)])
for phase,snapshot in alloc.update_frames(raw,0,312,668):
 recovered=alloc.recover(snapshot);expected=[(312,668)] if phase=='committed_one' else [(500,480)];assert alloc.records(recovered)==expected and alloc.recover(recovered)==recovered
 results['memory_rollback_snapshots'].append({'phase':phase,'pending':observation.inspect(snapshot)['rollback_pending'],'old_arrays_restored_or_retained':alloc.records(recovered)==[(500,480)],'new_arrays_retained':alloc.records(recovered)==[(312,668)],'repeat_recovery_idempotent':True,'in_memory_model_only':True})
results['summary']={'native_positive_vectors':len(results['native_vectors']),'native_negative_cases_rejected':len(results['negative_native_cases']),'builder_process_exit_points':len(results['process_exit_matrix']),'rollback_memory_snapshots':len(results['memory_rollback_snapshots'])}
(out/'EXPERIMENT-RESULTS.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results['summary']))
