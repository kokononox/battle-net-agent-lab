"""Offline single-pair Retail RESEARCH updater CLI, Linux only.
init -> plan -> update/resume -> status -> export in NEW owned paths.
Not a full-game updater, download client, Windows installer, or live-install writer.
"""
import argparse,fcntl,json,os,stat,uuid
from contextlib import contextmanager
from pathlib import Path
import archive_prefix_poc as prefix
import encoding_target as encoding
import name_seed_model as names
import patch_audit as a
import portable_run
import retail_direct_cycle as engine
import retail_storage_poc as safety
import retail_update_cycle as legacy
import source_binding as b
import synthetic_casc_format as fmt
import synthetic_casc_store as fs
MARKER='SAMPLE-UPDATER-RESEARCH.json'
ROLES=('bind','lookup','span','direct')
LAYOUT={MARKER,'LOCK','origin.json','tools.json','cycle'}

def canonical(obj):return safety.canonical(obj)
def _load(root):
 root=b.safe(root);fs.no_game_ancestors(root);a.require(set(os.listdir(root))==LAYOUT,'sample_workspace_layout')
 w=b.Watch();marker=b.json_object(w.read(root/MARKER,4096))
 a.require(set(marker)=={'format','workspace_id','origin_sha256','tools_sha256','cycle_workspace_id','installation_ready'} and marker['format']=='retail-sample-updater-1' and marker['installation_ready'] is False,'sample_workspace_marker')
 for key in ('workspace_id','cycle_workspace_id'):a.require(str(uuid.UUID(marker[key]))==marker[key],'sample_workspace_uuid')
 origin_raw=w.read(root/'origin.json',65536);tools_raw=w.read(root/'tools.json',65536)
 a.require(a.sha256(origin_raw)==marker['origin_sha256'] and a.sha256(tools_raw)==marker['tools_sha256'],'sample_workspace_configuration_hash')
 origin=b.json_object(origin_raw);tools=b.json_object(tools_raw)
 a.require(origin.get('format')=='retail-sample-input-proof-1' and origin.get('portable_verification',{}).get('status')=='source_patch_target_and_encoding_verified','sample_origin_proof')
 a.require(origin['portable_verification']['target_ckey']==engine.base.old.CK and isinstance(origin.get('portable_root'),str) and Path(origin['portable_root']).is_absolute(),'sample_origin_profile')
 a.require(set(tools)==set(ROLES) and all(isinstance(tools[n],dict) and set(tools[n])=={'path','sha256'} for n in ROLES),'sample_tools_schema')
 oracles=[]
 for name in ROLES:
  p=w.file(tools[name]['path']);a.require(a.sha256(w.read(p,2*1024**2))==tools[name]['sha256'],'sample_tool_digest_changed');oracles.append(p)
 engine.identities(*oracles)
 cycle_marker=b.json_object(w.read(root/'cycle'/engine.base.MARKER,4096));a.require(cycle_marker['workspace_id']==marker['cycle_workspace_id'],'sample_cycle_identity')
 lock=w.file(root/'LOCK');a.require(lock.stat().st_size==1,'sample_lock_shape');w.check()
 return root,origin,oracles,w

@contextmanager
def locked(root):
 root,origin,oracles,w=_load(root)
 with (root/'LOCK').open('r+b') as lock:
  a.require(b.fp(os.fstat(lock.fileno()))==w.files[root/'LOCK'],'sample_lock_descriptor_identity')
  try:fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:raise a.AuditError('sample_workspace_busy') from None
  try:yield root,origin,oracles
  finally:fcntl.flock(lock.fileno(),fcntl.LOCK_UN);w.check()

def _public(state):
 return {'format':'retail-sample-updater-status-1','profile':'offline-pinned-single-retail-pair','network_download_supported':False,'installation_ready':False,'target_published':state['target_published'],'resume_state':state['custom_resume_state'],'data_bytes':state['data_bytes'],'native_io_on_locked_live_archive':state['native_io_on_locked_live_archive'],'native_read_addresses':state['native_read_addresses'],'idempotent_noop':state.get('idempotent_noop',False),'engine':state}

def init(portable,out,oracles):
 portable=b.safe(portable);out=safety.safe_new(out);a.require(portable not in out.parents,'sample_output_in_portable');engine.identities(*oracles)
 proof=portable_run.run(portable);a.require(any(r.get('exact_target_ekey_reproduced') and r['ekey']==legacy.TARGET for r in proof['encoding_options']),'sample_official_target_encoding')
 w=b.Watch();source=w.read(portable/'source.blte');patch=w.read(portable/'sample.zbsdiff');manifest=w.read(portable/'PORTABLE-MANIFEST.json',65536);legacy.inputs(source,patch)
 seed_result=names.model('LAB-PC',r'C:\Games\World of Warcraft\Data');seed=bytes.fromhex(seed_result['seed'])
 cycle_id=str(uuid.uuid4());cycle_marker={'format':'owned-retail-v8-cycle-1','workspace_id':cycle_id,'seed':seed.hex(),'not_installation':True,'value_qwords':'fixture-policy-offset-span','custom_journal_not_agent':True}
 tools={name:{'path':str(b.safe(path,True)),'sha256':a.sha256(fs.read(path,2*1024**2))} for name,path in zip(ROLES,oracles)}
 origin={'format':'retail-sample-input-proof-1','portable_root':str(portable),'portable_manifest_sha256':a.sha256(manifest),'portable_verification':proof,'name_seed':seed_result,'source_ckey_is_derived_not_independent':True,'remote_download_performed':False}
 tools_raw=canonical(tools);origin_raw=canonical(origin)
 marker={'format':'retail-sample-updater-1','workspace_id':str(uuid.uuid4()),'origin_sha256':a.sha256(origin_raw),'tools_sha256':a.sha256(tools_raw),'cycle_workspace_id':cycle_id,'installation_ready':False}
 w.check();out.mkdir();cycle=out/'cycle';cycle.mkdir()
 for name,raw in [('LOCK',b'\0'),('origin.json',origin_raw),('tools.json',tools_raw)]:fs.write_new(out/name,raw)
 data=prefix.prefix(seed,0,1024)+fmt.make_span(source,legacy.SOURCE,33940,0,480)
 for name,raw in [(engine.base.MARKER,canonical(cycle_marker)),('LOCK',b'\0'),('data.000',data),('PATCH.zbsdiff',patch),('shmem',legacy.control(False))]:fs.write_new(cycle/name,raw)
 for bucket,raw in engine.base.tables(seed,False).items():fs.write_new(cycle/legacy.idx(bucket,1),raw)
 fs.sync_dir(cycle)
 # Publish the top-level marker last. Interrupted init is fail-closed, not resumable.
 fs.write_new(out/MARKER,canonical(marker));fs.sync_dir(out);w.check();result=status(out);result['portable_verified_at_init']=True;return result

def status(root):
 with locked(root) as (root,origin,oracles):return _public(engine.status(root/'cycle',*oracles))
def plan(root):
 with locked(root) as (root,origin,oracles):
  state=engine.status(root/'cycle',*oracles)
  return {'format':'retail-sample-updater-plan-1','profile':'offline-pinned-single-retail-pair','action':'already_published' if state['target_published'] else 'apply_verified_saved_patch','source_ekey':legacy.SOURCE,'target_ekey':legacy.TARGET,'target_ckey':safety.CK,'decoded_target_bytes':33940,'encoded_target_bytes':158,'patch_bytes':117,'network_requests':0,'full_game_build_plan':False,'installation_ready':False}
def update(root,fail_after=None):
 with locked(root) as (root,origin,oracles):return _public(engine.advance(root/'cycle',*oracles,fail_after=fail_after))
def export(root,out):
 with locked(root) as (root,origin,oracles):
  out=safety.safe_new(out)
  a.require(root not in out.parents and Path(origin['portable_root']) not in out.parents,'sample_export_in_input_or_workspace')
  cycle=root/'cycle'
  with engine.base.locked(cycle):
   view=engine.base.inspect(cycle);a.require(view['updated'] and view['journal']['state']=='committed','sample_export_requires_committed_target')
   proof=engine.gate(cycle,view,*oracles[1:]);target=next(o for o in proof['lookup_gate_objects'] if o['ekey']==legacy.TARGET)
   rows=engine.direct.compare(oracles[3],cycle,[target['returned_offset']],target['returned_span']);engine.payload.validate_rows(oracles[2],[target['returned_offset']],rows)
   decoded,_=fmt.read_span(rows[0][1],legacy.TARGET,33940,safety.CK,0,target['returned_offset'])
   a.require(a.sha256(decoded)==encoding.TARGET_SHA256,'sample_export_decoded_identity')
   tmp=out.with_name('.retail-sample-export-'+uuid.uuid4().hex+'.tmp')
   try:
    fs.write_new(tmp,decoded);legacy.publish_index_noreplace(tmp,out);fs.sync_dir(out.parent)
   finally:
    if tmp.exists():tmp.unlink()
   a.require(fs.read(out,65536)==decoded,'sample_export_readback')
   return {'format':'retail-sample-updater-export-1','output':str(out),'bytes':len(decoded),'ckey':a.md5(decoded),'sha256':a.sha256(decoded),'read_from_committed_live_cycle':True,'existing_file_overwritten':False,'installation_ready':False}

def main():
 p=argparse.ArgumentParser(description=__doc__);subs=p.add_subparsers(dest='mode',required=True)
 for mode in ('init','status','plan','update','export'):
  q=subs.add_parser(mode);q.add_argument('--workspace',type=Path,required=True)
  if mode=='init':
   q.add_argument('--portable',type=Path,required=True)
   for n in ROLES:q.add_argument('--'+n+'-oracle',type=Path,required=True)
  if mode=='update':q.add_argument('--test-exit-after',choices=engine.base.PHASES,help='Research child-process failpoint; exits 91, not a normal update option')
  if mode=='export':q.add_argument('--out-new',type=Path,required=True)
 x=p.parse_args()
 try:
  if x.mode=='init':result=init(x.portable,x.workspace,[getattr(x,n+'_oracle') for n in ROLES])
  elif x.mode=='update':result=update(x.workspace,x.test_exit_after)
  elif x.mode=='export':result=export(x.workspace,x.out_new)
  else:result=globals()[x.mode](x.workspace)
  print(json.dumps(result,indent=2));return 0
 except (a.AuditError,b.BindingError,OSError) as ex:
  print(json.dumps({'status':'stopped_safely','error_type':type(ex).__name__,'reason':str(ex),'installation_ready':False}));return 1
if __name__=='__main__':raise SystemExit(main())
