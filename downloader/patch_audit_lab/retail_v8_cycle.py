"""NEW owned V8 research cycle with mandatory original-Agent inner-bind gate.

Linux custom publication/resume, not Windows Agent transaction semantics.
Index qwords are still an explicit fixture policy, not full Agent object I/O.
"""
import argparse,json,os,struct,uuid
from pathlib import Path
import patch_audit as a
import source_binding as b
import retail_storage_poc as old
import retail_update_cycle as legacy
import synthetic_casc_format as fmt
import synthetic_casc_store as fs
import archive_prefix_poc as prefix
import name_seed_model as names
import agent_bind_contract as bind
import agent_value_range as value
MARKER='RETAIL-V8-RESEARCH.json';JOURNAL=legacy.JOURNAL
PHASES=legacy.PHASES;INDEX_TMP=legacy.INDEX_TMP;CONTROL_TMP=legacy.CONTROL_TMP
SOURCE=legacy.SOURCE;SOURCE_CK=legacy.SOURCE_CK;TARGET=legacy.TARGET

def oracle_identity(oracle):
 """Require the local pinned-fragment build receipt and exact ELF digest."""
 import agent_static_audit as identity
 oracle=b.safe(oracle,True);receipt=oracle.parent/'BUILD-RECEIPT.json';a.require(receipt.is_file(),'v8_oracle_receipt_missing');obj=b.json_object(fs.read(receipt,65536))
 a.require(obj.get('format')=='agent-bind-contract-build-1' and obj.get('agent_sha256')==identity.AGENT_SHA256 and obj.get('original_code_bytes')==3442 and obj.get('original_bytes_verified_in_elf') is True and obj.get('no_rwx') is True and obj.get('nx_stack') is True,'v8_oracle_build_receipt')
 a.require(a.sha256(fs.read(oracle,1024**2))==obj.get('binary_sha256'),'v8_oracle_binary_identity');return True

def tables(seed,updated):
 rows={i:[] for i in range(16)}
 for i,k in enumerate(prefix.keys(seed,0,1024)):rows[i].append(bind.record(k.hex(),i*30,30))
 rows[fmt.bucket(SOURCE)].append(bind.record(SOURCE,480,188))
 if updated:rows[fmt.bucket(TARGET)].append(bind.record(TARGET,668,188))
 return {i:bind.make_index(rows[i],i) for i in range(16)}

def create(prior,out,oracle):
 # Validate original executable exists before any output is created.
 oracle_identity(oracle);prior=b.safe(prior);out=old.safe_new(out);a.require(prior not in out.parents,'v8_output_in_prior')
 watch=b.Watch()
 for p in sorted(prior.iterdir()):watch.file(p)
 with legacy.locked(prior) as p:
  v=legacy.inspect(p);a.require(v['updated'] and v['journal']['state']=='committed','v8_prior_cycle_incomplete')
 seed=v['seed'];data=v['data'][:668];indexes=tables(seed,False)
 for i,raw in indexes.items():a.require(bind.compare(oracle,raw,i)['status']==0,'v8_initial_bind_rejected')
 # Marker binds this new experiment, not original Lab or user's installation.
 marker={'format':'owned-retail-v8-cycle-1','workspace_id':str(uuid.uuid4()),'seed':seed.hex(),'not_installation':True,'value_qwords':'fixture-policy-offset-span','custom_journal_not_agent':True}
 out.mkdir()
 for n,raw in ((MARKER,old.canonical(marker)),('LOCK',b'\0'),('data.000',data),('PATCH.zbsdiff',watch.read(prior/'PATCH.zbsdiff',1024)),('shmem',legacy.control(False))):fs.write_new(out/n,raw)
 for i,raw in indexes.items():fs.write_new(out/legacy.idx(i,1),raw)
 fs.sync_dir(out);watch.check();return status(out,oracle)

def inspect(root):
 marker_raw=fs.read(root/MARKER,4096);marker=b.json_object(marker_raw)
 a.require(set(marker)=={'format','workspace_id','seed','not_installation','value_qwords','custom_journal_not_agent'} and marker['format']=='owned-retail-v8-cycle-1' and marker['not_installation'] is True and marker['custom_journal_not_agent'] is True and marker['value_qwords']=='fixture-policy-offset-span','v8_marker')
 a.require(str(uuid.UUID(marker['workspace_id']))==marker['workspace_id'],'v8_workspace_identity')
 a.require(marker['seed']==names.model('LAB-PC',r'C:\Games\World of Warcraft\Data')['seed'],'v8_explicit_seed')
 seed=bytes.fromhex(marker['seed']);data=fs.read(root/'data.000',1024);a.require(668<=len(data)<=856,'v8_data_length')
 prefix.read_prefix(data[:480],seed,0,1024);source,_=fmt.read_span(data[480:668],SOURCE,33940,SOURCE_CK,0,480)
 encoded=legacy.inputs(data[510:668],fs.read(root/'PATCH.zbsdiff',1024));targetspan=fmt.make_span(encoded,TARGET,33940,0,668);expected=data[:668]+targetspan
 a.require(expected.startswith(data),'v8_partial_tail_mismatch')
 ctl=fs.read(root/'shmem',65536);a.require(ctl in (legacy.control(False),legacy.control(True)),'v8_control_contract');updated=ctl==legacy.control(True)
 if updated:a.require(data==expected,'v8_published_incomplete_data')
 initial=tables(seed,False);final=tables(seed,True);targetbucket=fmt.bucket(TARGET);newname=legacy.idx(targetbucket,2)
 required={MARKER,'LOCK','data.000','PATCH.zbsdiff','shmem'}|{legacy.idx(i,1) for i in range(16)};optional={JOURNAL,INDEX_TMP,CONTROL_TMP,newname};present=set(os.listdir(root));a.require(required<=present and present<=required|optional,'v8_layout')
 for i,raw in initial.items():a.require(fs.read(root/legacy.idx(i,1),bind.LIMIT)==raw,'v8_initial_index_changed')
 for n in (newname,INDEX_TMP):
  if n in present:a.require(fs.read(root/n,bind.LIMIT)==final[targetbucket],'v8_candidate_index_changed')
 if CONTROL_TMP in present:a.require(fs.read(root/CONTROL_TMP,65536)==legacy.control(True),'v8_control_temp_changed')
 if updated:a.require(newname in present,'v8_published_index_missing')
 journal=None
 if JOURNAL in present:
  journal=b.json_object(fs.read(root/JOURNAL,4096));a.require(journal.get('state') in ('prepared','committed') and journal==legacy.journal_expected(marker_raw,expected,journal['state']),'v8_journal_binding')
  if journal['state']=='committed':a.require(updated,'v8_commit_without_publish')
 elif updated or len(data)>668:a.require(False,'v8_unjournaled_write')
 return {'marker_raw':marker_raw,'seed':seed,'data':data,'expected_data':expected,'target_span':targetspan,'source_decoded':source,'updated':updated,'journal':journal,'present':present,'new_name':newname,'new_index':final[targetbucket]}

def gate(root,view,oracle,candidate=False):
 """Mandatory original parser + full-key lookup, then independent strict span read."""
 oracle_identity(oracle)
 target_visible=view['updated'] or candidate
 if target_visible:a.require(view['data']==view['expected_data'],'v8_gate_incomplete_target')
 ctl=fs.read(root/'shmem',65536);sequences=struct.unpack_from('<16I',ctl,0x110);selected={}
 for i,sequence in enumerate(sequences):
  if candidate and i==fmt.bucket(TARGET):sequence=2
  a.require(sequence==(2 if target_visible and i==fmt.bucket(TARGET) else 1),'v8_exact_sequence_selection')
  raw=fs.read(root/legacy.idx(i,sequence),bind.LIMIT);bind.strict_read(raw,i);proof=bind.compare(oracle,raw,i)
  a.require(proof['status']==0,'v8_actual_bind_failed');selected[i]=raw
 for key,ckey,offset in ((SOURCE,SOURCE_CK,480),(TARGET,old.CK,668)):
  if key==TARGET and not target_visible:continue
  bucket=fmt.bucket(key);proof=bind.compare(oracle,selected[bucket],bucket,query=key)
  a.require(proof['status']==0 and proof['end']-proof['begin']==1,'v8_actual_fullkey_lookup_failed')
  q0,q1=struct.unpack_from('<QQ',bytes.fromhex(proof['selected']),16);a.require((q0,q1)==(offset,188),'v8_fixture_value_policy');a.require(value.strict_policy(0,value.MASK,q0,q1),'v8_value_nonwrapping_bounds')
  fmt.read_span(view['data'][q0:q0+q1],key,33940,ckey,0,q0)
 return {'original_agent_inner_bind_verified':True,'original_agent_fullkey_search_verified':True,'span_readback':'independent Python, not Agent object I/O','selected_index_count':16,'visible_objects':2 if target_visible else 1}

def result(v,proof):
 return {**legacy.result(v),**proof,'format':'retail-v8-cycle-status-1','index_profile':'Agent-9824-V8-primary-only','mandatory_native_gate':True,'agent_qword_semantics':'fixture policy, full Agent readpath unproven','windows_agent_executed':False}

def locked(root):
 # Reuse only the safe POSIX lock primitive through a dedicated implementation;
 # no masquerading as a V7 store and no legacy marker creation.
 import fcntl
 from contextlib import contextmanager
 @contextmanager
 def acquire():
  p=b.safe(root);fs.no_game_ancestors(p);a.require(os.name=='posix','v8_linux_research_only');b.safe(p/MARKER,True);lock=b.safe(p/'LOCK',True);a.require(lock.stat().st_size==1,'v8_lock_shape')
  with lock.open('r+b') as f:
   try:fcntl.flock(f.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
   except BlockingIOError:raise a.AuditError('v8_busy') from None
   try:yield p
   finally:fcntl.flock(f.fileno(),fcntl.LOCK_UN)
 return acquire()

def status(root,oracle,*,additional_gate=None):
 with locked(root) as p:
  view=inspect(p);proof=gate(p,view,oracle)
  if additional_gate is not None:proof.update(additional_gate(p,view,False))
  return result(view,proof)

def advance(root,oracle,fail_after=None,*,additional_gate=None):
 a.require(fail_after is None or fail_after in PHASES,'v8_failpoint');oracle_identity(oracle)
 with locked(root) as p:
  view=inspect(p)
  def phase(name):
   if fail_after==name:os._exit(91)
  def verify(view,candidate=False):
   proof=gate(p,view,oracle,candidate)
   if additional_gate is not None:proof.update(additional_gate(p,view,candidate))
   return proof
  if view['updated'] and view['journal']['state']=='committed':return {**result(view,verify(view)),'idempotent_noop':True}
  # Validate currently published view even before starting or resuming a transaction.
  verify(view)
  if view['journal'] is None:
   a.require(not ({view['new_name'],INDEX_TMP,CONTROL_TMP}&view['present']),'v8_unowned_transaction_files')
   fs.write_new(p/JOURNAL,old.canonical(legacy.journal_expected(view['marker_raw'],view['expected_data'],'prepared')));fs.sync_dir(p)
  phase('prepared')
  with b.safe(p/'data.000',True).open('r+b') as f:
   current=f.read();a.require(current==view['data'],'v8_data_changed');middle=762
   if len(current)<middle:f.seek(0,os.SEEK_END);f.write(view['expected_data'][len(current):middle]);f.flush();os.fsync(f.fileno())
   phase('target_half_appended');end=f.seek(0,os.SEEK_END)
   if end<len(view['expected_data']):f.write(view['expected_data'][end:]);f.flush();os.fsync(f.fileno())
  phase('target_data_synced')
  if not (p/view['new_name']).exists():
   if not (p/INDEX_TMP).exists():fs.write_new(p/INDEX_TMP,view['new_index'])
   phase('index_temp_synced');legacy.publish_index_noreplace(p/INDEX_TMP,p/view['new_name']);fs.sync_dir(p)
  phase('index_named')
  if (p/INDEX_TMP).exists():a.require(fs.read(p/INDEX_TMP,bind.LIMIT)==view['new_index'],'v8_temp_index_changed');(p/INDEX_TMP).unlink();fs.sync_dir(p)
  verify(inspect(p),candidate=True);phase('index_bound')
  if not view['updated']:
   if not (p/CONTROL_TMP).exists():fs.write_new(p/CONTROL_TMP,legacy.control(True))
   phase('control_temp_synced');os.replace(p/CONTROL_TMP,p/'shmem');fs.sync_dir(p)
  phase('control_published');checked=inspect(p);a.require(checked['updated'],'v8_publish_readback');proof=verify(checked)
  fs.atomic(p/JOURNAL,old.canonical(legacy.journal_expected(checked['marker_raw'],checked['expected_data'],'committed')));phase('committed')
  return {**result(inspect(p),proof),'idempotent_noop':False}

def main():
 p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='mode',required=True)
 for mode in ('create','status','advance'):
  s=sub.add_parser(mode);s.add_argument('--oracle',type=Path,required=True)
  if mode=='create':s.add_argument('--prior-v7-owned-cycle',type=Path,required=True);s.add_argument('--out-new',type=Path,required=True)
  else:s.add_argument('--root',type=Path,required=True)
  if mode=='advance':s.add_argument('--test-exit-after',choices=PHASES)
 x=p.parse_args();r=create(x.prior_v7_owned_cycle,x.out_new,x.oracle) if x.mode=='create' else status(x.root,x.oracle) if x.mode=='status' else advance(x.root,x.oracle,x.test_exit_after);print(json.dumps(r,indent=2))
if __name__=='__main__':main()
