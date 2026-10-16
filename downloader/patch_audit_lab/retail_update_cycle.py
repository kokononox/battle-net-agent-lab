"""One real Retail patch in a NEW owned research store; never a WoW install.
Append-only data, exact header sequence lookup, custom resume journal and POSIX
cooperating-writer lock. NOT the Agent's journal, Windows publication or power-loss proof.
"""
import argparse,json,os,struct,uuid,subprocess,ctypes,errno
from contextlib import contextmanager
from pathlib import Path
import patch_audit as a
import source_binding as b
import synthetic_casc_format as fmt
import synthetic_casc_store as fs
import archive_prefix_poc as prefix
import name_seed_model as names
import retail_storage_poc as old
import agent_allocator_model as alloc
import staging_sample as sample
import refs_source_check as blte
import encoding_target as encoding
import portable_run

MARKER='RETAIL-UPDATE-RESEARCH.json'
SOURCE=sample.OPTION['source_ekey'];SOURCE_CK=sample.OBSERVED['derived_source_ckey'];TARGET=old.EK
PHASES=('prepared','target_half_appended','target_data_synced','index_temp_synced','index_named','index_bound','control_temp_synced','control_published','committed')
JOURNAL='CUSTOM-RESUME.json';INDEX_TMP='index.next';CONTROL_TMP='control.next'

def idx(which,seq):
    a.require(type(which)is int and 0<=which<16 and type(seq)is int and 1<=seq<=2,'cycle_index_name_bounds')
    return f'{which:02x}{seq:08x}.idx'

def make_index(rows,which):
    a.require(0<=which<16 and 1<=len(rows)<=3,'cycle_index_rows')
    entries=[]
    for key,offset,span,flag in sorted(rows):
        a.require(flag in (0,1) and (fmt.bucket(key)+flag)&15==which,'cycle_index_bucket_mode')
        a.require((flag==1 and span==30 and offset in range(0,480,30)) or (flag==0 and key in (SOURCE,TARGET) and span==188 and offset in (480,668)),'cycle_index_row_policy')
        entries.append(bytes.fromhex(key)[:9]+fmt.location(0,offset)+struct.pack('<I',span))
    a.require(len({r[:9] for r in entries})==len(entries),'cycle_prefix_collision')
    h=struct.pack('<HBBBBBBQ',7,which,0,4,5,9,30,0x4000000000);hi=lo=0
    for entry in entries:hi,lo=fmt.hashlittle2(entry,hi,lo)
    return struct.pack('<II',16,fmt.hashlittle2(h)[0])+h+bytes(8)+struct.pack('<II',18*len(entries),hi)+b''.join(entries)

def tables(seed,updated):
    rows={i:[] for i in range(16)}
    for slot,key in enumerate(prefix.keys(seed,0,1024)):rows[slot].append((key.hex(),slot*30,30,1))
    rows[fmt.bucket(SOURCE)].append((SOURCE,480,188,0))
    if updated:rows[fmt.bucket(TARGET)].append((TARGET,668,188,0))
    return {i:make_index(rows[i],i) for i in range(16)}

def control(updated):
    end=856 if updated else 668
    raw=bytearray(old.control(alloc.make([(alloc.SEGMENT-end,end)]),fmt.bucket(SOURCE)))
    seq=[1]*16
    if updated:seq[fmt.bucket(TARGET)]=2
    struct.pack_into('<16I',raw,0x110,*seq);return bytes(raw)

def inputs(source,patch):
    a.require(len(source)==158 and a.sha256(source)==sample.OBSERVED['encoded_sha256'],'cycle_source_encoded_identity')
    decoded,_=blte.decode_source(source,SOURCE,33940);a.require(a.md5(decoded)==SOURCE_CK,'cycle_source_derived_ckey')
    target,_=sample.rebuild(decoded,patch);encoded=encoding.encode(target,'b:{256K*=z}')
    a.require(len(encoded)==158 and a.sha256(encoded)==old.ENCODED_SHA,'cycle_target_encoded_identity')
    return encoded

def create(root,source,patch,seed_result,origin):
    root=old.safe_new(root);seed=bytes.fromhex(a.key(seed_result['seed']))
    a.require(seed_result.get('explicit_synthetic_inputs') is True and seed_result.get('actual_user_installation_binding_proven') is False,'cycle_synthetic_name_inputs_only')
    inputs(source,patch);data=prefix.prefix(seed,0,1024)+fmt.make_span(source,SOURCE,33940,0,480)
    root.mkdir()
    marker={'format':'retail-update-owned-research-1','workspace_id':str(uuid.uuid4()),'seed':seed.hex(),'name_seed':seed_result,'source_ekey':SOURCE,'target_ekey':TARGET,'installation_ready':False,'custom_journal_not_agent_protocol':True}
    for name,raw in [(MARKER,old.canonical(marker)),('ORIGIN.json',old.canonical(origin)),('PATCH.zbsdiff',patch),('LOCK',b'\0'),('data.000',data),('shmem',control(False))]:fs.write_new(root/name,raw)
    for which,raw in tables(seed,False).items():fs.write_new(root/idx(which,1),raw)
    fs.sync_dir(root);return status(root)

def init(fixture,out,isolated_oracle):
    out=old.safe_new(out);fixture=b.safe(fixture);a.require(fixture not in out.parents,'cycle_output_in_original_fixture')
    proof=portable_run.run(fixture);a.require(any(r.get('exact_target_ekey_reproduced') and r.get('ekey')==TARGET for r in proof['encoding_options']),'cycle_official_encoding_relation')
    w=b.Watch()
    for n in sorted(portable_run.FIXED|{'PORTABLE-MANIFEST.json'}):w.file(fixture/n)
    source=w.read(fixture/'source.blte');patch=w.read(fixture/'sample.zbsdiff')
    named=names.compare(isolated_oracle,'LAB-PC',r'C:\Games\World of Warcraft\Data')
    origin={'format':'cycle-portable-input-proof-1','original_fixture_manifest_verified':True,'source_full_ekey_verified':proof['source_full_ekey_verified'],'patch_hash_verified':proof['patch_hash_verified'],'target_ckey':proof['target_ckey'],'encoding_proof':proof['encoding_proof'],'source_ckey_is_derived_not_independent':True}
    result=create(out,source,patch,named,origin);w.check();result['original_fixture_identities_unchanged']=True;return result

@contextmanager
def locked(root):
    root=b.safe(root);fs.no_game_ancestors(root);a.require(os.name=='posix','cycle_posix_research_only')
    b.safe(root/MARKER,True);lock=b.safe(root/'LOCK',True);a.require(lock.stat().st_size==1,'cycle_lock_shape')
    import fcntl
    with lock.open('r+b') as f:
        try:fcntl.flock(f.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise a.AuditError('cycle_busy') from None
        try:yield root
        finally:fcntl.flock(f.fileno(),fcntl.LOCK_UN)

def journal_expected(marker,data,state):
    return {'format':'custom-cycle-resume-1','marker_sha256':a.sha256(marker),'old_target_bucket_sequence':1,'new_target_bucket_sequence':2,'expected_final_data_sha256':a.sha256(data),'target_encoded_sha256':old.ENCODED_SHA,'state':state,'not_agent_journal':True}

def inspect(root):
    """Called under cooperating lock; strict owned layout and fixed pinned sample."""
    raw=fs.read(root/MARKER,16384);marker=b.json_object(raw)
    a.require(set(marker)=={'format','workspace_id','seed','name_seed','source_ekey','target_ekey','installation_ready','custom_journal_not_agent_protocol'} and marker['format']=='retail-update-owned-research-1' and marker['source_ekey']==SOURCE and marker['target_ekey']==TARGET and marker['installation_ready'] is False and marker['custom_journal_not_agent_protocol'] is True,'cycle_marker')
    a.require(str(uuid.UUID(marker['workspace_id']))==marker['workspace_id'],'cycle_workspace_id')
    named=names.model('LAB-PC',r'C:\Games\World of Warcraft\Data');stored=marker['name_seed']
    a.require(isinstance(stored,dict) and all(stored.get(k)==v for k,v in named.items()) and set(stored)<=set(named)|{'fragment_comparison'},'cycle_name_seed_binding')
    if 'fragment_comparison' in stored:a.require(stored['fragment_comparison']=={'matched':True,'isolated_agent_pure_fragments_executed':True,'windows_apis_executed':False},'cycle_name_fragment_receipt')
    a.require(marker['seed']==named['seed'],'cycle_seed');seed=bytes.fromhex(marker['seed'])
    origin=b.json_object(fs.read(root/'ORIGIN.json',65536));a.require(origin.get('format')=='cycle-portable-input-proof-1' and origin.get('original_fixture_manifest_verified') is True and origin.get('target_ckey')==old.CK and origin.get('patch_hash_verified') is True and origin.get('source_full_ekey_verified') is True,'cycle_origin')
    data=fs.read(root/'data.000',1024);a.require(668<=len(data)<=856,'cycle_data_length')
    prefix.read_prefix(data[:480],seed,0,1024)
    source,_=fmt.read_span(data[480:668],SOURCE,33940,SOURCE_CK,0,480)
    patch=fs.read(root/'PATCH.zbsdiff',1024);encoded=inputs(data[510:668],patch)
    targetspan=fmt.make_span(encoded,TARGET,33940,0,668);expected=data[:668]+targetspan
    a.require(expected.startswith(data),'cycle_partial_target_mismatch')
    ctl=fs.read(root/'shmem',65536);a.require(ctl in (control(False),control(True)),'cycle_control_semantics');updated=ctl==control(True)
    if updated:a.require(len(data)==856,'cycle_published_target_incomplete')
    initial=tables(seed,False);final=tables(seed,True);bucket=fmt.bucket(TARGET);newname=idx(bucket,2)
    required={MARKER,'ORIGIN.json','PATCH.zbsdiff','LOCK','data.000','shmem'}|{idx(i,1) for i in range(16)}
    optional={JOURNAL,INDEX_TMP,CONTROL_TMP,newname};present=set(os.listdir(root));a.require(required<=present and present<=required|optional,'cycle_layout')
    for i,value in initial.items():a.require(fs.read(root/idx(i,1),4096)==value,'cycle_original_index_changed')
    for name in (newname,INDEX_TMP):
        if name in present:a.require(fs.read(root/name,4096)==final[bucket],'cycle_new_index_content')
    if CONTROL_TMP in present:a.require(fs.read(root/CONTROL_TMP,65536)==control(True),'cycle_control_temp_content')
    if updated:a.require(newname in present,'cycle_published_index_missing')
    journal=None
    if JOURNAL in present:
        journal=b.json_object(fs.read(root/JOURNAL,4096));a.require(journal.get('state') in ('prepared','committed') and journal==journal_expected(raw,expected,journal['state']),'cycle_journal_binding')
        if journal['state']=='committed':a.require(updated,'cycle_commit_without_control')
    elif updated or len(data)>668:a.require(False,'cycle_unjournaled_mutation')
    return {'seed':seed,'source_decoded':source,'target_span':targetspan,'data':data,'expected_data':expected,'updated':updated,'journal':journal,'marker_raw':raw,'new_index':final[bucket],'new_name':newname,'present':present}

def result(view):
    return {'format':'real-retail-update-cycle-status-1','target_published':view['updated'],'source_full_ekey_and_derived_ckey_verified':True,'target_full_ekey_and_expected_ckey_verified':view['updated'],'target_bucket_sequence':2 if view['updated'] else 1,'visible_objects':2 if view['updated'] else 1,'data_bytes':len(view['data']),'pending_unpublished_tail_bytes':0 if view['updated'] else len(view['data'])-668,'source_span_unchanged':True,'archive_prefix_placeholder':False,'custom_resume_state':None if view['journal'] is None else view['journal']['state'],'exact_header_sequence_used':True,'max_filename_selection_used':False,'source_ckey_is_derived_not_independent':True,'agent_windows_publication_executed':False,'installation_ready':False,'network_requests':0}

def status(root):
    with locked(root) as p:return result(inspect(p))

def publish_index_noreplace(source,destination):
    """Linux research equivalent only: atomic renameat2(RENAME_NOREPLACE).
    No link fallback: the shared-file safety gate requires st_nlink==1.
    """
    libc=ctypes.CDLL(None,use_errno=True)
    a.require(hasattr(libc,'renameat2'),'cycle_noreplace_unsupported')
    fn=libc.renameat2;fn.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];fn.restype=ctypes.c_int
    if fn(-100,os.fsencode(source),-100,os.fsencode(destination),1):
        code=ctypes.get_errno()
        raise a.AuditError('cycle_index_already_exists' if code==errno.EEXIST else 'cycle_index_publish_failed')

def advance(root,fail_after=None,bind=lambda root:True):
    a.require(fail_after is None or fail_after in PHASES,'cycle_failpoint')
    with locked(root) as p:
        view=inspect(p)
        def phase(name):
            if fail_after==name:os._exit(91)
        if view['updated'] and view['journal']['state']=='committed':return {**result(view),'idempotent_noop':True}
        if view['journal'] is None:
            a.require(not ({view['new_name'],INDEX_TMP,CONTROL_TMP}&view['present']),'cycle_refuse_existing_unowned_transaction_files')
            fs.write_new(p/JOURNAL,old.canonical(journal_expected(view['marker_raw'],view['expected_data'],'prepared')));fs.sync_dir(p)
        phase('prepared')
        # Verify partial tail before every resume, append exact missing bytes only.
        with b.safe(p/'data.000',True).open('r+b') as f:
            current=f.read();a.require(current==view['data'],'cycle_data_changed')
            middle=min(762,len(view['expected_data']))
            if len(current)<middle:f.seek(0,os.SEEK_END);f.write(view['expected_data'][len(current):middle]);f.flush();os.fsync(f.fileno())
            phase('target_half_appended')
            end=f.seek(0,os.SEEK_END)
            if end<len(view['expected_data']):f.write(view['expected_data'][end:]);f.flush();os.fsync(f.fileno())
        phase('target_data_synced')
        # Linux no-overwrite rename; not an execution of Windows MoveFileExW.
        if not (p/view['new_name']).exists():
            if not (p/INDEX_TMP).exists():fs.write_new(p/INDEX_TMP,view['new_index'])
            phase('index_temp_synced');publish_index_noreplace(p/INDEX_TMP,p/view['new_name']);fs.sync_dir(p)
        phase('index_named')
        if (p/INDEX_TMP).exists():
            a.require(fs.read(p/INDEX_TMP,4096)==view['new_index'],'cycle_index_temp_changed');(p/INDEX_TMP).unlink();fs.sync_dir(p)
        a.require(bind(p) is True,'cycle_index_bind_failed');phase('index_bound')
        if not view['updated']:
            if not (p/CONTROL_TMP).exists():fs.write_new(p/CONTROL_TMP,control(True))
            phase('control_temp_synced');os.replace(p/CONTROL_TMP,p/'shmem');fs.sync_dir(p)
        phase('control_published')
        checked=inspect(p);a.require(checked['updated'],'cycle_readback_after_publish')
        fs.atomic(p/JOURNAL,old.canonical(journal_expected(checked['marker_raw'],checked['expected_data'],'committed')))
        phase('committed');return {**result(inspect(p)),'idempotent_noop':False}

def native_call(binary,*args):
    binary=b.safe(binary,True)
    run=subprocess.run([str(binary),*map(str,args)],capture_output=True,text=True,timeout=5)
    a.require(run.returncode==0,'cycle_native_rejected')
    obj=json.loads(run.stdout);a.require(obj.get('accepted') is True,'cycle_native_result');return obj

def native_bind(binary,root):
    native_call(binary,root/idx(fmt.bucket(TARGET),2),root/'data.000',TARGET,old.CK)
    return True

def native_status(root,selector,object_oracle):
    with locked(root) as p:
        v=inspect(p);selection=native_call(selector,p,v['seed'].hex(),'1024')
        a.require(selection['target_visible']==v['updated'],'cycle_native_visibility')
        source=native_call(object_oracle,p/idx(fmt.bucket(SOURCE),1),p/'data.000',SOURCE,SOURCE_CK)
        target=native_call(object_oracle,p/v['new_name'],p/'data.000',TARGET,old.CK) if v['updated'] else None
        return {'selection':selection,'source':source,'target':target,'installation_ready':False}

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='mode',required=True)
    i=sub.add_parser('init');i.add_argument('--fixture',required=True,type=Path);i.add_argument('--out-new',required=True,type=Path);i.add_argument('--isolated-oracle',required=True,type=Path)
    for name in ('status','advance'):
        x=sub.add_parser(name);x.add_argument('--root',type=Path,required=True)
        if name=='advance':
            x.add_argument('--test-exit-after',choices=PHASES)
            x.add_argument('--native-object-oracle',type=Path,required=True)
    args=p.parse_args();got=init(args.fixture,args.out_new,args.isolated_oracle) if args.mode=='init' else status(args.root) if args.mode=='status' else advance(args.root,args.test_exit_after,lambda root:native_bind(args.native_object_oracle,root))
    print(json.dumps(got,indent=2))
if __name__=='__main__':main()
