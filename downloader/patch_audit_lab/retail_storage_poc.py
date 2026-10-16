"""Real one-object Retail patch -> owned NEW data/index fixture -> strict readback.
NOT an install writer. The first 480 bytes are explicitly placeholder, not a
reconstructed archive prefix. Generated shmem is NOT a live activation record.
"""
import argparse,json,os,struct,subprocess
from pathlib import Path
from unittest.mock import patch
import patch_audit as a
import source_binding as b
import portable_run
import staging_sample as sample
import encoding_target as encoding
import refs_source_check as blte
import synthetic_casc_format as fmt
import synthetic_casc_store as guards
import agent_allocator_model as allocator
import shmem_readonly as shmem

MARKER='RESEARCH-ONLY-NOT-INSTALL.json'
EK='faedca88d0a0ab30dae5519239582d31'
CK='3d42bf2e42127f313b0ec64cb440cde9'
ENCODED_SHA='73bb9f2ec6c3dba2dbe61d5aa7e5bd4560f0d96c53972adb7472894d4f69b364'
PHASES=('data_written','index_written','control_written','receipt_written')
PREFIX=(b'RESEARCH PLACEHOLDER: archive-prefix format NOT reconstructed.\n').ljust(allocator.PREFIX,b'\0')

def control(payload,bucket):
    raw=bytearray(0x4000);struct.pack_into('<II',raw,0,5,0x154)
    name=b'Global\\research-fixture-not-an-install\0';raw[8:8+len(name)]=name
    struct.pack_into('<II',raw,0x108,len(payload),0x1000);struct.pack_into('<I',raw,0x110+bucket*4,1)
    raw[0x1000:0x1000+len(payload)]=payload
    return bytes(raw)

def canonical(obj):return (json.dumps(obj,sort_keys=True,indent=2)+'\n').encode()
def expected_index():return f'{fmt.bucket(EK):02x}00000001.idx'
def safe_new(root):
    root=Path(root).absolute();guards.no_game_ancestors(root);b.safe(root.parent)
    a.require(not root.exists() and not root.is_symlink(),'poc_requires_new_empty_owned_root');return root

def materialize(root,encoded,decoded,fail_after=None):
    a.require(fail_after is None or fail_after in PHASES,'poc_failpoint')
    a.require(isinstance(encoded,bytes) and len(encoded)==158 and a.sha256(encoded)==ENCODED_SHA,'poc_exact_encoded_identity')
    a.require(isinstance(decoded,bytes) and len(decoded)==33940 and a.md5(decoded)==CK,'poc_exact_decoded_identity')
    got,_=blte.decode_source(encoded,EK,len(decoded));a.require(got==decoded,'poc_encoded_roundtrip')
    root=safe_new(root);root.mkdir()
    guards.write_new(root/MARKER,canonical({'format':'retail-one-object-research-fixture-1','installation_ready':False,'archive_prefix_placeholder':True}))
    free=allocator.make([(allocator.SEGMENT,0)]);first=allocator.allocate(free,30+len(encoded));a.require(first['code']==16,'poc_prefix_requirement')
    reserved=allocator.reserve_prefix(free,0);a.require(reserved['code']==0,'poc_prefix_reservation')
    allocated=allocator.allocate(reserved['payload'],30+len(encoded));a.require(allocated['code']==0 and allocated['address']==480,'poc_allocation')
    span=fmt.make_span(encoded,EK,len(decoded),0,allocated['address']);a.require(len(span)==188,'poc_span_width')
    def write(name,data,phase):
        guards.write_new(root/name,data);guards.sync_dir(root)
        if fail_after==phase:os._exit(91)  # Child-process test only, explicit CLI flag.
    write('data.000',PREFIX+span,'data_written')
    index=fmt.make_index([{'ekey':EK,'archive':0,'offset':480,'span':188}],fmt.bucket(EK))
    write(expected_index(),index,'index_written')
    ctl=control(allocated['payload'],fmt.bucket(EK));write('shmem',ctl,'control_written')
    receipt={'format':'retail-one-object-research-receipt-1','target_ekey':EK,'target_ckey':CK,'encoded_bytes':158,'decoded_bytes':33940,'span_bytes':188,'offset':480,'archive':0,'installation_ready':False,'files':{n:{'size':len(raw),'sha256':a.sha256(raw)} for n,raw in [('data.000',PREFIX+span),(expected_index(),index),('shmem',ctl)]}}
    write('RECEIPT.json',canonical(receipt),'receipt_written')
    return verify(root)

def verify(root):
    root=b.safe(root);guards.no_game_ancestors(root)
    names={MARKER,'data.000',expected_index(),'shmem','RECEIPT.json'}
    a.require(set(os.listdir(root))==names,'poc_incomplete_or_unexpected_layout')
    watch=b.Watch();marker=b.json_object(watch.read(root/MARKER,4096));a.require(marker=={'format':'retail-one-object-research-fixture-1','installation_ready':False,'archive_prefix_placeholder':True},'poc_marker')
    receipt=b.json_object(watch.read(root/'RECEIPT.json',8192))
    rows=receipt.get('files');a.require(isinstance(rows,dict) and set(rows)=={'data.000',expected_index(),'shmem'},'poc_receipt_layout')
    files={name:watch.read(root/name,65536) for name in rows}
    for name,raw in files.items():a.require(rows[name]=={'size':len(raw),'sha256':a.sha256(raw)},'poc_file_identity')
    data=files['data.000'];a.require(len(data)==668 and data[:480]==PREFIX,'poc_placeholder_or_data_length')
    index_rows=fmt.read_index(files[expected_index()],fmt.bucket(EK));a.require(index_rows==[{'prefix':EK[:18],'archive':0,'offset':480,'span':188}],'poc_index_row')
    decoded,_=fmt.read_span(data[480:],EK,33940,CK,0,480);a.require(a.md5(decoded)==CK and a.sha256(data[510:])==ENCODED_SHA,'poc_span_identity')
    observation=shmem.inspect(files['shmem'],[expected_index()]);a.require(observation['sequence_observations'][fmt.bucket(EK)]['sequence_file_present'] is True,'poc_sequence')
    free=allocator.records(files['shmem'][0x1000:0x1000+0x2ab8]);a.require(free==[(allocator.SEGMENT-668,668)],'poc_allocator_post_state')
    # Receipt metadata is a fixture completeness marker, never an activation
    # pointer. Verify known fields rather than trusting a user-supplied summary.
    expected={'format':'retail-one-object-research-receipt-1','target_ekey':EK,'target_ckey':CK,'encoded_bytes':158,'decoded_bytes':33940,'span_bytes':188,'offset':480,'archive':0,'installation_ready':False,'files':rows}
    a.require(receipt==expected,'poc_receipt_identity');watch.check()
    return {'format':'retail-one-object-readback-1','status':'real_retail_sample_stored_and_read_back','target_ckey':CK,'target_ekey':EK,'encoded_bytes':158,'decoded_bytes':33940,'span_bytes':188,'data_bytes':len(data),'index_bytes':len(files[expected_index()]),'allocator_post_state_verified':True,'sequence_fixture_binding_verified':True,'archive_prefix_placeholder':True,'actual_installation_binding_proven':False,'installation_ready':False,'files_written_during_verify':0,'network_requests':0}

def native_verify(root,oracle):
    root=b.safe(root);oracle=b.safe(oracle,True)
    proc=subprocess.run([str(oracle),str(root/expected_index()),str(root/'data.000'),EK,CK],capture_output=True,text=True,timeout=15)
    a.require(len(proc.stdout)<4096 and len(proc.stderr)<4096,'poc_native_output_bounds')
    got=b.json_object(proc.stdout.encode());a.require(proc.returncode==0 and got.get('accepted') is True,'poc_native_readback_rejected');return got

def run(fixture,out,oracle=None,fail_after=None):
    # Reject existing or game-like output before reading the 200MB metadata.
    out=safe_new(out);fixture=b.safe(fixture)
    a.require(out!=fixture and fixture not in out.parents,'poc_output_inside_fixture')
    with patch('socket.socket',side_effect=RuntimeError('poc_network_forbidden')):
        proof=portable_run.run(fixture)
        a.require(any(row.get('exact_target_ekey_reproduced') and row.get('ekey')==EK for row in proof['encoding_options']),'poc_encoding_relation')
        watch=b.Watch()
        for name in sorted(portable_run.FIXED|{'PORTABLE-MANIFEST.json'}):watch.file(fixture/name)
        source=watch.read(fixture/'source.blte');patch_bytes=watch.read(fixture/'sample.zbsdiff')
        old,_=blte.decode_source(source,sample.OPTION['source_ekey'],sample.OPTION['source_size']);decoded,_=sample.rebuild(old,patch_bytes)
        encoded=encoding.encode(decoded,'b:{256K*=z}')
        got=materialize(out,encoded,decoded,fail_after);watch.check()
        selected=next(row for row in proof['encoding_options'] if row.get('exact_target_ekey_reproduced') and row.get('ekey')==EK)
        got['input_chain']={'original_fixture_manifest_verified':True,
            'fixture_file_identities_unchanged_during_output':True,
            'source_full_ekey_verified':proof['source_full_ekey_verified'],
            'patch_hash_verified':proof['patch_hash_verified'],
            'target_ckey':proof['target_ckey'],'target_sha256':proof['target_sha256'],
            'encoding_proof':proof['encoding_proof'],'selected_encoding':selected}
        # Check all original file fingerprints retained by portable_run itself;
        # source/patch additionally watched across materialization here.
        if oracle is not None:got['native_readback']=native_verify(out,oracle)
    return got

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixture',type=Path);p.add_argument('--out-new',type=Path);p.add_argument('--verify',type=Path);p.add_argument('--native-oracle',type=Path);p.add_argument('--test-exit-after',choices=PHASES);args=p.parse_args()
    if args.verify:
        a.require(not args.fixture and not args.out_new and not args.test_exit_after,'poc_ambiguous_mode');got=verify(args.verify)
        if args.native_oracle:got['native_readback']=native_verify(args.verify,args.native_oracle)
    else:
        a.require(args.fixture is not None and args.out_new is not None,'poc_fixture_and_new_output_required');got=run(args.fixture,args.out_new,args.native_oracle,args.test_exit_after)
    print(json.dumps(got,indent=2))
if __name__=='__main__':main()
