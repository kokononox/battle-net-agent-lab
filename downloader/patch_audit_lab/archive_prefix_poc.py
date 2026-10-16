"""Owned research fixtures with Agent-shaped 16-record archive prefixes.
A caller-supplied seed is NOT an inferred Windows installation identity.
No activation, install discovery, network, or original-fixture modifications.
"""
import argparse,json,struct,subprocess
from pathlib import Path
import patch_audit as a
import source_binding as b
import synthetic_casc_format as f
import synthetic_casc_store as guards
import retail_storage_poc as old
import agent_allocator_model as alloc

MARKER='RESEARCH-ONLY-NOT-INSTALL.json'

def keys(seed,archive,capacity):
    a.require(isinstance(seed,bytes) and len(seed)==16,'prefix_seed_width')
    a.require(type(capacity)is int and 1<=capacity<=1024 and type(archive)is int and 0<=archive<capacity,'prefix_archive_capacity')
    result=[]
    for slot in range(16):
        k=bytearray(seed)
        if capacity>256:k[2]=archive>>8
        k[1]=archive&255
        for trial in range(256):
            k[0]=trial
            if (f.bucket(k.hex())+1)&15==slot:break
        else:raise ValueError('prefix_bucket_search_exhausted')
        result.append(bytes(k))
    return result

def prefix(seed,archive,capacity):
    out=[]
    for slot,key in enumerate(keys(seed,archive,capacity)):
        h=key[::-1]+struct.pack('<I',30)+b'\1\0'
        h+=struct.pack('<I',f.hashlittle2(h,0x3d6be971)[0])
        out.append(h+f.checksum_b(h,archive,slot*30))
    return b''.join(out)

def read_prefix(raw,seed,archive,capacity):
    a.require(isinstance(raw,bytes) and len(raw)==480,'prefix_size')
    for slot,key in enumerate(keys(seed,archive,capacity)):
        p=raw[slot*30:(slot+1)*30]
        a.require(p[:16]==key[::-1] and p[16:22]==struct.pack('<I',30)+b'\1\0','prefix_key_size_flags')
        a.require(int.from_bytes(p[22:26],'little')==f.hashlittle2(p[:22],0x3d6be971)[0],'prefix_checksum_a')
        a.require(p[26:]==f.checksum_b(p[:26],archive,slot*30),'prefix_checksum_b')
    return True

def index(rows,which):
    a.require(type(which)is int and 0<=which<16 and 1<=len(rows)<=2,'prefix_index_count')
    entries=[]
    for key,offset,span in sorted(rows):
        a.require(((f.bucket(key)+1)&15 if span==30 else f.bucket(key))==which and ((span==30 and offset in range(0,480,30)) or (key==old.EK and offset==480 and span==188)),'prefix_index_row')
        entries.append(bytes.fromhex(key)[:9]+f.location(0,offset)+struct.pack('<I',span))
    a.require(len({e[:9] for e in entries})==len(entries),'prefix_index_collision')
    header=struct.pack('<HBBBBBBQ',7,which,0,4,5,9,30,0x4000000000)
    hi=lo=0
    for entry in entries:hi,lo=f.hashlittle2(entry,hi,lo)
    return struct.pack('<II',16,f.hashlittle2(header)[0])+header+bytes(8)+struct.pack('<II',18*len(entries),hi)+b''.join(entries)

def expected(seed,capacity,span):
    a.require(len(span)==188,'prefix_real_span_size')
    f.read_span(span,old.EK,33940,old.CK,0,480)
    a.require(a.sha256(span[30:])==old.ENCODED_SHA,'prefix_real_encoded_identity')
    fullkeys=keys(seed,0,capacity);rows={i:[] for i in range(16)}
    for slot,key in enumerate(fullkeys):rows[slot].append((key.hex(),slot*30,30))
    rows[f.bucket(old.EK)].append((old.EK,480,188))
    data=prefix(seed,0,capacity)+span
    files={'data.000':data}
    for which in range(16):files[f'{which:02x}00000001.idx']=index(rows[which],which)
    ctl=bytearray(old.control(alloc.make([(alloc.SEGMENT-668,668)]),f.bucket(old.EK)))
    struct.pack_into('<16I',ctl,0x110,*([1]*16));files['shmem']=bytes(ctl)
    return files

def build(baseline,out,seed,capacity=1024):
    out=old.safe_new(out);baseline=b.safe(baseline)
    a.require(baseline not in out.parents,'prefix_output_inside_baseline')
    old.verify(baseline);watch=b.Watch()
    for p in baseline.iterdir():watch.file(p)
    raw=watch.read(baseline/'data.000',1024)
    files=expected(seed,capacity,raw[480:]);out.mkdir()
    marker={'format':'archive-prefix-research-1','seed':seed.hex(),'seed_origin':'explicit_research_input_not_windows_identity','capacity':capacity,'installation_ready':False}
    guards.write_new(out/MARKER,old.canonical(marker))
    for name,data in files.items():guards.write_new(out/name,data)
    guards.write_new(out/'RECEIPT.json',old.canonical({'files':{n:{'size':len(v),'sha256':a.sha256(v)} for n,v in files.items()}}));guards.sync_dir(out)
    watch.check();result=verify(out);result['baseline_identities_unchanged']=True;return result

def verify(root):
    root=b.safe(root);guards.no_game_ancestors(root);w=b.Watch()
    marker=b.json_object(w.read(root/MARKER,4096))
    a.require(set(marker)=={'format','seed','seed_origin','capacity','installation_ready'} and marker['format']=='archive-prefix-research-1' and marker['seed_origin']=='explicit_research_input_not_windows_identity' and marker['installation_ready'] is False,'prefix_marker')
    a.key(marker['seed']);seed=bytes.fromhex(marker['seed']);capacity=marker['capacity']
    data=w.read(root/'data.000',1024);a.require(len(data)==668,'prefix_data_size')
    read_prefix(data[:480],seed,0,capacity);wanted=expected(seed,capacity,data[480:])
    a.require(set(p.name for p in root.iterdir())==set(wanted)|{MARKER,'RECEIPT.json'},'prefix_fixture_layout')
    for name,value in wanted.items():a.require(w.read(root/name,65536)==value,'prefix_fixture_content')
    receipt=b.json_object(w.read(root/'RECEIPT.json',8192));a.require(receipt=={'files':{n:{'size':len(v),'sha256':a.sha256(v)} for n,v in wanted.items()}},'prefix_receipt')
    w.check()
    return {'format':'archive-prefix-readback-1','archive_prefix_placeholder':False,'reserved_headers':16,'reserved_index_rows':16,'index_files':16,'total_index_rows':17,'data_bytes':668,'encoded_sha256':old.ENCODED_SHA,'target_ekey':old.EK,'target_ckey':old.CK,'research_seed':seed.hex(),'seed_is_actual_installation_identity':False,'installation_ready':False,'agent_executed':False,'network_requests':0}

def native(root,oracle):
    got=verify(root);p=subprocess.run([str(b.safe(oracle,True)),str(b.safe(root)),got['research_seed'],'1024'],capture_output=True,text=True,timeout=15)
    a.require(len(p.stdout)<8192 and len(p.stderr)<8192,'prefix_native_output_bounds')
    result=b.json_object(p.stdout.encode());a.require(p.returncode==0 and result.get('accepted') is True,'prefix_native_rejected');return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--baseline',type=Path);p.add_argument('--out-new',type=Path);p.add_argument('--seed');p.add_argument('--verify',type=Path);p.add_argument('--native-oracle',type=Path);args=p.parse_args()
    if args.verify:
        a.require(not(args.baseline or args.out_new or args.seed),'prefix_ambiguous_mode');root=args.verify;got=verify(root)
    else:
        a.require(args.baseline and args.out_new and args.seed,'prefix_required_args');a.key(args.seed);root=args.out_new;got=build(args.baseline,root,bytes.fromhex(args.seed))
    if args.native_oracle:got['native']=native(root,args.native_oracle)
    print(json.dumps(got,indent=2))
if __name__=='__main__':main()
