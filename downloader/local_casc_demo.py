"""Offline end-to-end local reuse demo. Creates a NEW case, no game access/network."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import threading
import zlib
import local_casc
import lookup3
import plan_storage as store
import repair_core as core


def _entry(key, offset, size):
    return key[:9]+offset.to_bytes(5,'big')+size.to_bytes(4,'little')


def _index(entries):
    header=struct.pack('<HBBBBBBQ',7,0,0,4,5,9,30,0x4000000000)
    a=b=0
    for row in entries:
        a,b=lookup3.hashlittle2(row,a,b)
    body=b''.join(entries)
    return struct.pack('<II',16,lookup3.hashlittle(header))+header+bytes(8)+struct.pack('<II',len(body),a)+body


def run(new_case):
    case=core.safe(new_case)
    if case.exists():
        raise core.RepairError('new_demo_case_must_not_exist')
    case.mkdir(parents=True)
    lab=core.Lab.create(case/'lab')
    folder=case/'generated-storage'/'Data'/'data'
    folder.mkdir(parents=True)
    data=[b'local healthy content A'*11,b'local healthy content B'*19,b'local damaged content C'*13]
    blobs=[b'BLTE'+bytes(4)+b'Z'+zlib.compress(d) for d in data]
    keys=[hashlib.md5(b).digest() for b in blobs]
    ckeys=[hashlib.md5(d).digest() for d in data]
    binding={'product':'wow','region':'eu','version':'synthetic-local-demo',
             'build_config':'a'*32,'cdn_config':'b'*32}
    with store.Writer(lab,'demo-plan',threading.Event()) as out:
        out.db.execute('''CREATE TABLE plan(ekey BLOB PRIMARY KEY,encoded_size INTEGER,
            ckey BLOB,decoded_size INTEGER,mapping_state TEXT,route_kind TEXT,transfer_supported INTEGER)''')
        for i,k in enumerate(keys):
            out.db.execute('INSERT INTO plan VALUES (?,?,?,?,?,?,?)',
                (k,len(blobs[i]),ckeys[i],len(data[i]),'mapped','archive',1))
        out.metadata('target_binding',binding)
        out.metadata('plan_id','offline-demo-plan')
    plan=out.path
    archive=bytearray();entries=[]
    for i,b in enumerate(blobs):
        offset=len(archive)
        actual=b if i<2 else b[:-1]+bytes([b[-1]^1])
        archive+=bytes(30)+actual
        entries.extend([_entry(keys[i],offset,len(b)+30),_entry(keys[i],offset+30,len(b))])
    (folder/'data.000').write_bytes(archive)
    raw=_index(entries)
    for gen in (1,2):
        (folder/('00%08x.idx'%gen)).write_bytes(raw)
    before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.iterdir()}
    inventory,inv=local_casc.inventory(lab,plan,folder)
    paused,ev=local_casc.verify_batch(lab,plan,inv,byte_budget=0)
    first,ev=local_casc.verify_batch(lab,plan,inv,previous=ev,max_candidates=1)
    final,ev=local_casc.verify_batch(lab,plan,inv,previous=ev)
    remaining=local_casc.remaining(lab,plan,inv,ev)
    after={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.iterdir()}
    assert before==after
    assert inventory['reference_aliases_collapsed']==9
    assert paused['candidate_rows_pending']==3
    assert first['batch_candidate_rows_completed']==1
    assert final['target_objects_fully_verified_locally']==2
    assert remaining['remaining_conditional_transfer_candidates']==1
    result={'scope':'generated offline local CASC reuse demonstration; NOT real game storage',
        'success':True,'normalized_candidates':3,'reference_aliases_collapsed':9,
        'fully_verified_reusable_objects':2,'damaged_fixture_not_subtracted':True,
        'budget_pause_and_checkpoint_resume_verified':True,'generated_source_files_unchanged':True,
        'required_user_download_bytes':None,'installation_ready':False}
    core.atomic_json(case/'DEMO-RESULT.json',result)
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--new-case',required=True,type=Path)
    args=parser.parse_args()
    print(json.dumps(run(args.new_case),indent=2))
