"""Generated payloads only; emits reproducible receipts, never opens game or Lab.
Run from package root: python -B research/synthetic-casc-storage/run_research.py ORACLE
"""
import hashlib,json,os,subprocess,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
import synthetic_casc_store as s
import synthetic_casc_format as f
import patch_audit as a

oracle=Path(sys.argv[1]).resolve(strict=True)
report={'format':'synthetic-storage-research-1','real_game_written':False,'payloads':'generated strings only','platform':sys.platform,'reference_commit':'38a34665624b8775bb875274b36191b21c38d97b','crash_matrix':[],'native_index_checks':[],'scope_limits':['custom active.json, not vendor activation','community span checksum-B not proven for Agent 9824','CascLib capture functions only; not full CascOpenStorage','Linux process-exit experiments; not Windows or power-loss proof']}
with tempfile.TemporaryDirectory(prefix='synthetic-storage-research-') as temp:
    root=Path(temp).resolve()
    env={**os.environ,'PYTHONPATH':str(Path(s.__file__).resolve().parent)}
    for i,phase in enumerate(s.PHASES):
        store=s.Store.create(root/f'crash-{i}')
        store.add([(b'old synthetic object','z')]);old=store.pointer();before=store.view()
        oldfolder=store.root/'generations'/old['generation']
        oldhash={p.name:a.sha256(p.read_bytes()) for p in oldfolder.iterdir()}
        code='import os,sys;from synthetic_casc_store import Store;Store(sys.argv[1]).add([(b"new synthetic object","z")],lambda p:os._exit(91) if p==sys.argv[2] else None)'
        run=subprocess.run([sys.executable,'-B','-c',code,str(store.root),phase],env=env,capture_output=True,text=True)
        if run.returncode!=91:raise RuntimeError('missing interruption: '+run.stderr)
        fresh=s.Store(store.root);recovery=fresh.recover();values=fresh.view()
        expected='new' if phase=='committed_recorded' else 'old'
        actual='old' if values==before and fresh.pointer()==old else 'new' if len(values)==2 else 'invalid'
        unchanged=oldhash=={p.name:a.sha256(p.read_bytes()) for p in oldfolder.iterdir()}
        repeat=fresh.recover()==fresh.recover()
        if actual!=expected or not unchanged or not repeat:raise RuntimeError('recovery mismatch')
        report['crash_matrix'].append({'phase':phase,'child_exit':run.returncode,'expected':expected,'actual':actual,'old_generation_unchanged':unchanged,'repeat_recovery_stable':repeat,'recovery_reports':recovery})
    keys=['001100000000000000'+'44'*7,'110000000000000000'+'55'*7,'000011000000000000'+'66'*7]
    bucket=f.bucket(keys[0]);assert all(f.bucket(k)==bucket for k in keys)
    rows=[{'ekey':key,'archive':i,'offset':i*188,'span':188} for i,key in enumerate(keys)]
    raw=f.make_index(rows,bucket);p=root/'multi.idx'
    for label,at in [('valid',None),('header_hash_corruption',4),('entry_hash_corruption',36),('entry_payload_corruption',41)]:
        sample=bytearray(raw)
        if at is not None:sample[at]^=1
        p.write_bytes(sample);run=subprocess.run([str(oracle),str(p),str(bucket)],capture_output=True,text=True)
        result=json.loads(run.stdout);expected=at is None
        assert result['accepted']==expected and (run.returncode==0)==expected
        if expected:assert result['entries']==3
        report['native_index_checks'].append({'case':label,'exit':run.returncode,'result':result,'index_sha256':a.sha256(bytes(sample))})
    store=s.Store.create(root/'rollover',archive_limit=512)
    store.add([(b'A'*250,'n'),(b'B'*250,'n')]);m,files,decoded=store.generation(store.pointer())
    assert len(m['archives'])==2 and sorted(decoded.values())==[b'A'*250,b'B'*250]
    report['rollover']={'archives':len(m['archives']),'objects':len(decoded),'archive_bytes':[len(files[k]) for k in sorted(m['archives'])]}
report['passed']=True
print(json.dumps(report,indent=2))
