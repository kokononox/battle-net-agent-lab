"""Explicit local report export; no network operations or credential collection."""
from pathlib import Path
import hashlib,json,os,sys,uuid,zipfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
from state import assert_local_tree

def export():
    print('Local report ZIP may contain EXE paths, hashes, firewall rule names, VPN profile/server names and IPs.')
    print('Passwords, VPN credentials, full firewall backup and protected session journal are NOT collected.')
    if input('Type EXPORT to create a local ZIP (nothing is uploaded): ')!='EXPORT':return
    members={}
    results=sorted((ROOT/'private-state/lab-jobs').glob('*/result.json'))+sorted((ROOT/'private-state/recovery-jobs').glob('*/result.json'))
    for p in results:
        assert_local_tree(p)
        if p.stat().st_size>33554432:raise ValueError('oversized_result_not_exported')
        r=json.loads(p.read_text('utf-8-sig'))
        if isinstance(r.get('session'),dict):
            s=r.pop('session')
            r['session_summary']={k:s.get(k) for k in ('id','owner','phase','created_utc')}
            r['session_summary']['entry_count']=len(s.get('entries',[]))
        members[('recovery-results/' if p.parent.parent.name=='recovery-jobs' else 'lab-results/')+p.parent.name+'.json']=json.dumps(r,ensure_ascii=False,indent=2).encode('utf-8')
    if not members:raise ValueError('no_lab_results_yet')
    for name in ('QA.json','BUILD-INFO.json'):
        p=assert_local_tree(ROOT/name)
        if p.exists():members[name]=p.read_bytes()
    manifest={k:hashlib.sha256(v).hexdigest() for k,v in members.items()}
    members['report-sha256.json']=json.dumps(manifest,indent=2).encode()
    dest=assert_local_tree(ROOT/('UnifiedFW-051-LabResults-'+uuid.uuid4().hex[:12]+'.zip'))
    with zipfile.ZipFile(dest,'x',compression=zipfile.ZIP_DEFLATED) as z:
        for name,data in members.items():z.writestr(name,data)
    print('Created:',dest)
    print('Inspect before sharing. This is diagnostic evidence, not proof of packet isolation.')
if __name__=='__main__':
    try:export()
    except Exception as e:print('ERROR:',e)
    input('Press Enter to close. ')
