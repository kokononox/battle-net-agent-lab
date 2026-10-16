"""Optional network test: five pinned public Classic ZBSDIFF triplets.

No fixture binaries are bundled or executed. Reference commit and Git blob
identities are checked. Fixtures prove algorithm mechanics, not Retail install.
"""
import argparse
import hashlib
import json
import urllib.request
from pathlib import Path
from datetime import datetime, timezone
import patch_audit as a

COMMIT = '2d1294b9d8eba0c0d0ffc6387f0777f36ecae671'
REPO = 'wowemulation-dev/cascette-rs'
FIXDIR = 'crates/cascette-formats/test_fixtures/zbsdiff/'
MANIFEST_BLOB = '4921545272a42df55000506d36007683e0afb63c'
BASE = f'https://raw.githubusercontent.com/{REPO}/{COMMIT}/'


def git_blob(b):
    return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()


def run(root):
    root = Path(root)
    a.require(not root.exists() and not root.is_symlink(), 'new_fixture_directory_required')
    root.mkdir()
    opener = urllib.request.build_opener(a.NoRedirect())
    total = 0
    receipts = []
    def fetch(path, blob=None):
        nonlocal total
        url = BASE + path
        with opener.open(urllib.request.Request(url,headers={'Accept-Encoding':'identity'}),timeout=30) as r:
            a.validate_response(r,url,100000,None)
            b = r.read(100001)
        a.require(len(b)<=100000 and total+len(b)<=250000,'fixture_budget')
        total+=len(b)
        if blob is not None:a.require(git_blob(b)==blob,'reference_blob_mismatch')
        receipts.append({'url':url,'bytes':len(b),'git_blob':git_blob(b),'sha256':a.sha256(b)})
        return b
    manifest = fetch(FIXDIR+'manifest.json',MANIFEST_BLOB)
    specs = json.loads(manifest)
    a.require(len(specs)==5,'expected_five_fixtures')
    results=[]
    for spec in specs:
        k=a.key(spec['patch_ekey'])
        old=fetch(FIXDIR+k+'.old')
        patch=fetch(FIXDIR+k+'.zbsdiff')
        new=fetch(FIXDIR+k+'.new')
        a.require(len(old)==spec['old_size'] and len(new)==spec['new_size'] and len(patch)==spec['patch_size'],'fixture_sizes')
        a.require(a.md5(patch)==k and a.md5(new)==spec['target_ckey'],'fixture_identity')
        rebuilt,info=a.apply_patch(old,patch,k,len(new),spec['target_ckey'],source_sha256=a.sha256(old))
        a.require(rebuilt==new,'independent_expected_output_mismatch')
        rejected = False
        try:
            a.apply_patch(old+b'!',patch,k,len(new),spec['target_ckey'],source_sha256=a.sha256(old))
        except a.AuditError:
            rejected=True
        a.require(rejected,'modified_source_not_rejected')
        results.append({**spec,'exact_expected_bytes_matched':True,'final_ckey_verified':True,
                        'modified_source_rejected':True,'source_sha256':a.sha256(old),'target_sha256':a.sha256(rebuilt),**info})
    report={'checked_at_utc':datetime.now(timezone.utc).isoformat(),'status':'five_reference_triplets_reconstructed',
            'source_repository':REPO,'source_commit':COMMIT,'source_manifest_git_blob':MANIFEST_BLOB,
            'scope':'public Classic fixtures, not the Retail sample or user installation',
            'fixture_count':len(results),'results':results,'network_body_bytes':total,'receipts':receipts,
            'user_game_files_read':False,'retail_sample_reconstructed':False,'installation_ready':False,
            'source_ekey_proven_by_decoded_bytes':False}
    (root/'REFERENCE-FIXTURE-RESULTS.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True)
    report=run(parser.parse_args().output)
    print(json.dumps({k:report[k] for k in ('status','fixture_count','network_body_bytes','retail_sample_reconstructed')}))
