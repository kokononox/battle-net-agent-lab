import hashlib
import json
import os
from pathlib import Path
import re
import sys

STATES={'success','failure','skipped','cancelled',''}
def validate(r):
    keys='schema source_commit run_id runner_kind unit_outcome deps_outcome package_outcome native_outcome artifact_url artifact_digest selftest python_version build_manifest_sha256 game_update_tested user_pc_accessed standard_runner_only'
    if type(r) is not dict or set(r)!=set(keys.split()) or r['schema']!='local-observer-build-1':raise ValueError('schema')
    if not re.fullmatch('[a-f0-9]{40}',r['source_commit']) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('identity')
    if r['runner_kind']!='windows-2025' or r['game_update_tested'] is not False or r['user_pc_accessed'] is not False or r['standard_runner_only'] is not True:raise ValueError('scope')
    for k in ('unit_outcome','deps_outcome','package_outcome','native_outcome'):
        if r[k] not in STATES:raise ValueError('outcome')
    if r['artifact_url']:
        if not re.fullmatch('https://github.com/kokononox/battle-net-agent-lab/actions/runs/'+r['run_id']+r'/artifacts/[0-9]+',r['artifact_url']):raise ValueError('artifact_url')
        if not re.fullmatch('[a-f0-9]{64}',r['artifact_digest']) or r['native_outcome']!='success':raise ValueError('unpassed_artifact')
    for k in ('build_manifest_sha256',):
        if r[k] is not None and not re.fullmatch('[a-f0-9]{64}',r[k]):raise ValueError('hash')
    if r['python_version'] is not None and not re.fullmatch('[0-9.]{3,30}',r['python_version']):raise ValueError('python')
    if r['selftest'] is not None:
        s=r['selftest']
        if set(s)!=set('passed loopback_only send_observed wsasend_observed sspi_negative_input_observed fixture_excluded_from_real_report worker_exited script_errors error_code'.split()):raise ValueError('test_schema')
        for k in set(s)-{'script_errors','error_code'}:
            if type(s[k]) is not bool:raise ValueError('test_bool')
        if type(s['script_errors']) is not int or not 0<=s['script_errors']<10000:raise ValueError('test_errors')
        if s['error_code'] is not None and not re.fullmatch('[a-z0-9_]{1,100}',s['error_code']):raise ValueError('test_error')
        if r['artifact_url'] and (not all(s[k] for k in set(s)-{'script_errors','error_code'}) or s['script_errors'] or s['error_code']):raise ValueError('test_not_passed')
    elif r['artifact_url']:raise ValueError('no_test')
    return r

def main():
    if len(sys.argv)>1:
        src,dst=map(Path,sys.argv[1:]);r=validate(json.loads(src.read_text(encoding='utf-8')));dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text(json.dumps(r,indent=2)+'\n');return
    root=Path(__file__).resolve().parent;package=root/'release'/'Local-Retail-Privacy-Monitor-U1'
    test=package/'selftest-to-share.json';build=package/'BUILD-INFO.json';manifest=package/'MANIFEST-SHA256.json'
    r={'schema':'local-observer-build-1','source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'runner_kind':'windows-2025',
       **{key.lower():os.environ.get(key,'') for key in ('UNIT_OUTCOME','DEPS_OUTCOME','PACKAGE_OUTCOME','NATIVE_OUTCOME')},
       'artifact_url':os.environ.get('ARTIFACT_URL',''),'artifact_digest':os.environ.get('ARTIFACT_DIGEST',''),
       'selftest':json.loads(test.read_text()) if test.exists() else None,
       'python_version':json.loads(build.read_text()).get('python_version') if build.exists() else None,
       'build_manifest_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest() if manifest.exists() else None,
       'game_update_tested':False,'user_pc_accessed':False,'standard_runner_only':True}
    validate(r);(root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
if __name__=='__main__':main()
