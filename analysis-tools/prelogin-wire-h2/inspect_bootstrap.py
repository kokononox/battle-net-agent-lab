"""Official bootstrap identity ONLY. Never execute the downloaded file."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

OLD='de5d32d4ea5eed5a9e120027fb68b370976dbfecc8f2a8f91305977f0b87fcaf'


def validate(r):
    if type(r) is not dict or set(r)!=set('schema source_commit run_id status samples downloads_identical target_executed expected_h1_sha256'.split()):raise ValueError('schema')
    if r['schema']!='bnet-bootstrap-identity-only-1' or r['status'] not in ('complete','stopped') or r['expected_h1_sha256']!=OLD or r['target_executed'] is not False:raise ValueError('policy')
    if not re.fullmatch('[a-f0-9]{40}',r['source_commit']) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('identity')
    if type(r['downloads_identical']) is not bool or type(r['samples']) is not list or len(r['samples'])>2:raise ValueError('samples')
    for s in r['samples']:
        if type(s) is not dict or set(s)!=set('sha256 bytes authenticode_valid expected_blizzard_publisher accepted_for_execution winverifytrust_status'.split()):raise ValueError('sample')
        if not re.fullmatch('[a-f0-9]{64}',s['sha256']) or type(s['bytes']) is not int or not 0<s['bytes']<=128*1024**2:raise ValueError('hash_size')
        for k in ('authenticode_valid','expected_blizzard_publisher','accepted_for_execution'):
            if type(s[k]) is not bool:raise ValueError('boolean')
        if type(s['winverifytrust_status']) is not int or not -2**31<=s['winverifytrust_status']<2**31:raise ValueError('trust')
        if s['accepted_for_execution']!=(s['authenticode_valid'] and s['expected_blizzard_publisher']):raise ValueError('acceptance')
    same=len(r['samples'])==2 and r['samples'][0]['sha256']==r['samples'][1]['sha256']
    if r['downloads_identical']!=same or (r['status']=='complete' and len(r['samples'])!=2):raise ValueError('crossfoot')
    return r


def main():
    if len(sys.argv)==3:
        a,b=map(Path,sys.argv[1:])
        if a.stat().st_size>8192:raise ValueError('size')
        r=validate(json.loads(a.read_bytes()));b.parent.mkdir(parents=True,exist_ok=True);b.write_text(json.dumps(r,indent=2)+'\n');return
    if not (sys.platform=='win32' and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1' and os.environ.get('GITHUB_REF')=='refs/heads/research/prelogin-telemetry-wow-data-provenance' and os.environ.get('BOOTSTRAP_IDENTITY_ONLY')=='20261024-c1'):raise SystemExit('hosted_identity_only_required')
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
    import observe_agent as obs
    r={'schema':'bnet-bootstrap-identity-only-1','source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'status':'stopped','samples':[],'downloads_identical':False,'target_executed':False,'expected_h1_sha256':OLD}
    try:
        with tempfile.TemporaryDirectory(prefix='h2-identity-only-',dir=os.environ['RUNNER_TEMP']) as tmp:
            for n in range(2):
                p=Path(tmp)/('setup-'+str(n)+'.exe');download=obs.fetch_setup(p);signature=obs.signature(p,obs.clean_environment(os.environ))
                r['samples'].append({k:download[k] for k in ('sha256','bytes')}|signature)
            r['downloads_identical']=r['samples'][0]['sha256']==r['samples'][1]['sha256'];r['status']='complete'
    except Exception:pass
    finally:
        validate(r);out=Path('output');out.mkdir(exist_ok=True);(out/'bootstrap-identity.json').write_text(json.dumps(r,indent=2)+'\n')
        print(json.dumps({'status':r['status'],'samples':len(r['samples']),'target_executed':False}))


if __name__=='__main__':main()
