import hashlib,json,os,re,sys
from pathlib import Path

def validate(r):
    if type(r) is not dict or set(r)!=set('schema source_commit run_id runner_kind native_outcome fixture script_sha256 fixture_only network_settings_changed real_vpn_or_firewall_tested'.split()):raise ValueError('schema')
    if r['schema']!='sstp-preflight-s1-build-1' or r['runner_kind']!='windows-2025':raise ValueError('kind')
    if not re.fullmatch('[a-f0-9]{40}',r['source_commit']) or not re.fullmatch('[0-9]{1,30}',r['run_id']) or not re.fullmatch('[a-f0-9]{64}',r['script_sha256']):raise ValueError('identity')
    if r['fixture_only'] is not True or r['network_settings_changed'] is not False or r['real_vpn_or_firewall_tested'] is not False:raise ValueError('scope')
    if r['native_outcome'] not in {'success','failure','skipped','cancelled'}:raise ValueError('outcome')
    f=r['fixture']
    if f is not None:
        if set(f)!=set('schema passed tests real_vpn_or_firewall_queried network_dns_queried settings_changed'.split()):raise ValueError('fixture_schema')
        if f['schema']!='s1-preflight-fixture-1' or type(f['passed']) is not bool or type(f['tests']) is not int:raise ValueError('fixture_values')
        if any(f[k] is not False for k in ('real_vpn_or_firewall_queried','network_dns_queried','settings_changed')):raise ValueError('fixture_scope')
    if r['native_outcome']=='success' and (f is None or f['passed'] is not True or f['tests']!=20):raise ValueError('fixture_not_passed')
    return r

def main():
    if len(sys.argv)==3:
        src,dst=map(Path,sys.argv[1:]);r=validate(json.loads(src.read_text(encoding='utf-8-sig')));dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text(json.dumps(r,indent=2)+'\n');return
    root=Path(__file__).resolve().parent;f=root/'fixture-result.json'
    r={'schema':'sstp-preflight-s1-build-1','source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'runner_kind':'windows-2025','native_outcome':os.environ.get('NATIVE_OUTCOME','skipped'),
        'fixture':json.loads(f.read_text(encoding='utf-8-sig')) if f.exists() else None,'script_sha256':hashlib.sha256((root/'SSTP-Preflight.ps1').read_bytes()).hexdigest(),
        'fixture_only':True,'network_settings_changed':False,'real_vpn_or_firewall_tested':False}
    validate(r);(root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
if __name__=='__main__':main()
