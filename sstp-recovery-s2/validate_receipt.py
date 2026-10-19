import hashlib,json,os,re,sys
from pathlib import Path

def validate(r):
    keys='schema source_commit run_id runner_kind native_outcome fixture rehearsal main_sha256 worker_sha256 firewall_import_tested network_isolation_tested user_device_tested'.split()
    if type(r) is not dict or set(r)!=set(keys) or r['schema']!='sstp-recovery-s2-build-1' or r['runner_kind']!='windows-2025':raise ValueError('schema')
    if not re.fullmatch('[a-f0-9]{40}',r['source_commit']) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('identity')
    for k in ['main_sha256','worker_sha256']:
        if not re.fullmatch('[a-f0-9]{64}',r[k]):raise ValueError('hash')
    if any(r[k] is not False for k in ['firewall_import_tested','network_isolation_tested','user_device_tested']):raise ValueError('scope')
    if r['native_outcome'] not in ['success','failure','skipped','cancelled']:raise ValueError('outcome')
    if r['native_outcome']=='success':
        f=r['fixture'];p=r['rehearsal']
        if type(f) is not dict or set(f)!=set('schema passed checks network_settings_changed scheduled_task_created firewall_policy_exported'.split()) or f['schema']!='s2-rehearsal-fixture-1' or f['passed'] is not True or f['checks']!=17:raise ValueError('fixture')
        if any(f[k] is not False for k in ['network_settings_changed','scheduled_task_created','firewall_policy_exported']):raise ValueError('fixture_scope')
        if type(p) is not dict or set(p)!=set('passed firewall_backup_exported private_acl_checked system_probe_receipt_verified task_last_result owned_task_removed firewall_profile_summary_unchanged firewall_restore_import_tested network_settings_changed_by_tool'.split()):raise ValueError('rehearsal_schema')
        if any(p[k] is not True for k in ['passed','firewall_backup_exported','private_acl_checked','system_probe_receipt_verified','owned_task_removed','firewall_profile_summary_unchanged']) or p['task_last_result']!=0:raise ValueError('rehearsal')
        if p['firewall_restore_import_tested'] is not False or p['network_settings_changed_by_tool'] is not False:raise ValueError('rehearsal_scope')
    return r

def main():
    if len(sys.argv)==3:
        a,b=map(Path,sys.argv[1:]);r=validate(json.loads(a.read_text(encoding='utf-8-sig')));b.parent.mkdir(parents=True,exist_ok=True);b.write_text(json.dumps(r,indent=2)+'\n');return
    root=Path(__file__).parent
    def read(n):
        p=root/n
        return json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else None
    r={'schema':'sstp-recovery-s2-build-1','source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'runner_kind':'windows-2025','native_outcome':os.environ.get('NATIVE_OUTCOME','skipped'),'fixture':read('fixture-result.json'),'rehearsal':read('native-summary.json'),'main_sha256':hashlib.sha256((root/'Recovery-Rehearsal.ps1').read_bytes()).hexdigest(),'worker_sha256':hashlib.sha256((root/'Rollback-Probe.ps1').read_bytes()).hexdigest(),'firewall_import_tested':False,'network_isolation_tested':False,'user_device_tested':False}
    validate(r);(root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
if __name__=='__main__':main()
