import hashlib,json,os,re,sys
from pathlib import Path

def validate(r):
    if type(r) is not dict or set(r)!=set('schema source_commit run_id runner_kind native_outcome native hashes parse_error user_device_tested firewall_import_used enforcement_tested'.split()) or r['schema']!='sstp-rollback-s3-build-1' or r['runner_kind']!='windows-2025':raise ValueError('schema')
    if not re.fullmatch('[a-f0-9]{40}',r['source_commit']) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('identity')
    if set(r['hashes'])!=set(['Core.ps1','Timed-Rollback.ps1','Crash-Driver.ps1','Run-CI-Tests.ps1']) or any(not re.fullmatch('[a-f0-9]{64}',x) for x in r['hashes'].values()):raise ValueError('hashes')
    if any(r[k] is not False for k in ['user_device_tested','firewall_import_used','enforcement_tested']):raise ValueError('scope')
    if r['native_outcome'] not in ['success','failure','skipped','cancelled']:raise ValueError('outcome')
    if r['native_outcome']=='success':
        n=r['native']
        if not n or n['schema']!='sstp-targeted-rollback-s3-native-1' or n['passed'] is not True or n['fixture_checks']!=16 or n['stage']!='complete' or n['error_code'] is not None:raise ValueError('native')
        if any(n[k] is not False for k in ['user_device_tested','sstp_or_level3_enforcement_tested','firewall_import_used','concurrent_write_protection_atomic']):raise ValueError('native_scope')
        rows=n['scenarios']
        if len(rows)!=2 or [x['scenario'] for x in rows]!=['full','partial_conflict']:raise ValueError('scenario_count')
        for i,p in enumerate(rows):
            if any(p[k] is not True for k in ['driver_abrupt_exit_verified','profile_transition_observed','system_timer_verified','targeted_profile_restore_verified','fixture_a_restore_verified','unrelated_fixture_edit_preserved','repeat_no_writes_verified','task_removed','fixture_rules_removed']):raise ValueError('scenario_check')
            if p['emergency_controller_restore_used'] is not False or p['driver_exit_code']!=73 or p['expected_conflicts']!=i or p['observed_conflicts']!=i or p['task_last_result']!=2*i or p['conflict_fixture_preserved'] is not bool(i):raise ValueError('scenario_scope')
    return r

def main():
    if len(sys.argv)==3:
        a,b=map(Path,sys.argv[1:]);r=validate(json.loads(a.read_text(encoding='utf-8-sig')));b.parent.mkdir(parents=True,exist_ok=True);b.write_text(json.dumps(r,indent=2)+'\n');return
    root=Path(__file__).parent
    def read(n):
        p=root/n
        return json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else None
    r={'schema':'sstp-rollback-s3-build-1','source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'runner_kind':'windows-2025','native_outcome':os.environ.get('NATIVE_OUTCOME','skipped'),'native':read('native-result.json'),'hashes':{n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ['Core.ps1','Timed-Rollback.ps1','Crash-Driver.ps1','Run-CI-Tests.ps1']},'parse_error':read('parse-error.json'),'user_device_tested':False,'firewall_import_used':False,'enforcement_tested':False}
    validate(r);(root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
if __name__=='__main__':main()
