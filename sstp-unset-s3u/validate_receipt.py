import hashlib,json,os,re,sys
from pathlib import Path

def validate(r):
    if type(r) is not dict or set(r)!=set('schema source_commit run_id runner_kind native_outcome native hashes parse_error user_device_tested ready_for_user_apply'.split()) or r['schema']!='sstp-unset-s3u-build-1' or r['runner_kind']!='windows-2025':raise ValueError('schema')
    if not re.fullmatch('[a-f0-9]{40}',r['source_commit']) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('identity')
    if set(r['hashes'])!=set(['Core.ps1','Timer.ps1','Driver.ps1','Run-CI.ps1']) or any(not re.fullmatch('[a-f0-9]{64}',v) for v in r['hashes'].values()):raise ValueError('hashes')
    if r['user_device_tested'] is not False or r['ready_for_user_apply'] is not False:raise ValueError('scope')
    if r['native_outcome'] not in ['success','failure','cancelled','skipped']:raise ValueError('outcome')
    if r['native_outcome']=='success':
        n=r['native']
        if not n or n['schema']!='sstp-unset-s3u-native-1' or n['passed'] is not True or n['fixture_checks']!=13 or n['stage']!='complete' or n['error_code'] is not None:raise ValueError('native')
        if any(n[k] is not False for k in ['user_device_tested','enforcement_tested','registry_written_directly','policy_reset_or_import_used','s3_hardened_guard_changed','ready_for_user_apply']):raise ValueError('native_scope')
        if not re.fullmatch('[0-9.]{1,40}',n['os_version']) or not re.fullmatch('[0-9]{1,20}',n['os_build']) or not re.fullmatch('[0-9.]{1,40}',n['ps_version']):raise ValueError('platform')
        if len(n['rounds'])!=2 or [x['round'] for x in n['rounds']]!=[1,2]:raise ValueError('rounds')
        for p in n['rounds']:
            if any(p[k]!=3 for k in ['baseline_profile_count','baseline_notconfigured_count','observed_block_count','restore_write_calls']):raise ValueError('observed_counts')
            if any(p[k] is not True for k in ['outbound_registry_mutation_observed','driver_abrupt_exit_verified','system_timer_verified','stored_state_exact','registry_profile_values_exact','effective_cim_exact','effective_com_exact','selected_rule_properties_exact','task_removed']):raise ValueError('state')
            if p['controller_fallback_used'] is not False or p['repeat_restore_write_calls']!=0 or p['task_last_result']!=0:raise ValueError('fallback_or_repeat')
            if any(type(p[k]) is not int or p[k]<0 for k in ['registry_outbound_values_before','registry_outbound_values_during','registry_outbound_values_after']) or p['registry_outbound_values_before']!=p['registry_outbound_values_after']:raise ValueError('presence')
    return r

def main():
    if len(sys.argv)==3:
        a,b=map(Path,sys.argv[1:]);r=validate(json.loads(a.read_text(encoding='utf-8-sig')));b.parent.mkdir(parents=True,exist_ok=True);b.write_text(json.dumps(r,indent=2)+'\n');return
    root=Path(__file__).parent
    def read(n):
        p=root/n
        return json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else None
    r={'schema':'sstp-unset-s3u-build-1','source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'runner_kind':'windows-2025','native_outcome':os.environ.get('NATIVE_OUTCOME','skipped'),'native':read('native-result.json'),'hashes':{n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ['Core.ps1','Timer.ps1','Driver.ps1','Run-CI.ps1']},'parse_error':read('parse-error.json'),'user_device_tested':False,'ready_for_user_apply':False}
    validate(r);(root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
if __name__=='__main__':main()
