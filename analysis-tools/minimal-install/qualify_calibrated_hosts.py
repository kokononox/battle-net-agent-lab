"""D2 qualification: real OS hosts lifecycle on three independent disposable VMs.
No installer download/launch, account action, firewall mutation or TLS changes.
"""
import json,os,re,sys,tempfile,time
from pathlib import Path
from calibrated_hosts import CalibratedHosts,blank,validate_record,DOMAINS,CONTROL,POLICY
BRANCH='research/battlenet-minimal-install-isolation-2026-10-25'
APPROVAL='lab: approved calibrated DNS guard D2 20261025'
CASES={'telemetry':DOMAINS[0],'level3':DOMAINS[1],'us-version':DOMAINS[2]}

def authorized(env,platform):
 return (platform=='win32' and env.get('GITHUB_ACTIONS')=='true' and env.get('RUNNER_ENVIRONMENT')=='github-hosted' and env.get('RUNNER_OS')=='Windows' and env.get('GITHUB_REF')=='refs/heads/'+BRANCH and env.get('GITHUB_EVENT_NAME')=='push' and env.get('GITHUB_RUN_ATTEMPT')=='1' and env.get('BNET_DNS_D2')==APPROVAL and env.get('BNET_DNS_CASE') in CASES and bool(re.fullmatch('[a-f0-9]{40}',env.get('GITHUB_SHA',''))) and bool(re.fullmatch('[0-9]{1,30}',env.get('GITHUB_RUN_ID',''))))

def validate(r):
 if type(r) is not dict or set(r)!={'schema','source_commit','run_id','case','status','installer_launched','all_traffic_blocked_proven','error_code','hosts'}:raise ValueError('qualification_schema')
 if r['schema']!='bnet-calibrated-hosts-d2-1' or r['case'] not in CASES or not re.fullmatch('[a-f0-9]{40}',r['source_commit']) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('qualification_identity')
 if r['installer_launched'] is not False or r['all_traffic_blocked_proven'] is not False or r['status'] not in ('stopped','qualified'):raise ValueError('qualification_scope')
 if r['error_code'] is not None and (type(r['error_code']) is not str or not re.fullmatch('calibration_[a-z_]{1,80}',r['error_code'])):raise ValueError('qualification_error')
 validate_record(r['hosts'])
 if r['hosts']['domain']!=CASES[r['case']]:raise ValueError('qualification_case')
 if r['status']=='qualified' and (r['error_code'] is not None or not r['hosts']['restored'] or len(r['hosts']['checks'])!=3 or r['hosts']['verification_failures'] or not all(c['accepted'] for c in r['hosts']['checks'])):raise ValueError('qualification_claim')
 return r

def main():
 if not authorized(os.environ,sys.platform):raise SystemExit('approved_disposable_d2_required')
 sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
 import observe_agent as obs
 env=obs.clean_environment(os.environ);case=os.environ['BNET_DNS_CASE']
 r=dict(schema='bnet-calibrated-hosts-d2-1',source_commit=os.environ['GITHUB_SHA'],run_id=os.environ['GITHUB_RUN_ID'],case=case,status='stopped',installer_launched=False,all_traffic_blocked_proven=False,error_code=None,hosts=blank(CASES[case]))
 def write():
  validate(r);out=Path('output')/('dns-d2-'+case+'.json');out.parent.mkdir(exist_ok=True)
  data=json.dumps(r,indent=2)+'\n'
  if len(data.encode())>131072:raise ValueError('calibration_output_limit')
  out.write_text(data,encoding='utf-8')
 experiment=None
 try:
  with tempfile.TemporaryDirectory(prefix='bnet-dns-d2-',dir=os.environ['RUNNER_TEMP']) as tmp:
   experiment=CalibratedHosts(Path(os.environ['SystemRoot'])/'System32/drivers/etc/hosts',tmp,r['hosts'],env)
   try:
    experiment.apply();write()
    for _ in range(2):
     time.sleep(1)
     if not experiment.check():raise ValueError('calibration_repeated_check_failed')
     write()
   finally:
    if experiment.touched:
     if not experiment.restore():raise ValueError('calibration_restore_failed')
     write()
  r['status']='qualified'
 except Exception as exc:
  code=str(exc);r['error_code']=code if type(exc) is ValueError and re.fullmatch('calibration_[a-z_]{1,80}',code) else 'calibration_qualification_failed'
 finally:write()
 print(json.dumps(dict(case=case,status=r['status'],error_code=r['error_code'],installer_launched=False)))

if __name__=='__main__':
 if len(sys.argv)==3 and sys.argv[1]=='--validate':
  r=validate(json.loads(Path(sys.argv[2]).read_text(encoding='utf-8')))
  if r['source_commit']!=os.environ['GITHUB_SHA'] or r['run_id']!=os.environ['GITHUB_RUN_ID'] or r['case']!=os.environ['BNET_DNS_CASE']:raise SystemExit('qualification_artifact_identity')
 else:main()
