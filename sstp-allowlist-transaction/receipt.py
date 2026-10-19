import hashlib,json,os,re,sys
from pathlib import Path
FLAGS='firewall_changed dns_queried resident_program_created real_guard_tested enforcement_tested sstp_binding_tested user_device_tested ready_for_user_apply'.split()
KEYS=set('schema source_commit run_id passed checks fault_cases fresh_process_recoveries error_code adapter_kind'.split()+FLAGS)
def validate(n):
 if type(n) is not dict or set(n)!=KEYS or n['schema']!='sstp-transaction-test-1' or n['adapter_kind']!='file_model_only':raise ValueError('schema')
 if not re.fullmatch('[a-f0-9]{40}',n['source_commit']) or not re.fullmatch('[0-9]{1,30}',n['run_id']):raise ValueError('identity')
 if type(n['passed']) is not bool:raise ValueError('bool')
 for k,m in [('checks',231),('fault_cases',36),('fresh_process_recoveries',36)]:
  if type(n[k]) is not int or not 0<=n[k]<=m:raise ValueError('counts')
 if any(n[k] is not False for k in FLAGS):raise ValueError('scope')
 if n['error_code'] not in [None,'transaction_native_failure','transaction_native_unavailable']:raise ValueError('error')
 if n['passed'] and (n['checks']!=231 or n['fault_cases']!=36 or n['fresh_process_recoveries']!=36 or n['error_code'] is not None):raise ValueError('pass')
 return n
if __name__=='__main__':
 root=Path(__file__).parent;src=os.environ['GITHUB_SHA'];run=os.environ['GITHUB_RUN_ID'];p=Path(os.environ['RUNNER_TEMP'])/'transaction-native.json'
 n=json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else dict(schema='sstp-transaction-test-1',source_commit=src,run_id=run,passed=False,checks=0,fault_cases=0,fresh_process_recoveries=0,error_code='transaction_native_unavailable',adapter_kind='file_model_only',**{k:False for k in FLAGS})
 validate(n)
 if n['source_commit']!=src or n['run_id']!=run:raise ValueError('expected_identity')
 outcome=os.environ['NATIVE_OUTCOME']
 if outcome not in ['success','failure','cancelled','skipped'] or (outcome=='success' and not n['passed']):raise ValueError('outcome')
 files={f:root/f for f in ['ModelEngine.ps1','Worker.ps1','Test-Transactions.ps1']};files['Journal.ps1']=root.parent/'sstp-allowlist-backend/Journal.ps1'
 r=dict(schema='sstp-transaction-build-1',source_commit=src,run_id=run,native_outcome=outcome,native=n,hashes={f:hashlib.sha256(p.read_bytes()).hexdigest() for f,p in files.items()},ready_for_user_apply=False)
 (root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
 if not n['passed']:sys.exit(1)
