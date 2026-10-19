import hashlib,json,os,re,sys
from pathlib import Path
SCOPE='network_changed dns_queried resident_program_created enforcement_tested user_device_tested ready_for_user_apply'.split()
NATIVE=set(['schema','source_commit','run_id','passed','checks','error_code']+SCOPE)
def check(n):
 if type(n) is not dict or set(n)!=NATIVE or n['schema']!='sstp-allowlist-policy-test-1':raise ValueError('native_schema')
 if not re.fullmatch('[a-f0-9]{40}',n['source_commit']) or not re.fullmatch('[0-9]{1,30}',n['run_id']):raise ValueError('identity')
 if type(n['passed']) is not bool or type(n['checks']) is not int or not 0<=n['checks']<=35:raise ValueError('counts')
 if any(n[k] is not False for k in SCOPE):raise ValueError('scope')
 if n['error_code'] is not None and not re.fullmatch('policy_[a-z_0-9]{1,80}',n['error_code']):raise ValueError('error')
 if n['passed'] and (n['checks']!=35 or n['error_code'] is not None):raise ValueError('pass')
 return n
if __name__=='__main__':
 root=Path(__file__).parent;src=os.environ['GITHUB_SHA'];run=os.environ['GITHUB_RUN_ID'];p=Path(os.environ['RUNNER_TEMP'])/'policy-native.json'
 n=json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else dict(schema='sstp-allowlist-policy-test-1',source_commit=src,run_id=run,passed=False,checks=0,error_code='policy_native_unavailable',**{k:False for k in SCOPE})
 check(n)
 if n['source_commit']!=src or n['run_id']!=run:raise ValueError('expected_identity')
 outcome=os.environ['NATIVE_OUTCOME'];assert outcome in ['success','failure','cancelled','skipped']
 if outcome=='success' and not n['passed']:raise ValueError('outcome')
 r=dict(schema='sstp-allowlist-policy-build-1',source_commit=src,run_id=run,native_outcome=outcome,native=n,hashes={f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in ['Policy.ps1','Test-Policy.ps1','allowlist.example.json']},ready_for_user_apply=False)
 (root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
 if not n['passed']:sys.exit(1)
