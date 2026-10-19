import hashlib,json,os,re,sys
from pathlib import Path
FLAGS='network_changed firewall_changed dns_queried resident_program_created enforcement_tested user_device_tested ready_for_user_apply'.split()
def validate(n):
 if type(n) is not dict or set(n)!=set(['schema','source_commit','run_id','passed','checks','error_code']+FLAGS):raise ValueError('schema')
 if n['schema']!='sstp-journal-test-1' or not re.fullmatch('[a-f0-9]{40}',n['source_commit']) or not re.fullmatch('[0-9]{1,30}',n['run_id']):raise ValueError('identity')
 if type(n['passed']) is not bool or type(n['checks']) is not int or not 0<=n['checks']<=30:raise ValueError('counts')
 if any(n[k] is not False for k in FLAGS):raise ValueError('scope')
 if n['error_code'] not in [None,'journal_native_failure','journal_native_unavailable']:raise ValueError('error')
 if n['passed'] and (n['checks']!=30 or n['error_code'] is not None):raise ValueError('pass')
 return n
if __name__=='__main__':
 root=Path(__file__).parent;src=os.environ['GITHUB_SHA'];run=os.environ['GITHUB_RUN_ID'];p=Path(os.environ['RUNNER_TEMP'])/'journal-native.json'
 n=json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else dict(schema='sstp-journal-test-1',source_commit=src,run_id=run,passed=False,checks=0,error_code='journal_native_unavailable',**{k:False for k in FLAGS})
 validate(n)
 if n['source_commit']!=src or n['run_id']!=run:raise ValueError('expected_identity')
 outcome=os.environ['NATIVE_OUTCOME']
 if outcome not in ['success','failure','cancelled','skipped'] or (outcome=='success' and not n['passed']):raise ValueError('outcome')
 r=dict(schema='sstp-journal-build-1',source_commit=src,run_id=run,native_outcome=outcome,native=n,hashes={f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in ['Journal.ps1','RestorePolicy.ps1','Test-Journal.ps1']},ready_for_user_apply=False)
 (root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
 if not n['passed']:sys.exit(1)
