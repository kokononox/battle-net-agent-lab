import hashlib,json,os,re,sys
from pathlib import Path
FLAGS='live_sstp_projection_tested user_identity_chain_tested network_policy_changed dns_queried credentials_read resident_program_created firewall_filter_binding_qualified enforcement_tested ready_for_user_apply'.split()
KEYS=set('schema source_commit run_id passed checks error_code sdk_abi_verified native_iphelper_roundtrip_tested ras_enumeration_available ras_enumeration_error_code ras_enumerated_connection_count'.split()+FLAGS)
def validate(n):
 if type(n) is not dict or set(n)!=KEYS or n['schema']!='sstp-ras-identity-test-1':raise ValueError('schema')
 if not re.fullmatch('[a-f0-9]{40}',n['source_commit']) or not re.fullmatch('[0-9]{1,30}',n['run_id']):raise ValueError('identity')
 for k in ['passed','sdk_abi_verified','native_iphelper_roundtrip_tested','ras_enumeration_available']:
  if type(n[k]) is not bool:raise ValueError('bool')
 if type(n['checks']) is not int or not 0<=n['checks']<=40:raise ValueError('checks')
 if any(n[k] is not False for k in FLAGS):raise ValueError('scope')
 code=n['ras_enumeration_error_code'];count=n['ras_enumerated_connection_count']
 if code is not None and (type(code) is not int or not 1<=code<=2**32-1):raise ValueError('api_code')
 if count is not None and (type(count) is not int or not 0<=count<=128):raise ValueError('enum_count')
 if n['ras_enumeration_available'] and (code is not None or count is None):raise ValueError('available')
 if not n['ras_enumeration_available'] and count is not None:raise ValueError('unavailable')
 if n['error_code'] not in [None,'binding_native_failure','binding_native_unavailable']:raise ValueError('error')
 if n['passed'] and (n['checks']!=40 or n['error_code'] is not None or not n['sdk_abi_verified'] or not n['native_iphelper_roundtrip_tested'] or (not n['ras_enumeration_available'] and code is None)):raise ValueError('pass')
 return n
if __name__=='__main__':
 root=Path(__file__).parent;src=os.environ['GITHUB_SHA'];run=os.environ['GITHUB_RUN_ID'];p=Path(os.environ['RUNNER_TEMP'])/'ras-identity-native.json'
 n=json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else dict(schema='sstp-ras-identity-test-1',source_commit=src,run_id=run,passed=False,checks=0,error_code='binding_native_unavailable',sdk_abi_verified=False,native_iphelper_roundtrip_tested=False,ras_enumeration_available=False,ras_enumeration_error_code=None,ras_enumerated_connection_count=None,**{k:False for k in FLAGS})
 validate(n)
 if n['source_commit']!=src or n['run_id']!=run:raise ValueError('expected_identity')
 outcome=os.environ['NATIVE_OUTCOME']
 if outcome not in ['success','failure','cancelled','skipped'] or (outcome=='success' and not n['passed']):raise ValueError('outcome')
 names=['RasIdentity.cs','Policy.ps1','Inspect-RasIdentity.ps1','Test-RasIdentity.ps1','AbiProbe.cpp']
 r=dict(schema='sstp-ras-identity-build-1',source_commit=src,run_id=run,native_outcome=outcome,native=n,hashes={f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in names},ready_for_user_apply=False)
 (root/'build-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
 if not n['passed']:sys.exit(1)
