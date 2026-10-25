import argparse,base64,hashlib,json,re,urllib.request
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('log',type=Path);p.add_argument('--run',required=True);p.add_argument('--commit',required=True);p.add_argument('--label',required=True);a=p.parse_args()
assert re.fullmatch('[a-z0-9-]{1,60}',a.label) and re.fullmatch('[a-f0-9]{40}',a.commit) and a.run.isdigit()
s=a.log.read_text();matches=re.findall(r'G41_EVIDENCE_B64=([A-Za-z0-9+/=]+)',s)
if not matches:raise SystemExit('verified_report_not_found')
e=json.loads(base64.b64decode(matches[-1],validate=True));assert e['schema']=='quarantine_system_g41_v1'
assert e['run_id']==a.run and e['source_commit']==a.commit
base=Path(__file__).resolve().parents[2];root=base/'analysis-tools/quarantine-system-g41';mapping={};cache=base/'.g41-source-cache'/a.commit;cache.mkdir(parents=True,exist_ok=True)
for name,want in e['source_sha256'].items():
 assert Path(name).name==name and re.fullmatch('[A-Za-z0-9_.-]+',name)
 b=(root/name).read_bytes() if (root/name).exists() else b'';origin='current_local'
 if hashlib.sha256(b).hexdigest()!=want and hashlib.sha256(b.replace(b'\r\n',b'\n').replace(b'\n',b'\r\n')).hexdigest()!=want:
  f=cache/name
  if not f.exists():
   u=f'https://raw.githubusercontent.com/kokononox/battle-net-agent-lab/{a.commit}/analysis-tools/quarantine-system-g41/{name}'
   f.write_bytes(urllib.request.urlopen(u,timeout=30).read())
  b=f.read_bytes();origin='pinned_source'
 if hashlib.sha256(b).hexdigest()==want:conversion='exact_bytes'
 elif hashlib.sha256(b.replace(b'\r\n',b'\n').replace(b'\n',b'\r\n')).hexdigest()==want:conversion='windows_CRLF_checkout'
 else:raise AssertionError('source_mismatch:'+name)
 mapping[name]={'source':origin,'conversion':conversion,'runtime_sha256':want,'source_sha256':hashlib.sha256(b).hexdigest()}
report=base/'reports/quarantine-system-g41'
(report/(a.label+'-evidence.json')).write_text(json.dumps(e,indent=2)+'\n');(report/(a.label+'-source-verification.json')).write_text(json.dumps(mapping,indent=2)+'\n')
if e['status']=='three_synthetic_scenarios_verified':
 assert [r['mode'] for r in e['scenarios']]==['finish','cancel','error']
 for row in e['scenarios']:
  c=row['case'];r=row['recovery']
  assert c['baseline_connected'] is True and c['blocked_connected'] is False and row['post_restore_connected'] is True
  assert all(c[k] is True for k in ('gate_before','gate_after','capture_blocked','private_capture_stored','private_marker_retained','public_marker_absent','credential_redacted','fixture_alive_during_gate'))
  assert r['job_active_zero'] is True and r['job_terminated'] is True and r['firewall_restored'] is True and r['fingerprint_match'] is True
  assert r['active_before_termination']>0 and row['watchdog_exited'] is True and row['gate_armed'] is True and row['passed'] is True
  assert r['reason']==('controller_exit' if row['mode']=='error' else row['mode'])
  assert row['coordinator_exit_code']==(23 if row['mode']=='error' else 0) and c['error_code'] is None
 assert e['fallback_scoped_recovery_ok'] is True
 print('Independent per-scenario assertions passed')
print(json.dumps({'status':e['status'],'error':e['error_code'],'source_files_verified':len(mapping),'scenarios':[{'mode':r['mode'],'passed':r['passed'],'error':r['case']['error_code'],'stage':r['case'].get('stage')} for r in e['scenarios']]}))
