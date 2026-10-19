"""Verify browser-downloaded bounded CI receipt against its exact push payload."""
import argparse,base64,hashlib,io,json,pathlib,zipfile
ap=argparse.ArgumentParser();ap.add_argument('artifact');ap.add_argument('payload');ap.add_argument('source');ap.add_argument('run');ap.add_argument('output');ap.add_argument('--require-ui',action='store_true');ap.add_argument('--pure-checks',type=int,default=247);a=ap.parse_args()
browser=json.loads(pathlib.Path(a.artifact).read_text());raw=base64.b64decode(browser['base64'],validate=True)
assert hashlib.sha256(raw).hexdigest()==browser['sha256']
z=zipfile.ZipFile(io.BytesIO(raw));assert z.namelist()==['build-receipt.json'];assert z.infolist()[0].file_size<20000
r=json.loads(z.read('build-receipt.json'))
assert r['schema']=='sstp-overlay-build-1' and r['source_commit']==a.source and r['run_id']==a.run
payload=json.loads(pathlib.Path(a.payload).read_text());code={pathlib.Path(x['path']).name:x['content'] for x in payload['files'] if x['path'].startswith('sstp-allowlist-overlay/')}
assert set(code)==set(r['sha256'])
for name,digest in r['sha256'].items():
 text=code[name].replace('\r\n','\n')
 assert digest in [hashlib.sha256(text.encode()).hexdigest(),hashlib.sha256(text.replace('\n','\r\n').encode()).hexdigest()],name
assert r['pure']['schema']=='sstp-overlay-ranges-1' and r['pure']['passed'] is True and r['pure']['checks']==a.pure_checks
n=r['native'];assert n is not None and n['schema']=='sstp-overlay-native-1' and n['source_commit']==a.source and n['run_id']==a.run
for field in ['checks','worker_exits','fault_recoveries','probe_pairs','remaining_objects','foreign_display_changes']:assert type(n[field]) is int
for field in ['ipv6_packet_tested','remote_access_packet_tested','real_sstp_tested','disconnect_tested','reboot_tested','user_device_tested','ready_for_production']:assert n[field] is False
if r['passed']:
 assert n['passed'] is True and n['checks']==40 and n['worker_exits']==12 and n['fault_recoveries']==2 and n['probe_pairs']==6
 assert n['remaining_objects']==0 and n['unrelated_policy_equal'] is True
 if a.require_ui:assert r['ui_outcome']=='success'
 assert r['pure_outcome']=='success' and r['native_outcome']=='success'
pathlib.Path(a.output).write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'verified':True,'passed':r['passed'],'source_files':len(code),'zip_sha256':browser['sha256'],'native':n,'ui':r.get('ui_outcome')},indent=2))
