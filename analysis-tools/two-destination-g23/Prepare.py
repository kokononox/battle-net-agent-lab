"""Control build preflight only; no Battle.net download, cert probe or cache warming."""
import hashlib,json,os,sys
from pathlib import Path
root=Path(sys.argv[1]);c=json.loads((root/'config.json').read_text(encoding='utf-8-sig'))
if os.environ.get('BNET_ONLINE_G23')!='lab: approved native TLS control G23 20261025' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or c.get('scenario')!='tls_control':raise SystemExit('fresh_control_required')
raw=(root/'OfflineLauncher.exe').read_bytes();sha=hashlib.sha256(raw).hexdigest()
r={'trusted_repository_control_build':sha==c.get('helper_sha256') and 0<len(raw)<=8388608,'helper_sha256':sha,'bytes':len(raw),'installer_downloaded':False,'cache_warming_requested':False,'error_code':None}
if not r['trusted_repository_control_build']:r['error_code']='control_build_mismatch'
(root/'preflight.json').write_text(json.dumps(r));print(json.dumps(r))
if r['error_code']:raise SystemExit(1)
