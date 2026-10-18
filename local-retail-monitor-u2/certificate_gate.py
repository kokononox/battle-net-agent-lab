"""Test the real publisher policy. Download one pinned signed setup; NEVER execute it."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parent/'release'/'Local-Retail-Privacy-Monitor-U2'/'app'))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from core import signature
from observe_agent import fetch_setup
PIN='de5d32d4ea5eed5a9e120027fb68b370976dbfecc8f2a8f91305977f0b87fcaf'
r={'passed':False,'runtime_valid':False,'runtime_not_blizzard':False,'runtime_status':'not_tested','bootstrap_valid':False,'bootstrap_blizzard':False,'bootstrap_status':'not_tested','bootstrap_sha256':None,'downloaded_only_never_executed':True,'phase':'runtime','error_code':None}
try:
    own=signature(Path(sys.executable));r['runtime_valid']=own['valid'];r['runtime_not_blizzard']=not own['blizzard'];r['runtime_status']=own['status'];r['phase']='download'
    with tempfile.TemporaryDirectory(prefix='signature-only-') as x:
        dest=Path(x)/'Battle.net-Setup.exe';info=fetch_setup(dest);r['bootstrap_sha256']=info['sha256'];r['phase']='bootstrap_pin'
        if info['sha256']!=PIN:raise ValueError('bootstrap_pin_changed_no_execution')
        r['phase']='bootstrap_signature'
        actual=signature(dest);r['bootstrap_valid']=actual['valid'];r['bootstrap_blizzard']=actual['blizzard'];r['bootstrap_status']=actual['status']
        # Unsigned/non-Blizzard Python is a negative control, not a reason to relax Blizzard checks.
        r['passed']=r['runtime_not_blizzard'] and r['bootstrap_valid'] and r['bootstrap_blizzard'];r['phase']='complete'
except Exception as exc:
    r['error_code']=str(exc) if isinstance(exc,ValueError) and str(exc) in ('signature_check_failed','signature_check_rejected','signature_status_rejected','invalid_publisher_claim','bootstrap_pin_changed_no_execution') else 'signature_timeout' if isinstance(exc,__import__('subprocess').TimeoutExpired) else 'certificate_policy_gate_failed'
(Path(__file__).resolve().parent/'certificate-gate.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r))
if not r['passed']:raise SystemExit(1)
