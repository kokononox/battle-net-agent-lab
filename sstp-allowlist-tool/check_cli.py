"""Local cross-platform CLI checks. Never invokes Windows firewall commands."""
import json, os, pathlib, shutil, subprocess, tempfile
root = pathlib.Path(__file__).resolve().parent
pwsh = os.environ.get('PWSH') or shutil.which('pwsh')
if not pwsh: raise SystemExit('Set PWSH to a PowerShell 7 executable.')
checks = 0
with tempfile.TemporaryDirectory(prefix='sstp-cli-test-') as d:
    config = pathlib.Path(d) / 'allowlist.json'
    def run(action, address=None, ok=True):
        global checks
        cmd = [pwsh, '-NoLogo', '-NoProfile', '-File', str(root/'SstpAllowlist.ps1'), '-Action', action, '-ConfigPath', str(config)]
        if address is not None: cmd += ['-Address', address]
        out = subprocess.run(cmd, text=True, capture_output=True, timeout=30)
        assert (out.returncode == 0) is ok, (action, out.returncode)
        checks += 1
        if ok:
            assert not out.stderr.strip()
            return json.loads(out.stdout)
    assert run('Init')['domains'] == ['level3.blizzard.com']
    assert run('Add', 'example.com')['domains'] == ['example.com', 'level3.blizzard.com']
    assert run('Remove', 'example.com')['domains'] == ['level3.blizzard.com']
    assert run('List')['ip_addresses'] == []
    run('Add', '*.example.com', ok=False)
    run('Remove', 'level3.blizzard.com', ok=False)
    run('Enable', ok=False)
    run('Disable', ok=False)
    run('List', 'unexpected.example', ok=False)
    assert run('List')['domains'] == ['level3.blizzard.com']
    assert not list(pathlib.Path(d).glob('.sstp-config-*.tmp'))
    receipt = {'schema':'sstp-allowlist-cli-local-1','passed':True,'checks':checks,'platform':'Linux','powershell_version':'7.4.6','live_windows_tested':False,'network_changed':False,'ready_for_user_apply':False}
    (root/'cli-local-test.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt))
