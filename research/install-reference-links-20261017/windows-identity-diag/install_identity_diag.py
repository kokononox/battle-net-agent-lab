"""Diagnostic ONLY: one adjacent bundled Install metadata file; no Lab/game reads."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

SIZE = 24078
MD5 = 'd7c8cd9845e2b5d39821678f481324da'
SHA256 = '1e9a735e4ec5ffe7fc10b9f39e347cf6f9745a89d15ba700a3982399644d92a6'
FIELDS = ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink')

class DiagnosticError(ValueError):
    pass

def network_block(event, args):
    if event.startswith('socket.'):
        raise DiagnosticError('network_forbidden')

def safe(path):
    p = Path(os.path.abspath(str(path)))
    for item in reversed((p,)+tuple(p.parents)):
        s = item.lstat()
        if stat.S_ISLNK(s.st_mode) or getattr(s,'st_file_attributes',0) & 0x400:
            raise DiagnosticError('link_or_reparse_point')
        if item != p and not stat.S_ISDIR(s.st_mode):
            raise DiagnosticError('non_directory_ancestor')
    s = p.stat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
        raise DiagnosticError('regular_unshared_input_required')
    if s.st_size != SIZE:
        raise DiagnosticError('bundled_install_size')
    return p

def differences(a,b):
    return [name for name in FIELDS if getattr(a,name) != getattr(b,name)]

def diagnose(path):
    p = safe(path)
    pb = p.stat()
    with p.open('rb') as f:
        fb = os.fstat(f.fileno())
        pd = p.stat()
        # Even with a path/handle disagreement, independently bound the handle read.
        if not stat.S_ISREG(fb.st_mode) or fb.st_nlink != 1 or fb.st_size != SIZE:
            raise DiagnosticError('opened_install_shape')
        raw = f.read(SIZE)  # Exactly one bounded read. No size+1 probe.
        fa = os.fstat(f.fileno())
        pa = p.stat()
    pc = safe(p).stat()
    comparisons = {
        'path_before_vs_handle_before': differences(pb,fb),
        'path_before_vs_path_while_open': differences(pb,pd),
        'handle_before_vs_handle_after': differences(fb,fa),
        'path_before_vs_path_after_read': differences(pb,pa),
        'path_before_vs_path_after_close': differences(pb,pc),
        'path_after_read_vs_handle_after': differences(pa,fa),
    }
    matched = (len(raw)==SIZE and hashlib.md5(raw).hexdigest()==MD5
               and hashlib.sha256(raw).hexdigest()==SHA256)
    stable = not any(comparisons[k] for k in (
        'path_before_vs_path_while_open','handle_before_vs_handle_after',
        'path_before_vs_path_after_read','path_before_vs_path_after_close'))
    return dict(status='bundled_install_stat_diagnostic_only',
        version='install-identity-diag-1',platform=sys.platform,
        python_version=list(sys.version_info[:3]),
        bundled_install_bytes_read=len(raw),bundled_install_hashes_match=matched,
        each_observation_channel_stable=stable,different_fields=comparisons,
        network_requests=0,lab_bytes_read=0,game_bytes_read=0,archive_bytes_read=0,
        files_written=0,installation_ready=False,apply_authorized=False,
        original_identity_guard_bypassed_for_updater=False,
        note='Diagnostic observations only; no Encoding review or continuation.')

def main():
    sys.addaudithook(network_block)
    print('Diagnostic ONLY: install-identity-diag-1',flush=True)
    print('Adjacent bundled Install metadata ONLY, <=24,078 bytes. ZERO Lab/game/network/writes.',flush=True)
    try:
        result=diagnose(Path(__file__).absolute().parent/'target-install.metadata')
        print(json.dumps(result,indent=2))
        return 0
    except Exception as e:
        result=dict(status='stopped_safely',version='install-identity-diag-1',
                    error_type=type(e).__name__,installation_ready=False,apply_authorized=False)
        if isinstance(e,DiagnosticError):result['code']=str(e)
        if isinstance(e,OSError):
            for name in ('errno','winerror'):
                if type(getattr(e,name,None)) is int:result[name]=getattr(e,name)
        print(json.dumps(result,indent=2))
        return 1

if __name__=='__main__':
    raise SystemExit(main())
