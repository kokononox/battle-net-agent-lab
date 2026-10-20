"""Delete only capture PML files from this tool's own session, after report save."""
import re
from pathlib import Path

def cleanup(raw, base, procmon_present):
    result={'policy':'delete_own_raw_PML_after_report_saved_including_error_reports',
            'deleted_files':0,'deleted_bytes':0,'status':'not_applicable'}
    if raw is None:return result
    if procmon_present:
        result['status']='retained_Procmon_not_confirmed_closed';return result
    raw=Path(raw);base=Path(base)
    def redirect(p):return p.is_symlink() or getattr(p,'is_junction',lambda:False)()
    parent=base/'captures'
    if (redirect(parent) or redirect(raw) or raw.parent.resolve()!=parent.resolve()
        or not re.fullmatch(r'[a-f0-9]{32}',raw.name)
        or not raw.resolve().is_relative_to(base.resolve())):
        result['status']='retained_session_path_not_trusted';return result
    try:
        for p in raw.iterdir():
            if not re.fullmatch(r'capture(?:[-_]?\d+)?\.pml',p.name,re.I):continue
            if redirect(p) or not p.is_file():
                result['status']='some_files_retained';continue
            n=p.stat().st_size
            try:p.unlink()
            except OSError:
                result['status']='some_files_retained';continue
            result['deleted_files']+=1;result['deleted_bytes']+=n
        if result['status']!='some_files_retained':result['status']='completed'
    except OSError:result['status']='some_files_retained'
    return result
