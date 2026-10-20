"""Windows Procmon wrapper. Leaves isolation/firewall/hosts/game settings untouched."""
import base64,ctypes,ctypes.wintypes as W,hashlib,json,os,re,shutil,subprocess,sys,time,urllib.request,uuid,zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))

from cleanup_capture import cleanup
BASE=Path(__file__).resolve().parents[1]
TOOL_SHA='28495e642b2a465474a4edc58380eaf8b7ee580f3fbcb4141061deadafe9b885'
URL='https://download.sysinternals.com/files/ProcessMonitor.zip'
RAW=None
ACTIVE=None
ACTIVE_TOOL=None

def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def integrity():
    m=json.loads((BASE/'MANIFEST-SHA256.json').read_text('utf-8'))
    for n,h in m.items():
        p=Path(n)
        if p.is_absolute() or '..' in p.parts or not (BASE/p).is_file() or sha(BASE/p)!=h:raise RuntimeError('package_integrity_failed')

class ENTRY(ctypes.Structure):
    _fields_=[('dwSize',W.DWORD),('cntUsage',W.DWORD),('th32ProcessID',W.DWORD),('th32DefaultHeapID',ctypes.c_size_t),('th32ModuleID',W.DWORD),('cntThreads',W.DWORD),('th32ParentProcessID',W.DWORD),('pcPriClassBase',W.LONG),('dwFlags',W.DWORD),('szExeFile',W.WCHAR*260)]

def process_names():
    k=ctypes.WinDLL('kernel32',use_last_error=True);k.CreateToolhelp32Snapshot.argtypes=[W.DWORD,W.DWORD];k.CreateToolhelp32Snapshot.restype=W.HANDLE
    k.Process32FirstW.argtypes=[W.HANDLE,ctypes.POINTER(ENTRY)];k.Process32NextW.argtypes=[W.HANDLE,ctypes.POINTER(ENTRY)];k.CloseHandle.argtypes=[W.HANDLE]
    h=k.CreateToolhelp32Snapshot(2,0)
    if h==ctypes.c_void_p(-1).value:raise RuntimeError('process_snapshot_failed')
    e=ENTRY();e.dwSize=ctypes.sizeof(e);out={}
    try:
        ok=k.Process32FirstW(h,ctypes.byref(e))
        while ok:out[int(e.th32ProcessID)]=e.szExeFile.lower();ok=k.Process32NextW(h,ctypes.byref(e))
    finally:k.CloseHandle(h)
    return out

def procmon_pids():return {p for p,n in process_names().items() if n in ('procmon.exe','procmon64.exe','procmon64a.exe')}

def pick(title,pattern):
    class OFN(ctypes.Structure):
        _fields_=[('lStructSize',W.DWORD),('hwndOwner',W.HWND),('hInstance',W.HINSTANCE),('lpstrFilter',W.LPCWSTR),('lpstrCustomFilter',W.LPWSTR),('nMaxCustFilter',W.DWORD),('nFilterIndex',W.DWORD),('lpstrFile',W.LPWSTR),('nMaxFile',W.DWORD),('lpstrFileTitle',W.LPWSTR),('nMaxFileTitle',W.DWORD),('lpstrInitialDir',W.LPCWSTR),('lpstrTitle',W.LPCWSTR),('Flags',W.DWORD),('nFileOffset',W.WORD),('nFileExtension',W.WORD),('lpstrDefExt',W.LPCWSTR),('lCustData',ctypes.c_ssize_t),('lpfnHook',ctypes.c_void_p),('lpTemplateName',W.LPCWSTR),('pvReserved',ctypes.c_void_p),('dwReserved',W.DWORD),('FlagsEx',W.DWORD)]
    buf=ctypes.create_unicode_buffer(32768);o=OFN();o.lStructSize=ctypes.sizeof(o);o.lpstrFilter=pattern;o.nFilterIndex=1;o.lpstrFile=ctypes.cast(buf,W.LPWSTR);o.nMaxFile=len(buf);o.lpstrTitle=title;o.Flags=0x1000|0x80000|0x8
    d=ctypes.WinDLL('comdlg32');d.GetOpenFileNameW.argtypes=[ctypes.POINTER(OFN)]
    if not d.GetOpenFileNameW(ctypes.byref(o)):raise RuntimeError('file_selection_cancelled')
    return Path(buf.value)

def storage_preflight():
    """Resolve volume mount points; refuse system volume even through a mount alias."""
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    k.GetVolumePathNameW.argtypes=[W.LPCWSTR,W.LPWSTR,W.DWORD]
    k.GetVolumeNameForVolumeMountPointW.argtypes=[W.LPCWSTR,W.LPWSTR,W.DWORD]
    k.GetDriveTypeW.argtypes=[W.LPCWSTR]
    k.GetVolumeInformationW.argtypes=[W.LPCWSTR,W.LPWSTR,W.DWORD,ctypes.POINTER(W.DWORD),ctypes.POINTER(W.DWORD),ctypes.POINTER(W.DWORD),W.LPWSTR,W.DWORD]
    def volume(p):
        root=ctypes.create_unicode_buffer(32768);guid=ctypes.create_unicode_buffer(1024)
        if not k.GetVolumePathNameW(str(p),root,len(root)):raise RuntimeError('volume_path_check_failed')
        if not k.GetVolumeNameForVolumeMountPointW(root.value,guid,len(guid)):raise RuntimeError('volume_identity_check_failed')
        return root.value,guid.value.lower()
    package=BASE.resolve();root,guid=volume(package)
    system=Path(os.environ['SystemRoot']).resolve();_,sysguid=volume(system)
    if package.drive.lower()=='c:' or guid==sysguid:raise RuntimeError('extract_package_to_non_C_non_system_drive')
    if k.GetDriveTypeW(root) not in (2,3):raise RuntimeError('local_storage_required')
    fs=ctypes.create_unicode_buffer(64)
    if not k.GetVolumeInformationW(root,None,0,None,None,None,fs,len(fs)) or fs.value!='NTFS':raise RuntimeError('local_NTFS_drive_required')
    if shutil.disk_usage(package).free<3*1024**3:raise RuntimeError('need_3GiB_free_on_capture_drive')
    if shutil.disk_usage(system).free<1024**3:raise RuntimeError('need_1GiB_free_on_windows_drive')

def private_dir():
    # Never LocalAppData / TEMP; keep capture/tool files beside package on checked volume.
    p=BASE/'captures'/uuid.uuid4().hex;p.mkdir(parents=True,exist_ok=False)
    if not p.resolve().is_relative_to(BASE.resolve()):raise RuntimeError('capture_folder_redirect_not_allowed')
    who=subprocess.run([str(Path(os.environ['SystemRoot'])/'System32/whoami.exe'),'/user','/fo','csv','/nh'],capture_output=True,text=True,check=True).stdout
    sid=re.search(r'S-1-5-(?:\d+-)*\d+',who)
    if not sid:raise RuntimeError('user_sid_unavailable')
    r=subprocess.run([str(Path(os.environ['SystemRoot'])/'System32/icacls.exe'),str(p),'/inheritance:r','/grant:r','*'+sid.group()+':(OI)(CI)F','*S-1-5-18:(OI)(CI)F'],capture_output=True)
    if r.returncode:raise RuntimeError('private_acl_failed')
    return p

def stop_owned():
    if ACTIVE is None or ACTIVE.poll() is not None:return True
    if procmon_pids()!={ACTIVE.pid}:return False
    subprocess.run([str(ACTIVE_TOOL),'/Terminate'],timeout=12,capture_output=True)
    try:ACTIVE.wait(timeout=12)
    except subprocess.TimeoutExpired:return False
    return True

def verify_tool(tool):
    if sha(tool)!=TOOL_SHA:raise RuntimeError('procmon_version_hash_mismatch')
    code="""$s=Get-AuthenticodeSignature -LiteralPath $env:WOW_OBSERVER_SIGNED_TOOL; if (($s.Status -eq 'Valid') -and ($s.SignerCertificate.Subject -match '(^|,\\s*)O=Microsoft Corporation(,|$)')) { exit 0 }; exit 3"""
    env=os.environ.copy();env['WOW_OBSERVER_SIGNED_TOOL']=str(tool)
    ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    r=subprocess.run([str(ps),'-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(code.encode('utf-16le')).decode()],env=env,capture_output=True,timeout=60)
    if r.returncode:raise RuntimeError('microsoft_authenticode_verification_failed')

def get_tool(raw):
    print('\nProcmon is NOT bundled. Choose an existing official Procmon64.exe, or download it.')
    print('Windows signature verification may contact trust services, including for a LOCAL tool.')
    choice=input('Type LOCAL or DOWNLOAD (no firewall rule will be opened): ').strip().upper()
    if choice=='LOCAL':tool=pick('Choose official Microsoft Procmon64.exe','Procmon64.exe\0Procmon64.exe\0\0');verify_tool(tool);return tool
    if choice!='DOWNLOAD':raise RuntimeError('download_not_authorized')
    print('Downloading only from the official Microsoft Sysinternals URL. Signature checks may contact Windows trust services.')
    z=raw/'official-ProcessMonitor.zip';size=0
    with urllib.request.urlopen(URL,timeout=45) as r,open(z,'xb') as f:
        if not r.geturl().startswith('https://download.sysinternals.com/'):raise RuntimeError('unexpected_download_redirect')
        while True:
            b=r.read(256*1024)
            if not b:break
            size+=len(b)
            if size>16*1024*1024:raise RuntimeError('download_size_limit')
            f.write(b)
    with zipfile.ZipFile(z) as bundle:
        for n,limit in [('Procmon64.exe',8*1024*1024),('Eula.txt',128*1024)]:
            info=bundle.getinfo(n)
            if info.file_size>limit:raise RuntimeError('tool_archive_limit')
            (raw/n).write_bytes(bundle.read(n))
    tool=raw/'Procmon64.exe';verify_tool(tool);return tool

def save(report):
    p=BASE/'output';p.mkdir(exist_ok=True)
    out=p/('dependency-result-'+uuid.uuid4().hex+'.json')
    with open(out,'x',encoding='utf-8') as f:json.dump(report,f,ensure_ascii=False,indent=2)
    print('\nSEND ONLY:',out.name,'(inside output). Never send PML or the private captures folder.')
    return out

def finish(report):
    # Always create the report BEFORE deleting any raw data. Save failure preserves PML.
    report['raw_cleanup']={'status':'pending_after_report_save'}
    out=save(report)
    try:present=bool(procmon_pids())
    except Exception:present=True
    try:report['raw_cleanup']=cleanup(RAW,BASE,present)
    except Exception:report['raw_cleanup']={'status':'cleanup_failed_raw_may_remain'}
    # Atomic update; the initial report survives if replacement fails.
    temp=out.with_suffix('.json.tmp')
    try:
        with open(temp,'x',encoding='utf-8') as f:
            json.dump(report,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
        os.replace(temp,out)
    except Exception:
        print('Cleanup result could not be appended to JSON; initial report remains.')
    print('Raw PML cleanup:',report['raw_cleanup']['status'])

def main():
    global RAW,ACTIVE,ACTIVE_TOOL
    if os.name!='nt' or ctypes.sizeof(ctypes.c_void_p)!=8:raise RuntimeError('windows_x64_required')
    storage_preflight()
    integrity()
    if not ctypes.windll.shell32.IsUserAnAdmin():raise RuntimeError('run_Start_cmd_as_administrator')
    k=ctypes.WinDLL('kernel32',use_last_error=True);k.CreateMutexW.argtypes=[ctypes.c_void_p,W.BOOL,W.LPCWSTR];k.CreateMutexW.restype=W.HANDLE
    mutex=k.CreateMutexW(None,False,'Local\\WoWDependencyObserver_021')
    if not mutex or ctypes.get_last_error()==183:raise RuntimeError('another_observer_running')
    report={'schema':'wow-dependency-observer-1','version':'0.2.1','firewall_whitelist_hosts_vpn_game_settings_modified':False,
            'game_debugger_attach_or_injection_used':False,'procmon_kernel_driver_used':True,
            'raw_logs_paths_command_lines_or_environment_exported':False,'tls_contents_decoded':False,
            'native_windows_full_integration_tested_by_developer':False}
    try:
        print('WoW Dependency Observer 0.2.1 — SHORT CAPTURE / DIRECT PML / NO XML')
        print('Keep isolation unchanged. Close all Procmon windows. Leave WoW normally running at its login screen; do not enter credentials.')
        if procmon_pids():raise RuntimeError('existing_procmon_do_not_touch')
        selected=pick('Choose the Wow.exe that is already running normally','World of Warcraft\0Wow.exe\0\0')
        if selected.name.lower()!='wow.exe':raise RuntimeError('select_Wow_exe')
        report['selected_exe_sha256']=sha(selected)
        print('Label this run: 1=current isolation; 2=no isolation; 3=one destination removed.')
        labels={'1':'current_isolation','2':'no_isolation','3':'one_destination_removed'}
        report['isolation_state_user_reported']=labels.get(input('Enter 1, 2 or 3: ').strip(),'unspecified')
        report['isolation_effectiveness_verified']=False
        RAW=private_dir();tool=get_tool(RAW)
        report['procmon64_sha256']=TOOL_SHA;report['microsoft_signature_verified_before_launch']=True
        print('\nSYSTEM-WIDE metadata capture: 20 seconds, checked 1 GiB soft budget, direct PML reading only.')
        print('No XML, debugger, injection, new certificate, firewall/hosts/VPN change or game launch.')
        print('Data stays in this package captures folder, NOT LocalAppData. PML contains private system-wide metadata.')
        print('Procmon loads a Microsoft kernel driver; EULA/preferences may persist. OS/driver files can still use the Windows drive.')
        print('EULA: https://learn.microsoft.com/en-us/sysinternals/license-terms')
        print('Before CAPTURE, open WoW normally to its login screen. No account login needed. Keep it normally running during capture.')
        print('This short sample will NOT include all startup activity or prove absence of telemetry.')
        print('After a JSON report is saved, own raw PML files are deleted, even if analysis failed. No automatic retry.')
        if input('Type CAPTURE to consent to recording and Procmon /AcceptEula: ').strip()!='CAPTURE':raise RuntimeError('capture_not_authorized')
        if procmon_pids():raise RuntimeError('existing_procmon_do_not_touch')
        if 'wow.exe' not in process_names().values():raise RuntimeError('open_WoW_normally_to_login_first')
        storage_preflight()
        pml=RAW/'capture.pml';started=time.monotonic()
        ACTIVE_TOOL=tool
        ACTIVE=subprocess.Popen([str(tool),'/AcceptEula','/Quiet','/Minimized','/NoFilter','/BackingFile',str(pml),'/Runtime','20'])
        proc=ACTIVE
        report.update(capture_start_requested=True,native_runtime_limit_seconds=20,
                      capture_storage='package_captures_folder_non_system_volume',
                      xml_export_used=False,soft_raw_budget_bytes=1024**3,hard_disk_cap_guaranteed=False)
        time.sleep(0.5)
        if proc.poll() is not None:raise RuntimeError('procmon_exited_before_ready')
        ready=subprocess.run([str(tool),'/WaitForIdle'],timeout=12,capture_output=True)
        if ready.returncode or proc.poll() is not None:raise RuntimeError('procmon_readiness_not_confirmed')
        print('CAPTURE READY — leave WoW normally running. Stop automatically after 20 seconds.')
        report['capture_ready_observed']=True;reason=None
        while proc.poll() is None:
            size=sum(p.stat().st_size for p in RAW.glob('capture*.pml') if p.is_file())
            if size>=1024**3:reason='raw_soft_budget'
            elif shutil.disk_usage(RAW).free<1024**3:reason='capture_drive_reserve'
            elif shutil.disk_usage(Path(os.environ['SystemRoot'])).free<1024**3:reason='system_drive_reserve'
            elif time.monotonic()-started>=30:reason='watchdog_30_seconds'
            if reason:
                if not stop_owned():raise RuntimeError('cannot_confirm_owned_stop_close_Procmon_manually')
                break
            time.sleep(0.25)
        report['capture_procmon_exit_code']=proc.poll()
        report['early_stop_reason']=reason
        report['capture_elapsed_seconds']=round(time.monotonic()-started,1)
        report['capture_completion_verified']=proc.returncode==0 and reason is None
        if procmon_pids():raise RuntimeError('Procmon_still_present_no_analysis')
        if not pml.is_file() or pml.stat().st_size<1024:raise RuntimeError('capture_pml_missing_or_empty')
        one=(pml.stat().st_size,pml.stat().st_mtime_ns);time.sleep(1)
        if one!=(pml.stat().st_size,pml.stat().st_mtime_ns):raise RuntimeError('pml_still_changing')
        if any(p.name.lower()!='capture.pml' for p in RAW.glob('capture*.pml')):raise RuntimeError('split_pml_not_supported')
        print('Recording ended. Reading PML locally, without XML or network lookups. Analysis timeout: 120 seconds.')
        meta=RAW/'analysis-local.json'
        child=subprocess.run([sys.executable,'-I',str(BASE/'app/read_trace.py'),str(pml),str(selected),str(meta)],timeout=120,capture_output=True)
        if not meta.is_file() or meta.stat().st_size>8*1024**2:raise RuntimeError('analysis_output_invalid')
        report['analysis']=json.loads(meta.read_text('utf-8'))
        if child.returncode:report['status']='analysis_inconclusive'
        elif not report['capture_completion_verified']:report['status']='capture_incomplete_with_metadata'
        else:report['status']=report['analysis']['status']
        report['limits']=['20-second system-wide sample; start-up events before recording may be missed. Capture-category completeness is not certified.',
            '1 GiB is a polled SOFT budget, not a hard size cap. OS/Procmon failure can exceed it.',
            'Only PML v9 is supported. Unknown/incomplete format is inconclusive, never converted to XML.',
            'No TLS plaintext, DLL causality, complete domain map, or proof of CPU/BIOS transmission.',
            'Own raw PML is deleted after report save, including on analysis failure, only when all Procmon processes are confirmed closed. Locked/unsafe files may remain.',
            'Procmon EULA/preferences/driver or Windows activity can still use the system drive. No claim of zero C-drive writes.',
            'No native Windows end-to-end validation by developer.']
        finish(report)
    except (Exception,KeyboardInterrupt) as e:
        report['status']='capture_or_analysis_incomplete';report['error_kind']=type(e).__name__
        try:report['owned_capture_stopped']=stop_owned()
        except Exception:report['owned_capture_stopped']=False
        # Only fixed safe codes, never exception strings containing paths/private text.
        msg=str(e);report['error_code']=msg if re.fullmatch(r'[A-Za-z0-9_]{1,110}',msg) else 'operation_failed'
        print('\nStopped:',report['error_code'])
        print('If Procmon is still running, open its window, stop Capture and exit Procmon. Do not close the game by force.')
        finish(report)
    finally:
        try:stop_owned()
        except Exception:pass
        k.CloseHandle.argtypes=[W.HANDLE];k.CloseHandle(mutex)

if __name__=='__main__':
    try:main()
    except Exception as e:
        code=str(e);print('Preflight stopped:',code if re.fullmatch(r'[A-Za-z0-9_]{1,110}',code) else type(e).__name__)
