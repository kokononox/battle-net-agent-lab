"""Windows Procmon wrapper. Leaves isolation/firewall/hosts/game settings untouched."""
import base64,ctypes,ctypes.wintypes as W,hashlib,json,os,re,shutil,subprocess,sys,time,urllib.request,uuid,zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from analyze import analyze
BASE=Path(__file__).resolve().parents[1]
TOOL_SHA='28495e642b2a465474a4edc58380eaf8b7ee580f3fbcb4141061deadafe9b885'
URL='https://download.sysinternals.com/files/ProcessMonitor.zip'
RAW=None

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

def private_dir():
    p=Path(os.environ['LOCALAPPDATA'])/'WoWDependencyObserver'/uuid.uuid4().hex;p.mkdir(parents=True,exist_ok=False)
    who=subprocess.run([str(Path(os.environ['SystemRoot'])/'System32/whoami.exe'),'/user','/fo','csv','/nh'],capture_output=True,text=True,check=True).stdout
    sid=re.search(r'S-1-5-(?:\d+-)*\d+',who)
    if not sid:raise RuntimeError('user_sid_unavailable')
    r=subprocess.run([str(Path(os.environ['SystemRoot'])/'System32/icacls.exe'),str(p),'/inheritance:r','/grant:r','*'+sid.group()+':(OI)(CI)F','*S-1-5-18:(OI)(CI)F'],capture_output=True)
    if r.returncode:raise RuntimeError('private_acl_failed')
    return p

def verify_tool(tool):
    if sha(tool)!=TOOL_SHA:raise RuntimeError('procmon_version_hash_mismatch')
    code="""$s=Get-AuthenticodeSignature -LiteralPath $env:WOW_OBSERVER_SIGNED_TOOL; if (($s.Status -eq 'Valid') -and ($s.SignerCertificate.Subject -match '(^|,\\s*)O=Microsoft Corporation(,|$)')) { exit 0 }; exit 3"""
    env=os.environ.copy();env['WOW_OBSERVER_SIGNED_TOOL']=str(tool)
    ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    r=subprocess.run([str(ps),'-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(code.encode('utf-16le')).decode()],env=env,capture_output=True,timeout=60)
    if r.returncode:raise RuntimeError('microsoft_authenticode_verification_failed')

def get_tool(raw):
    print('\nProcmon is NOT bundled. Choose an existing official Procmon64.exe, or download it.')
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
    print('\nSEND ONLY:',out.name,'(inside output). Never send PML, XML or the private session folder.')
    return out

def main():
    global RAW
    if os.name!='nt' or ctypes.sizeof(ctypes.c_void_p)!=8:raise RuntimeError('windows_x64_required')
    integrity()
    if not ctypes.windll.shell32.IsUserAnAdmin():raise RuntimeError('run_Start_cmd_as_administrator')
    k=ctypes.WinDLL('kernel32',use_last_error=True);k.CreateMutexW.argtypes=[ctypes.c_void_p,W.BOOL,W.LPCWSTR];k.CreateMutexW.restype=W.HANDLE
    mutex=k.CreateMutexW(None,False,'Local\\WoWDependencyObserver_010')
    if not mutex or ctypes.get_last_error()==183:raise RuntimeError('another_observer_running')
    report={'schema':'wow-dependency-observer-1','version':'0.1.0','firewall_whitelist_hosts_vpn_game_settings_modified':False,
            'game_debugger_attach_or_injection_used':False,'procmon_kernel_driver_used':True,
            'raw_logs_paths_command_lines_or_environment_exported':False,'tls_contents_decoded':False,
            'native_windows_full_integration_tested_by_developer':False}
    try:
        print('WoW Dependency Observer 0.1.0 — NO CDB / NO INJECTION')
        print('Keep your existing isolation unchanged. Close WoW and all Procmon windows before continuing.')
        if procmon_pids():raise RuntimeError('existing_procmon_do_not_touch')
        if 'wow.exe' in process_names().values():raise RuntimeError('close_game_normally_first')
        selected=pick('Choose Wow.exe (do not launch it yet)','World of Warcraft\0Wow.exe\0\0')
        if selected.name.lower()!='wow.exe':raise RuntimeError('select_Wow_exe')
        report['selected_exe_sha256']=sha(selected)
        print('Label this run: 1=current isolation; 2=no isolation; 3=one destination removed.')
        labels={'1':'current_isolation','2':'no_isolation','3':'one_destination_removed'}
        report['isolation_state_user_reported']=labels.get(input('Enter 1, 2 or 3: ').strip(),'unspecified')
        report['isolation_effectiveness_verified']=False
        RAW=private_dir();tool=get_tool(RAW)
        report['procmon64_sha256']=TOOL_SHA;report['microsoft_signature_verified_before_launch']=True
        print('\nCapture is SYSTEM-WIDE for up to 60 seconds. Procmon loads a Microsoft kernel driver; no game injection.')
        print('Raw PML/XML may contain private paths, process command lines, environment and registry data.')
        print('Procmon EULA: https://learn.microsoft.com/en-us/sysinternals/license-terms')
        print('By typing CAPTURE you consent to this local recording and Procmon /AcceptEula. Tool preferences/EULA may persist.')
        print('No login needed. Open the game normally ONLY after CAPTURE READY; reach login, then close it normally.')
        if input('Type CAPTURE to continue: ').strip()!='CAPTURE':raise RuntimeError('capture_not_authorized')
        if procmon_pids():raise RuntimeError('existing_procmon_do_not_touch')
        if 'wow.exe' in process_names().values():raise RuntimeError('close_game_normally_first')
        if shutil.disk_usage(RAW).free<3*1024**3:raise RuntimeError('need_3GiB_free_for_private_trace')
        pml=RAW/'capture.pml';xml=RAW/'capture-local.xml';started=time.monotonic()
        proc=subprocess.Popen([str(tool),'/AcceptEula','/Quiet','/Minimized','/NoFilter','/BackingFile',str(pml),'/Runtime','60'])
        report['capture_start_requested']=True;report['native_runtime_limit_seconds']=60
        time.sleep(1)
        if proc.poll() is not None:raise RuntimeError('procmon_exited_before_ready')
        ready=subprocess.run([str(tool),'/WaitForIdle'],timeout=20,capture_output=True)
        if ready.returncode or proc.poll() is not None:raise RuntimeError('procmon_readiness_not_confirmed')
        print('\nCAPTURE READY — now open WoW normally. No account login. Keep existing blocks unchanged.\n')
        report['capture_ready_observed']=True;soft_stop=False
        while proc.poll() is None and time.monotonic()-started<85:
            time.sleep(1)
            # This is a checked soft budget, not a hard disk-size guarantee.
            size=sum(p.stat().st_size for p in RAW.glob('capture*.pml') if p.is_file())
            if size>512*1024*1024 and not soft_stop:
                ids=procmon_pids()
                if ids=={proc.pid}:
                    subprocess.run([str(tool),'/Terminate'],timeout=15,capture_output=True)
                    soft_stop=True;print('Soft raw-file budget exceeded; own Procmon stop requested.')
                else:raise RuntimeError('raw_budget_ownership_uncertain_manual_procmon_stop_needed')
        if proc.poll() is None:raise RuntimeError('procmon_runtime_not_finished_manual_stop_needed')
        report['capture_procmon_exit_code']=proc.returncode;report['soft_budget_stop_requested']=soft_stop
        report['capture_elapsed_seconds']=round(time.monotonic()-started,1)
        if not pml.exists() or pml.stat().st_size<1024:raise RuntimeError('capture_pml_missing_or_empty')
        if procmon_pids():raise RuntimeError('other_procmon_present_before_export')
        print('Recording ended. Exporting LOCAL XML with stack metadata; this can take a few minutes.')
        conv=subprocess.run([str(tool),'/AcceptEula','/Quiet','/NoConnect','/OpenLog',str(pml),'/SaveAs1',str(xml)],timeout=240)
        report['xml_export_exit_code']=conv.returncode
        if conv.returncode or not xml.is_file():raise RuntimeError('local_xml_export_failed')
        print('Analyzing metadata locally. No raw event text will be sent.')
        report['analysis']=analyze(xml,str(selected));report['status']=report['analysis']['status']
        report['limits']=['Procmon records system-wide metadata; only selected executable path + process-index descendants enter this JSON.',
          'No capture-category or stack-collection completeness guarantee. No DLL causality or CPU/BIOS upload proof.',
          'Procmon may persist its own UI/filter/EULA settings. Its driver may have application compatibility/performance effects.',
          'Runtime and file budget are bounded requests, not a guarantee after OS/tool failure. Do not start another Procmon during this test.',
          'The wrapper never weakens isolation or disables protections. Signature/download access may fail under isolation; failure stops the run.',
          'PML and XML stay in the private LocalAppData session folder; delete it after all Procmon processes exit if not needed.']
        save(report)
    except Exception as e:
        report['status']='capture_or_analysis_incomplete';report['error_kind']=type(e).__name__
        # Only fixed safe codes, never exception strings containing paths/private text.
        msg=str(e);report['error_code']=msg if re.fullmatch(r'[A-Za-z0-9_]{1,110}',msg) else 'operation_failed'
        print('\nStopped:',report['error_code'])
        print('If Procmon is still running, open its window, stop Capture and exit Procmon. Do not close the game by force.')
        save(report)
    finally:
        # No automatic process kill or unidentified global Procmon termination here.
        k.CloseHandle.argtypes=[W.HANDLE];k.CloseHandle(mutex)

if __name__=='__main__':
    try:main()
    except Exception as e:
        code=str(e);print('Preflight stopped:',code if re.fullmatch(r'[A-Za-z0-9_]{1,110}',code) else type(e).__name__)
