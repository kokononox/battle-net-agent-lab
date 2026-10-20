"""Attach-free TCP destination observer for one file selected by the user.
No injection, packet payload capture, DNS requests, or policy/process setters.
"""
import ctypes
from ctypes import wintypes as w
import datetime
import hashlib
import json
import ntpath
import os
from pathlib import Path
import sys
import time
from safepaths import safe_path

BASE = Path(__file__).resolve().parents[1]
MAX_PROCESSES = 128
MAX_FLOWS = 4096
WAIT_SECONDS = 180
OBSERVE_SECONDS = 120


def path_key(path):
    return ntpath.normcase(ntpath.normpath(str(path)))


def file_hash(path):
    p = safe_path(path)
    if p.suffix.lower() != '.exe' or not p.is_file() or not 0 < p.stat().st_size <= 512*1024**2:
        raise ValueError('select_local_exe_under_512_mib')
    with p.open('rb') as f:
        if f.read(2) != b'MZ':
            raise ValueError('selected_file_not_pe_executable')
        f.seek(0)
        h = hashlib.file_digest(f, 'sha256').hexdigest()
    return h


def choose_exe():
    # Native Windows file browser; no tkinter/install/browser/network needed.
    class OPENFILENAMEW(ctypes.Structure):
        _fields_ = [('lStructSize',w.DWORD),('hwndOwner',w.HWND),('hInstance',w.HINSTANCE),
            ('lpstrFilter',w.LPCWSTR),('lpstrCustomFilter',w.LPWSTR),('nMaxCustFilter',w.DWORD),
            ('nFilterIndex',w.DWORD),('lpstrFile',w.LPWSTR),('nMaxFile',w.DWORD),
            ('lpstrFileTitle',w.LPWSTR),('nMaxFileTitle',w.DWORD),('lpstrInitialDir',w.LPCWSTR),
            ('lpstrTitle',w.LPCWSTR),('Flags',w.DWORD),('nFileOffset',w.WORD),
            ('nFileExtension',w.WORD),('lpstrDefExt',w.LPCWSTR),('lCustData',ctypes.c_ssize_t),
            ('lpfnHook',ctypes.c_void_p),('lpTemplateName',w.LPCWSTR),('pvReserved',ctypes.c_void_p),
            ('dwReserved',w.DWORD),('FlagsEx',w.DWORD)]
    if ctypes.sizeof(OPENFILENAMEW) != 152:
        raise ValueError('unexpected_file_dialog_structure')
    dialog = ctypes.WinDLL('comdlg32', use_last_error=True)
    dialog.GetOpenFileNameW.argtypes = [ctypes.POINTER(OPENFILENAMEW)]
    dialog.GetOpenFileNameW.restype = w.BOOL
    dialog.CommDlgExtendedError.argtypes = []
    dialog.CommDlgExtendedError.restype = w.DWORD
    buf = ctypes.create_unicode_buffer(32768)
    ofn = OPENFILENAMEW()
    ofn.lStructSize = ctypes.sizeof(ofn)
    ofn.lpstrFilter = 'Executable files (*.exe)\0*.exe\0\0'
    ofn.lpstrFile = ctypes.cast(buf, w.LPWSTR)
    ofn.nMaxFile = len(buf)
    ofn.lpstrTitle = 'Select game or launcher EXE - it will NOT be launched'
    # Existing file/path; no CWD mutation; Explorer dialog; do not dereference shortcuts.
    ofn.Flags = 0x1000 | 0x800 | 0x8 | 0x80000 | 0x100000
    ofn.lpstrDefExt = 'exe'
    if not dialog.GetOpenFileNameW(ctypes.byref(ofn)):
        if dialog.CommDlgExtendedError():
            raise ValueError('file_dialog_failed')
        return None
    return safe_path(buf.value)


def process_rows():
    # Process metadata only. Command lines, environment, modules and payloads NOT read.
    class ENTRY(ctypes.Structure):
        _fields_=[('dwSize',w.DWORD),('cntUsage',w.DWORD),('th32ProcessID',w.DWORD),
            ('th32DefaultHeapID',ctypes.c_size_t),('th32ModuleID',w.DWORD),('cntThreads',w.DWORD),
            ('th32ParentProcessID',w.DWORD),('pcPriClassBase',w.LONG),('dwFlags',w.DWORD),('szExeFile',w.WCHAR*260)]
    if ctypes.sizeof(ENTRY) != 568:
        raise ValueError('unexpected_process_structure')
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    k.CreateToolhelp32Snapshot.argtypes=[w.DWORD,w.DWORD];k.CreateToolhelp32Snapshot.restype=w.HANDLE
    k.Process32FirstW.argtypes=[w.HANDLE,ctypes.POINTER(ENTRY)];k.Process32FirstW.restype=w.BOOL
    k.Process32NextW.argtypes=[w.HANDLE,ctypes.POINTER(ENTRY)];k.Process32NextW.restype=w.BOOL
    k.CloseHandle.argtypes=[w.HANDLE];k.CloseHandle.restype=w.BOOL
    h=k.CreateToolhelp32Snapshot(2,0)
    if h==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
    rows=[]
    try:
        row=ENTRY();row.dwSize=ctypes.sizeof(row)
        good=k.Process32FirstW(h,ctypes.byref(row))
        if not good:raise ctypes.WinError(ctypes.get_last_error())
        while good:
            rows.append({'pid':int(row.th32ProcessID),'parent_pid':int(row.th32ParentProcessID),'name':row.szExeFile.lower()})
            good=k.Process32NextW(h,ctypes.byref(row))
        if ctypes.get_last_error() not in (0,18):raise ctypes.WinError(ctypes.get_last_error())
    finally:k.CloseHandle(h)
    return rows


def process_identity(pid):
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];k.OpenProcess.restype=w.HANDLE
    k.CloseHandle.argtypes=[w.HANDLE];k.CloseHandle.restype=w.BOOL
    k.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,ctypes.POINTER(w.DWORD)]
    k.QueryFullProcessImageNameW.restype=w.BOOL
    class FT(ctypes.Structure):_fields_=[('low',w.DWORD),('high',w.DWORD)]
    k.GetProcessTimes.argtypes=[w.HANDLE,*([ctypes.POINTER(FT)]*4)];k.GetProcessTimes.restype=w.BOOL
    h=k.OpenProcess(0x1000,False,pid)
    if not h:raise ctypes.WinError(ctypes.get_last_error())
    try:
        buf=ctypes.create_unicode_buffer(32768);n=w.DWORD(len(buf))
        if not k.QueryFullProcessImageNameW(h,0,buf,ctypes.byref(n)):raise ctypes.WinError(ctypes.get_last_error())
        c,e,kt,ut=FT(),FT(),FT(),FT()
        if not k.GetProcessTimes(h,ctypes.byref(c),ctypes.byref(e),ctypes.byref(kt),ctypes.byref(ut)):raise ctypes.WinError(ctypes.get_last_error())
        return {'path':buf.value,'creation':(c.high<<32)|c.low}
    finally:k.CloseHandle(h)


class Tracker:
    def __init__(self,path,sha,identity_fn=process_identity,hash_fn=file_hash):
        self.path=path_key(path);self.sha=sha;self.identity=identity_fn;self.hash=hash_fn
        self.tracked={};self.flows={};self.limited=False;self.identity_errors=0;self.started=False

    def discover(self,rows):
        live={}
        # Identity cache is valid only during this sample; never bind by PID alone.
        candidates={r['pid']:r for r in rows}
        cache={}
        def info(pid):
            if pid not in cache:
                try:cache[pid]=self.identity(pid)
                except OSError:self.identity_errors+=1;cache[pid]=None
            return cache[pid]
        for pid,r in candidates.items():
            token_rows=[(t,d) for t,d in self.tracked.items() if t[0]==pid]
            if not token_rows and r['name']!=ntpath.basename(self.path):continue
            i=info(pid)
            if not i:continue
            token=(pid,i['creation']);old=self.tracked.get(token)
            if old and old['path']==path_key(i['path']):live[pid]=(token,old);continue
            if path_key(i['path'])==self.path:
                if self.hash(i['path'])!=self.sha:raise ValueError('selected_exe_changed')
                if len(self.tracked)>=MAX_PROCESSES:self.limited=True;continue
                d={'index':len(self.tracked)+1,'pid':pid,'name':r['name'],'path':self.path,
                   'role':'selected_exe','parent_index':None}
                self.tracked[token]=d;live[pid]=(token,d);self.started=True
        # Descendant ancestry accepted only with live, identity-verified parent in this sample.
        for _ in range(MAX_PROCESSES):
            added=False
            for pid,r in candidates.items():
                if pid in live or r['parent_pid'] not in live:continue
                parent_token,parent=live[r['parent_pid']];i=info(pid)
                if not i or i['creation']<parent_token[1]:continue
                token=(pid,i['creation'])
                if len(self.tracked)>=MAX_PROCESSES:self.limited=True;continue
                d={'index':len(self.tracked)+1,'pid':pid,'name':r['name'],'path':path_key(i['path']),
                   'role':'observed_descendant','parent_index':parent['index']}
                self.tracked[token]=d;live[pid]=(token,d);added=True
            if not added:break
        return live

    def add_connections(self,live,connections,elapsed):
        for c in connections:
            pid=c['OwningProcess']
            if pid not in live or not c['RemotePort']:continue
            token,d=live[pid]
            try:i=self.identity(pid)
            except OSError:self.identity_errors+=1;continue
            if (pid,i['creation'])!=token or path_key(i['path'])!=d['path']:continue
            import ipaddress
            ip=ipaddress.ip_address(c['RemoteAddress'])
            if ip.is_unspecified:continue
            key=(d['index'],str(ip),c['RemotePort'])
            if key not in self.flows:
                if len(self.flows)>=MAX_FLOWS:self.limited=True;continue
                self.flows[key]={'process_index':d['index'],'remote_address':str(ip),
                    'remote_port':c['RemotePort'],'is_public_ip':ip.is_global,'is_loopback':ip.is_loopback,
                    'first_seen_seconds':round(elapsed,2),'last_seen_seconds':round(elapsed,2),
                    'sample_observations':0,'tcp_states':[]}
            f=self.flows[key];f['last_seen_seconds']=round(elapsed,2);f['sample_observations']+=1
            state=c['State']
            if state not in f['tcp_states']:f['tcp_states'].append(state)

    def report(self):
        # Do not export absolute file paths (may contain usernames).
        return {'processes':[{k:v for k,v in d.items() if k!='path'} for d in self.tracked.values()],
            'tcp_destinations':list(self.flows.values()),'identity_read_errors':self.identity_errors,
            'limits_hit':self.limited}


def save(report):
    out=safe_path(BASE/'output');out.mkdir(exist_ok=True)
    raw=(json.dumps(report,ensure_ascii=True,indent=2)+'\n').encode()
    if len(raw)>4*1024**2:raise ValueError('report_size_limit')
    path=safe_path(out/('launcher-destinations-'+str(time.time_ns())+'.json'))
    with path.open('xb') as f:f.write(raw)
    print('\nREPORT:',str(path))
    print('Send this JSON only. No automatic upload occurred.')


def main():
    report={'schema':'launcher-destinations-1','version':'0.1.5','status':'preflight',
        'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'error_code':None,
        'selected_exe_name':None,'selected_exe_sha256':None,'observation':None,'sampler_errors':0,
        'limits':{'tcp_sampling_only':True,'udp_quic_covered':False,'payloads_or_tls_decrypted':False,
        'domains_proven_from_ip':False,'early_or_short_lived_connections_may_be_missed':True,
        'preexisting_or_unobserved_helpers_covered':False,'descendant_tracking_best_effort':True,
        'no_zero_telemetry_or_only_download_verdict':True,'no_network_policy_changes':True,
        'no_online_dns_requests':True,'no_process_launch_termination_or_injection':True,
        'no_automatic_update_pause':True,'native_windows_qualification_completed_by_builder':False}}
    tracker=None;lock=None
    try:
        if sys.platform!='win32' or ctypes.sizeof(ctypes.c_void_p)!=8:raise ValueError('windows_x64_required')
        if not ctypes.windll.shell32.IsUserAnAdmin():raise ValueError('run_start_launcher_as_administrator')
        from passive_boot import integrity,mutex
        integrity();lock=mutex()
        print('Game/launcher destination observer 0.1.5 - TCP metadata only, NOT content inspection.')
        print('Close the selected application first. Existing firewall/VPN restrictions remain unchanged.')
        print('Choose the game or launcher EXE in the file browser. It will NOT be executed by this tool.')
        path=choose_exe()
        if path is None:report['status']='cancelled';return
        sha=file_hash(path);report['selected_exe_name']=path.name;report['selected_exe_sha256']=sha
        tracker=Tracker(path,sha)
        if tracker.discover(process_rows()):raise ValueError('close_selected_application_then_retry')
        print('SELECTED:',path.name)
        print('Open the selected application yourself now (or use its usual launcher). Waiting up to 180 seconds; Q stops observation only.')
        from native_tcp import tcp_connections
        import msvcrt
        wait_end=time.monotonic()+WAIT_SECONDS;start=None
        while True:
            if msvcrt.kbhit() and msvcrt.getwch().lower()=='q':report['status']='user_stopped';break
            now=time.monotonic()
            if start is None and now>=wait_end:report['status']='selected_exe_not_observed';break
            if start is not None and now-start>=OBSERVE_SECONDS:report['status']='observation_ended';break
            try:
                live=tracker.discover(process_rows())
                if tracker.started and start is None:
                    start=now;report['status']='observing'
                    print('Selected EXE detected. Recording TCP destinations for 120 seconds; Q ends early.')
                    print('Helpers observed as descendants are included; existing/unseen helpers may be missed.')
                if live:tracker.add_connections(live,tcp_connections(set(live)),0 if start is None else now-start)
            except OSError:report['sampler_errors']+=1
            time.sleep(.2)
    except KeyboardInterrupt:report['status']='interrupted'
    except Exception as e:
        import re
        report['status']='stopped'
        report['error_code']=str(e) if isinstance(e,ValueError) and re.fullmatch('[a-z0-9_]{1,100}',str(e)) else 'local_observation_failed'
        print('STOP:',report['error_code'])
    finally:
        if tracker:
            report['observation']=tracker.report()
            flows=report['observation']['tcp_destinations']
            print('Distinct sampled TCP destinations (per process):',len(flows))
            for f in flows[:30]:
                print('  Process',f['process_index'],str(f['remote_address'])+':'+str(f['remote_port']),','.join(f['tcp_states']))
            print('SynSent is an attempt, NOT proof of a successful connection. See JSON for all rows.')
        print('Observer stopped. Game/launcher/download were NOT paused or closed.')
        save(report)

if __name__=='__main__':main()
