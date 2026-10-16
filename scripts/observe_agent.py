"""Bounded bootstrap observation on a fresh GitHub-hosted Windows runner only.
No login, game/product request, raw-log upload or CASC access.
Optional explicitly approved one-off language action; otherwise UI read-only.
"""
import argparse
import collections
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SETUP_URL = 'https://downloader.battle.net/download/getInstaller?os=win&installer=Battle.net-Setup.exe'
MAX_SETUP = 128 * 1024**2
MAX_REPORT = 256 * 1024
NAMES = {'agent.exe', 'battle.net.exe', 'battle.net launcher.exe', 'battle.net-setup.exe',
         'battle.net helper.exe', 'blizzarderror.exe'}
PUBLISHERS = {'Blizzard Entertainment, Inc.', 'Blizzard Entertainment, Inc',
              'Blizzard Entertainment Inc.', 'Blizzard Entertainment'}
MARKERS = ('initializ', 'download', 'patch', 'install', 'repair', 'error', 'login', 'auth')
ROOT_KEYS = ('agent', 'app', 'local_app', 'temporary_install')
CLEAN_ENV_KEYS = {'SYSTEMROOT','WINDIR','PATH','PATHEXT','COMSPEC','TEMP','TMP',
    'USERPROFILE','HOMEDRIVE','HOMEPATH','APPDATA','LOCALAPPDATA','PROGRAMDATA',
    'PROGRAMFILES','PROGRAMFILES(X86)','COMMONPROGRAMFILES','COMMONPROGRAMFILES(X86)',
    'ALLUSERSPROFILE','PROCESSOR_ARCHITECTURE','PROCESSOR_IDENTIFIER',
    'NUMBER_OF_PROCESSORS','OS','SYSTEMDRIVE','SYSTEMDIRECTORY'}


class LabError(Exception):
    pass


def clean_environment(source):
    return {k:v for k,v in source.items() if k.upper() in CLEAN_ENV_KEYS}


def safe_url(url):
    p = urllib.parse.urlsplit(url)
    host = (p.hostname or '').lower()
    allowed = (host in {'battle.net','blizzard.com','blzddist1-a.akamaihd.net'} or
               host.endswith('.battle.net') or host.endswith('.blizzard.com'))
    if p.scheme != 'https' or not allowed or p.username or p.password or p.port not in (None,443):
        raise LabError('installer_url_outside_https_allowlist')
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_setup(destination):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    url = SETUP_URL; started = time.monotonic(); count = 0
    temp = destination.with_suffix('.part')
    try:
        for redirects in range(7):
            safe_url(url)
            req = urllib.request.Request(url,headers={'User-Agent':'AgentLab/0.1','Accept-Encoding':'identity'})
            try:
                response = opener.open(req,timeout=20)
            except urllib.error.HTTPError as exc:
                if exc.code in (301,302,303,307,308):
                    location = exc.headers.get('Location',''); exc.close()
                    if not location: raise LabError('installer_redirect_without_location')
                    url = urllib.parse.urljoin(url,location); continue
                raise LabError('installer_http_error') from None
            with response:
                if response.status != 200: raise LabError('installer_http_status_not_200')
                length = response.headers.get('Content-Length')
                if length and (not length.isdigit() or int(length)>MAX_SETUP):
                    raise LabError('installer_declared_body_limit')
                digest=hashlib.sha256()
                with temp.open('xb') as sink:
                    while True:
                        if time.monotonic()-started>120: raise LabError('installer_download_deadline')
                        chunk=response.read(65536)
                        if not chunk:break
                        count+=len(chunk)
                        if count>MAX_SETUP:raise LabError('installer_body_limit')
                        digest.update(chunk);sink.write(chunk)
                    sink.flush();os.fsync(sink.fileno())
                if length and count!=int(length):raise LabError('installer_body_length_mismatch')
                with temp.open('rb') as f:
                    if f.read(2)!=b'MZ':raise LabError('installer_not_windows_pe')
                os.replace(temp,destination)
                return {'bytes':count,'sha256':digest.hexdigest(),'redirects':redirects}
        raise LabError('installer_redirect_limit')
    finally:
        if temp.exists():temp.unlink()


def signature(path, env):
    from native_authenticode import verify, NativeSignatureError
    try:return verify(path,env)
    except NativeSignatureError as exc:raise LabError(str(exc)) from None


def snapshot(env):
    # Native process/IP-helper APIs avoid the cold WMI provider timeout observed
    # on the hosted Windows runner. No process paths or command lines are read.
    import native_windows
    return native_windows.snapshot(NAMES)


def safe_snapshot(raw, elapsed):
    processes=[];ids=set()
    for item in (raw.get('processes') or [])[:24]:
        name=str(item.get('Name','')).lower()
        if name not in NAMES:continue
        pid=item.get('ProcessId');parent=item.get('ParentProcessId')
        if type(pid) is not int or not 0<pid<2**32:continue
        ids.add(pid)
        processes.append({'name':name,'pid':pid,'parent_pid':parent if type(parent) is int else 0})
    connections=[]
    states={'Closed','Listen','SynSent','SynReceived','Established','FinWait1','FinWait2',
            'CloseWait','Closing','LastAck','TimeWait','DeleteTCB','Bound'}
    for item in (raw.get('connections') or [])[:24]:
        if item.get('OwningProcess') not in ids:continue
        try:address=ipaddress.ip_address(item['RemoteAddress'])
        except (KeyError,ValueError,TypeError):continue
        port=item.get('RemotePort');state_name=str(item.get('State',''))
        if type(port) is not int or not 0<=port<=65535:continue
        # Public destination address only; private/internal addresses are labeled.
        connections.append({'pid':item['OwningProcess'],'remote_address':str(address) if address.is_global else 'nonpublic',
                            'remote_port':port,'state':state_name if state_name in states else 'other'})
    return {'elapsed_seconds':elapsed,'processes':processes,'connections':connections}


def file_metadata(roots):
    groups={};agents=[];logs=[]
    deadline=time.monotonic()+8
    for category,root in roots.items():
        count=total=skipped=0;exts=collections.Counter()
        if root.exists() and not is_reparse(root):
            for folder,dirs,files in os.walk(root,followlinks=False):
                # Explicitly skip junctions/reparse points, not just symlinks.
                dirs[:]=[d for d in dirs if not is_reparse(Path(folder)/d)]
                for name in files:
                    if count>=10000 or time.monotonic()>deadline:break
                    path=Path(folder)/name
                    try:
                        info=path.lstat()
                        if not stat.S_ISREG(info.st_mode) or is_reparse(path):skipped+=1;continue
                        count+=1;total+=info.st_size
                        ext=path.suffix.lower();exts[ext if re.fullmatch(r'\.[a-z0-9]{1,10}',ext) else 'other']+=1
                        if name.lower()=='agent.exe' and len(agents)<4:agents.append(path)
                        if ext in ('.log','.txt') and len(logs)<24:logs.append(path)
                    except OSError:skipped+=1
                if count>=10000 or time.monotonic()>deadline:break
        groups[category]={'files_observed':count,'bytes_on_disk_observed':total,
                          'skipped_files':skipped,'extensions':dict(exts.most_common(32))}
    return groups,agents,logs


def is_reparse(path):
    try:
        s=path.lstat();return stat.S_ISLNK(s.st_mode) or bool(getattr(s,'st_file_attributes',0)&1024)
    except OSError:return True


def log_marker_counts(paths):
    result=dict.fromkeys(MARKERS,0);read=0
    for p in paths:
        try:
            if is_reparse(p):continue
            with p.open('rb') as f:b=f.read(min(2*1024**2,32*1024**2-read))
            read+=len(b);text=b.decode('utf-8',errors='ignore').lower()
            for key in MARKERS:result[key]+=text.count(key)
            if read>=32*1024**2:break
        except OSError:continue
    return {'bytes_read':read,'keyword_occurrences_only':result,'raw_log_content_exported':False}


def stop_observed(raw, env):
    """Only on a fresh hosted VM; never called for a user/self-hosted machine."""
    pids=[]
    for item in raw.get('processes') or []:
        if str(item.get('Name','')).lower() in NAMES and type(item.get('ProcessId')) is int:
            pids.append(item['ProcessId'])
    for pid in sorted(set(pids),reverse=True)[:16]:
        subprocess.run([str(Path(os.environ['SystemRoot'])/'System32'/'taskkill.exe'),'/PID',str(pid),'/T','/F'],
                       env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5,check=False)


def initial_report():
    return {'schema':'agent-bootstrap-observation-9','status':'not_started',
      'scope':'fresh_hosted_windows_bootstrap_only;not_WoW_update_or_install',
      'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
      'source_commit':os.environ.get('GITHUB_SHA') if re.fullmatch('[0-9a-f]{40}',os.environ.get('GITHUB_SHA','')) else None,
      'run_id':os.environ.get('GITHUB_RUN_ID') if os.environ.get('GITHUB_RUN_ID','').isdigit() else None,
      'run_attempt':os.environ.get('GITHUB_RUN_ATTEMPT') if os.environ.get('GITHUB_RUN_ATTEMPT','').isdigit() else None,
      'install_step':__import__('install_step').blank(),'language_step':__import__('language_step').blank(),'gui_observations':[],'safety_test_result':{},'signature_backend':'Windows_WinVerifyTrust_Authenticode',
      'installer':{},'samples':[],'file_observations':{},'agent_binaries':[],
      'log_markers':{},'setup_visual':__import__('setup_visual').blank(),'agent_state':__import__('agent_state').blank(),'cleanup_attempted':False,'error_code':None,
      'phase':'environment_check','error_type':None,'underlying_error_type':None,'numeric_error_code':None,
      'limits':{'observation_seconds':150,'installer_body_bytes':MAX_SETUP,
                'bootstrapper_child_network_hard_byte_cap':False},
      'safety':{'account_login_attempted':False,'game_download_requested':False,
        'game_installation_modified':False,'CASC_writes_requested':False,
        'raw_logs_exported':False,'binaries_exported':False,
        'github_tokens_passed_in_child_environment':False},
      'interpretation':{'installation_complete_proven':False,'agent_bootstrap_observation_only':True,
        'no_agent_observed_does_not_prove_agent_absent':True,
        'endpoint_sampling_is_not_full_network_capture':True,
        'log_keyword_counts_do_not_prove_operation_execution':True}}


def observe(out_dir, seconds=150, advance_language=False, advance_install=False):
    if type(seconds) is not int or not 30<=seconds<=150:raise LabError('observation_seconds_out_of_range')
    report=initial_report();report['limits']['observation_seconds']=seconds
    from language_step import blank as language_blank, run as language_run
    if advance_install and not advance_language:raise LabError('language_authorization_required')
    from install_step import blank as install_blank, run as install_run
    report['install_step']=install_blank(advance_install)
    report['language_step']=language_blank(advance_language)
    install_checked=False
    def advance(targets):
        # The callback is used only for the first read-only snapshot, never repeated.
        report['language_step']['outcome_uncertain']=True # retained if an unexpected wrapper failure interrupts
        report['language_step']=language_run(targets,process.pid,setup,authorized=True)
    def install(targets):
        report['install_step']['outcome_uncertain']=True
        report['install_step']=install_run(targets,process.pid,setup,authorized=True)
    work=None;env=clean_environment(os.environ);raw={'processes':[]};launched=False;process=None
    try:
        if sys.platform!='win32' or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_OS')!='Windows' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
            raise LabError('fresh_github_hosted_windows_required')
        test_summary=out_dir/'safety-test-summary.json'
        if test_summary.exists():
            from run_safety_tests import validate_summary
            summary=validate_summary(json.loads(test_summary.read_text(encoding='utf-8')))
            report['safety_test_result']=summary
            if summary['result']!='passed':raise LabError('safety_test_suite_failed')
        run_id=os.environ.get('GITHUB_RUN_ID','');attempt=os.environ.get('GITHUB_RUN_ATTEMPT','')
        if not run_id.isdigit() or not attempt.isdigit():raise LabError('invalid_run_identity')
        report['phase']='directory_prepare'
        temp=Path(os.environ['RUNNER_TEMP']).resolve()
        if is_reparse(temp):raise LabError('runner_temp_reparse_not_allowed')
        work=temp/('bnet-observe-'+run_id+'-'+attempt);work.mkdir(exist_ok=False)
        roots={'agent':Path(os.environ['ProgramData'])/'Battle.net'/'Agent',
               'app':Path(os.environ['ProgramFiles(x86)'])/'Battle.net',
               'local_app':Path(os.environ['LOCALAPPDATA'])/'Battle.net',
               'temporary_install':work/'app'}
        report['phase']='baseline_snapshot'
        raw=snapshot(env)
        if raw.get('processes') or any(r.exists() for r in roots.values()):
            raise LabError('preexisting_battlenet_state_refused')
        setup=work/'Battle.net-Setup.exe'
        report['phase']='installer_download'
        report['installer'].update(fetch_setup(setup))
        report['phase']='installer_signature'
        report['installer'].update(signature(setup,env))
        if not report['installer']['accepted_for_execution']:raise LabError('installer_signature_or_publisher_not_accepted')
        # No silent/EULA/login flags. Only separately approved language and
        # exact setup-options Continue; no legal/account or other wizard actions.
        report['phase']='bootstrapper_launch'
        process=subprocess.Popen([str(setup)],cwd=work,env=env,stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        launched=True;started=time.monotonic()
        report['phase']='sampling'
        while time.monotonic()-started<seconds:
            raw=snapshot(env)
            report['samples'].append(safe_snapshot(raw,round(time.monotonic()-started,2)))
            if not report['gui_observations'] and time.monotonic()-started>=5:
                report['phase']='gui_inspection'
                import native_gui
                pids={p['pid'] for p in report['samples'][-1]['processes']}
                report['gui_observations'].append(native_gui.inspect(pids,round(time.monotonic()-started,2),on_visible_targets=advance) if advance_language else native_gui.inspect(pids,round(time.monotonic()-started,2)))
                report['phase']='sampling'
            if advance_install and not install_checked and time.monotonic()-started>=30:
                install_checked=True # One attempt only, including mismatch or uncertainty.
                if report['language_step']['status']=='continued' and not report['language_step']['outcome_uncertain']:
                    import native_gui
                    pids={p['pid'] for p in report['samples'][-1]['processes']}
                    report['gui_observations'].append(native_gui.inspect(pids,round(time.monotonic()-started,2),on_visible_targets=install))
            if len(report['samples'])>=30:break
            time.sleep(5)
        report['phase']='gui_inspection'
        import native_gui
        pids={p['pid'] for p in report['samples'][-1]['processes']}
        def capture_visual(targets):
            import setup_visual
            report['setup_visual']=setup_visual.capture(targets)
        report['gui_observations'].append(native_gui.inspect(pids,round(time.monotonic()-started,2),on_visible_targets=capture_visual) if advance_language and not advance_install else native_gui.inspect(pids,round(time.monotonic()-started,2)))
        report['phase']='filesystem_observation'
        groups,agents,logs=file_metadata(roots);report['file_observations']=groups
        for path in agents[:1]:
            if path.stat().st_size>128*1024**2:continue
            report['phase']='agent_binary_signature'
            sig=signature(path,env)
            report['agent_binaries'].append({'name':'agent.exe','bytes':path.stat().st_size,
                'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),**sig})
        report['log_markers']=log_marker_counts(logs)
        report['phase']='agent_state_observation'
        import agent_state
        report['agent_state']=agent_state.collect(logs,roots,report['gui_observations'][-1])
        observed=any(p['name']=='agent.exe' for s in report['samples'] for p in s['processes'])
        report['status']='agent_process_observed' if observed else 'bootstrapper_observed_agent_not_observed'
        report['phase']='cleanup'
        report['cleanup_attempted']=True
        raw=snapshot(env);stop_observed(raw,env)
        if process.poll() is None:
            subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],env=env,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5,check=False)
        try:process.wait(timeout=10)
        except subprocess.TimeoutExpired:process.kill()
        report['phase']='complete'
    except Exception as exc:
        report['status']='stopped'
        report['error_type']=type(exc).__name__ if re.fullmatch('[A-Za-z0-9_]{1,64}',type(exc).__name__) else 'Exception'
        underlying=getattr(exc,'reason',None)
        if isinstance(underlying,BaseException):
            name=type(underlying).__name__
            report['underlying_error_type']=name if re.fullmatch('[A-Za-z0-9_]{1,64}',name) else 'Exception'
        code=getattr(underlying,'verify_code',getattr(exc,'winerror',getattr(exc,'errno',None)))
        if type(code) is int and -2**31<=code<2**31:report['numeric_error_code']=code
        report['error_code']=str(exc) if isinstance(exc,LabError) and re.fullmatch('[a-z0-9_]{1,100}',str(exc)) else 'bounded_probe_failed'
    finally:
        if launched and not report['cleanup_attempted']:
            report['cleanup_attempted']=True
            try:stop_observed(snapshot(env),env)
            except Exception:pass
        if process is not None and process.poll() is None:
            try:
                subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],env=env,
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5,check=False)
            except Exception:pass
        out_dir.mkdir(parents=True,exist_ok=True)
        payload=json.dumps(report,indent=2).encode()
        if len(payload)>MAX_REPORT:raise LabError('sanitized_report_size_limit')
        path=out_dir/'agent-observation-to-share.json';path.write_bytes(payload)
        # Console contains no exception strings, paths, logs or download URLs.
        print(json.dumps({'status':report['status'],'error_code':report['error_code'],
                          'sanitized_report_written':True}))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
    p.add_argument('--observation-seconds',type=int,default=150)
    args=p.parse_args()
    from language_step import authorized_environment
    approved=authorized_environment(os.environ)
    from install_step import authorized_environment as install_authorized
    install_approved=install_authorized(os.environ)
    observe(args.output,150 if install_approved else (120 if approved else args.observation_seconds),advance_language=approved,advance_install=install_approved)
