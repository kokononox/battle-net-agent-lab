"""One approved fresh-Windows Agent handshake. No account or product operations."""
import ctypes
from ctypes import wintypes as w
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import time

SCHEMA='logged-out-agent-interface-1'
APPROVAL='lab: approved logged-out Agent interface probe 2026-10-17 6f4d2b81'
MAX_BODY=65536
STATUSES={'not_started','bootstrap_not_ready','agent_not_unique','agent_signature_refused',
 'agent_launch_failed','agent_exited','listener_not_unique','identity_changed','http_rejected',
 'response_rejected','handshake_token_observed','handshake_without_token','stopped_safely'}
class Stop(Exception):
    pass

def fresh_environment(env, platform):
    return (platform=='win32' and env.get('GITHUB_ACTIONS')=='true'
        and env.get('RUNNER_OS')=='Windows' and env.get('RUNNER_ENVIRONMENT')=='github-hosted'
        and env.get('GITHUB_EVENT_NAME')=='push' and env.get('GITHUB_RUN_ATTEMPT')=='1'
        and env.get('AGENT_INTERFACE_ONCE')==APPROVAL
        and re.fullmatch('[0-9a-f]{40}',env.get('GITHUB_SHA','')) is not None
        and re.fullmatch('[0-9]+',env.get('GITHUB_RUN_ID','')) is not None)

def blank():
    return dict(schema=SCHEMA, source_commit=os.environ.get('GITHUB_SHA',''),
        run_id=os.environ.get('GITHUB_RUN_ID',''),run_attempt=os.environ.get('GITHUB_RUN_ATTEMPT',''),
        status='not_started',bootstrap_status='not_started',bootstrap_language_continued=False,
        bootstrap_account_login_attempted=False,bootstrap_game_download_requested=False,
        clean_hosted_windows_required=True,agent_signature_verified=False,agent_sha256=None,
        process_path_verified=False,listener_owner_verified=False,listener_binding=None,
        http_requests_attempted=0,http_status=None,response_bytes=0,response_json_object=False,
        authorization_token_present=False,account_login_attempted=False,
        game_download_requested=False,game_update_requested=False,repair_requested=False,
        game_files_opened=0,raw_response_exported=False,token_exported=False,
        account_login_requirement_proven=False,game_update_without_login_proven=False,
        retail_policy_proven=False,classic_download_authorized=False,
        free_disk_before_bytes=0,free_disk_after_bytes=0,
        installer_body_limit_bytes=128*1024**2,response_body_limit_bytes=MAX_BODY,
        bootstrap_observation_seconds=120,agent_observation_seconds=30,
        child_network_hard_byte_cap=False,cleanup_attempted=False)

def validate(r):
    if type(r) is not dict or set(r)!=set(blank()):raise ValueError('schema')
    template=blank()
    for k,v in template.items():
        if type(v) is bool and k not in OBSERVED_FLAGS and r[k] is not v:raise ValueError('fixed_flag')
    for k in ('bootstrap_language_continued','agent_signature_verified','process_path_verified',
              'listener_owner_verified','response_json_object','authorization_token_present','cleanup_attempted'):
        if type(r[k]) is not bool:raise ValueError('boolean')
    # These observations may differ from the blank; all other booleans are fixed safety claims.
    if r['schema']!=SCHEMA or r['status'] not in STATUSES:raise ValueError('status')
    if not re.fullmatch('[0-9a-f]{40}',r['source_commit']):raise ValueError('commit')
    if not re.fullmatch('[0-9]{1,30}',r['run_id']) or r['run_attempt']!='1':raise ValueError('run')
    if r['bootstrap_status'] not in {'not_started','stopped','agent_process_observed','bootstrapper_observed_agent_not_observed'}:raise ValueError('bootstrap')
    if r['agent_sha256'] is not None and not re.fullmatch('[0-9a-f]{64}',r['agent_sha256']):raise ValueError('hash')
    if r['listener_binding'] not in (None,'loopback','wildcard'):raise ValueError('binding')
    for k,cap in (('http_requests_attempted',1),('response_bytes',MAX_BODY),
                  ('free_disk_before_bytes',2**60),('free_disk_after_bytes',2**60),('game_files_opened',0)):
        if type(r[k]) is not int or not 0<=r[k]<=cap:raise ValueError('count')
    for k in ('installer_body_limit_bytes','response_body_limit_bytes','bootstrap_observation_seconds','agent_observation_seconds'):
        if type(r[k]) is not int or r[k]!=template[k]:raise ValueError('limit')
    if r['http_status'] is not None and (type(r['http_status']) is not int or not 100<=r['http_status']<=599):raise ValueError('http_status')
    if r['http_requests_attempted'] and not (r['agent_signature_verified'] and r['process_path_verified'] and r['listener_owner_verified']):raise ValueError('request_without_identity')
    if r['listener_owner_verified'] and not r['process_path_verified']:raise ValueError('listener_identity')
    if r['process_path_verified'] and not r['agent_signature_verified']:raise ValueError('signature')
    if r['agent_signature_verified'] != (r['agent_sha256'] is not None):raise ValueError('signature_hash')
    if r['http_requests_attempted']==0 and (r['http_status'] is not None or r['response_bytes'] or r['response_json_object'] or r['authorization_token_present']):raise ValueError('response_without_request')
    if r['authorization_token_present'] and not (r['response_json_object'] and r['http_status']==200):raise ValueError('token')
    if r['status'] in {'handshake_token_observed','handshake_without_token'}:
        if not (r['http_requests_attempted']==1 and r['http_status']==200 and r['response_json_object'] and r['cleanup_attempted']):raise ValueError('handshake')
        if r['authorization_token_present'] != (r['status']=='handshake_token_observed'):raise ValueError('handshake_token')
    return r

# Override fixed-boolean validation only for observed booleans, never safety flags.
OBSERVED_FLAGS={'bootstrap_language_continued','agent_signature_verified','process_path_verified',
               'listener_owner_verified','response_json_object','authorization_token_present','cleanup_attempted'}

def unique_json(raw):
    def pairs(items):
        result={}
        for k,v in items:
            if k in result:raise ValueError('duplicate')
            result[k]=v
        return result
    def reject(_):raise ValueError('nonfinite')
    if len(raw)>MAX_BODY:raise ValueError('body_limit')
    result=json.loads(raw.decode('utf-8-sig'),object_pairs_hook=pairs,parse_constant=reject)
    if type(result) is not dict:raise ValueError('object_required')
    return result

def read_token(raw):
    result=unique_json(raw)
    token=result.get('authorization')
    # No field names, token values, raw body or error text enter the report.
    return token if type(token) is str and 0<len(token)<=8192 else None

def inspect_response(raw):
    return read_token(raw) is not None

def request_agent(port, report, connection_factory=http.client.HTTPConnection):
    if type(port) is not int or not 1<=port<=65535:raise Stop('listener_not_unique')
    if report['http_requests_attempted']!=0:raise Stop('http_rejected')
    if not (report['agent_signature_verified'] and report['process_path_verified'] and report['listener_owner_verified']):raise Stop('identity_changed')
    report['http_requests_attempted']=1 # Before I/O: no retry, including uncertain delivery.
    conn=connection_factory('127.0.0.1',port,timeout=3)
    try:
        conn.request('GET','/agent',headers={'User-Agent':'phoenix-agent/1.0','Accept':'application/json','Accept-Encoding':'identity','Connection':'close'})
        response=conn.getresponse();report['http_status']=response.status
        if response.status!=200:raise Stop('http_rejected')
        if response.getheader('Content-Encoding','identity').lower() not in ('','identity'):raise Stop('response_rejected')
        length=response.getheader('Content-Length')
        if length is not None and (not re.fullmatch('[0-9]{1,10}',length) or int(length)>MAX_BODY):raise Stop('response_rejected')
        raw=response.read(MAX_BODY+1)
        if len(raw)>MAX_BODY:raise Stop('response_rejected')
        report['response_bytes']=len(raw)
        if length is not None and len(raw)!=int(length):raise Stop('response_rejected')
        try:token=read_token(raw);present=token is not None
        except (ValueError,UnicodeError,RecursionError):raise Stop('response_rejected') from None
        report['response_json_object']=True;report['authorization_token_present']=present
        report['status']='handshake_token_observed' if present else 'handshake_without_token'
        return token # Memory-only; never add this value to the report.
    finally:conn.close()

def listener_rows(pid):
    """IPv4 listen endpoints owned by the exact spawned PID. No port scan."""
    api=ctypes.WinDLL('iphlpapi',use_last_error=True).GetExtendedTcpTable
    api.argtypes=[ctypes.c_void_p,ctypes.POINTER(w.DWORD),w.BOOL,w.ULONG,ctypes.c_int,w.ULONG];api.restype=w.DWORD
    size=w.DWORD(0);code=api(None,ctypes.byref(size),False,socket.AF_INET,5,0)
    if code not in (0,122):raise Stop('listener_not_unique')
    for _ in range(3):
        if not 4<=size.value<=16*1024**2:raise Stop('listener_not_unique')
        allocated=size.value;buf=ctypes.create_string_buffer(allocated)
        code=api(buf,ctypes.byref(size),False,socket.AF_INET,5,0)
        if code==0:break
        if code!=122:raise Stop('listener_not_unique')
    if code:raise Stop('listener_not_unique')
    count=struct.unpack_from('<I',buf.raw)[0]
    if 4+count*24>allocated:raise Stop('listener_not_unique')
    rows=[]
    for i in range(count):
        state,addr,port,_,_,owner=struct.unpack_from('=6I',buf.raw,4+i*24)
        if state==2 and owner==pid:
            ip=socket.inet_ntoa(struct.pack('=I',addr))
            rows.append((ip,socket.ntohs(port&65535)))
    return rows

def choose_listener(rows):
    # A wildcard listen is reachable through loopback; never connect externally.
    if not rows:return None
    if len(rows)!=1:raise Stop('listener_not_unique')
    address,port=rows[0]
    if address not in ('127.0.0.1','0.0.0.0') or type(port) is not int or not 1<=port<=65535:raise Stop('listener_not_unique')
    return port,'loopback' if address=='127.0.0.1' else 'wildcard'

def process_image(pid):
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    api.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];api.OpenProcess.restype=w.HANDLE
    api.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,ctypes.POINTER(w.DWORD)];api.QueryFullProcessImageNameW.restype=w.BOOL
    api.CloseHandle.argtypes=[w.HANDLE];api.CloseHandle.restype=w.BOOL
    h=api.OpenProcess(0x1000,False,pid)
    if not h:raise Stop('identity_changed')
    try:
        n=w.DWORD(32768);text=ctypes.create_unicode_buffer(n.value)
        if not api.QueryFullProcessImageNameW(h,0,text,ctypes.byref(n)):raise Stop('identity_changed')
        return Path(text.value)
    finally:api.CloseHandle(h)

def choose_agent(root,is_reparse):
    if not root.is_dir() or is_reparse(root):raise Stop('agent_not_unique')
    candidates=[]
    with os.scandir(root) as entries:
        for i,item in enumerate(entries):
            if i>=64:raise Stop('agent_not_unique')
            if re.fullmatch(r'Agent\.[0-9]{1,10}',item.name):
                folder=Path(item.path);path=folder/'Agent.exe'
                if is_reparse(folder) or is_reparse(path) or not path.is_file():raise Stop('agent_not_unique')
                if not 2<=path.stat().st_size<=128*1024**2:raise Stop('agent_not_unique')
                candidates.append(path)
    if len(candidates)!=1:raise Stop('agent_not_unique')
    return candidates[0].resolve()

def run(out, after_handshake=None, report_sink=None):
    r=blank() if report_sink is None else report_sink
    if r!=blank():raise ValueError("handshake_sink_must_be_blank")
    process=None;env=None
    out.mkdir(parents=True,exist_ok=True)
    try:
        if not fresh_environment(os.environ,sys.platform):raise Stop('stopped_safely')
        import observe_agent as lab
        env=lab.clean_environment(os.environ)
        if lab.snapshot(env)['processes']:raise Stop('bootstrap_not_ready')
        r['free_disk_before_bytes']=shutil.disk_usage(os.environ['RUNNER_TEMP']).free
        bootstrap=lab.observe(out,seconds=120,advance_language=True,advance_install=False)
        r['bootstrap_status']=bootstrap['status']
        language=bootstrap['language_step']
        r['bootstrap_language_continued']=language['status']=='continued' and not language['outcome_uncertain']
        if bootstrap['safety']['account_login_attempted'] or bootstrap['safety']['game_download_requested']:raise Stop('bootstrap_not_ready')
        if bootstrap['status']!='agent_process_observed' or not bootstrap['cleanup_attempted'] or not r['bootstrap_language_continued']:raise Stop('bootstrap_not_ready')
        if lab.snapshot(env)['processes']:raise Stop('bootstrap_not_ready')
        root=Path(os.environ['ProgramData'])/'Battle.net'/'Agent'
        agent=choose_agent(root,lab.is_reparse)
        sig=lab.signature(agent,env)
        if not sig['accepted_for_execution']:raise Stop('agent_signature_refused')
        r['agent_signature_verified']=True;r['agent_sha256']=hashlib.sha256(agent.read_bytes()).hexdigest()
        process=subprocess.Popen([str(agent),'--internalclienttools'],cwd=agent.parent,env=env,
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        deadline=time.monotonic()+30;selected=None
        while time.monotonic()<deadline:
            if process.poll() is not None:raise Stop('agent_exited')
            if process_image(process.pid).resolve()!=agent:raise Stop('identity_changed')
            r['process_path_verified']=True
            selected=choose_listener(listener_rows(process.pid))
            if selected:break
            time.sleep(.5)
        if not selected:raise Stop('listener_not_unique')
        if process.poll() is not None or process_image(process.pid).resolve()!=agent or choose_listener(listener_rows(process.pid))!=selected:raise Stop('identity_changed')
        port,binding=selected;r['listener_binding']=binding;r['listener_owner_verified']=True
        def verify_live():
            if process.poll() is not None or process_image(process.pid).resolve()!=agent or choose_listener(listener_rows(process.pid))!=selected:raise Stop('identity_changed')
            return True
        token=request_agent(port,r)
        verify_live()
        # Only trusted in-repository observers; no plugin or configuration loading.
        # Nested handshake count remains 1; the observer reports its own extra request.
        if after_handshake is not None and token is not None:
            after_handshake(token,port,verify_live)
            verify_live()
        token=None
    except Stop as exc:r['status']=str(exc) if str(exc) in STATUSES else 'stopped_safely'
    except Exception:r['status']='stopped_safely' # Never stringify exceptions/response data.
    finally:
        if env is not None:
            r['cleanup_attempted']=True
            try:
                import observe_agent as lab
                if process is not None and process.poll() is None:
                    subprocess.run([str(Path(os.environ['SystemRoot'])/'System32'/'taskkill.exe'),'/PID',str(process.pid),'/T','/F'],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5,check=False)
                lab.stop_observed(lab.snapshot(env),env)
            except Exception:pass # Disposal of the hosted job is the final isolation boundary.
            try:r['free_disk_after_bytes']=shutil.disk_usage(os.environ['RUNNER_TEMP']).free
            except OSError:pass
        validate(r)
        (out/'agent-interface-to-share.json').write_text(json.dumps(r,indent=2),encoding='utf-8')
        print(json.dumps({'status':r['status'],'http_requests_attempted':r['http_requests_attempted'],'report_written':True}))
    return r

if __name__=='__main__':
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
    run(Path('output'))
