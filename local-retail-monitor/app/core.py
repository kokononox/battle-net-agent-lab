"""Attach-only local observation. Never spawn/control Battle.net or persist API buffers."""
from collections import Counter
import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time
import zlib
from body_meta import analyze_body
from hosts_guard import safe_path
from native_identity import identity
from native_tcp import snapshot

NAMES={'agent.exe','battle.net.exe','battle.net launcher.exe','battle.net-setup.exe','battle.net helper.exe','blizzarderror.exe'}
WOW={'wow.exe','wow-64.exe','wowt.exe','wowb.exe','wowclassic.exe'}
APIS={'send','WSASend','EncryptMessage'}
HOOKS=APIS|{'connect','WSAConnect','closesocket'}
CLEAN={'SYSTEMROOT','WINDIR','PATH','PATHEXT','COMSPEC','TEMP','TMP','USERPROFILE','APPDATA','LOCALAPPDATA','PROGRAMDATA','PROGRAMFILES','PROGRAMFILES(X86)','OS','SYSTEMDRIVE','PROCESSOR_ARCHITECTURE','NUMBER_OF_PROCESSORS'}

def clean_env():return {k:v for k,v in os.environ.items() if k.upper() in CLEAN}
def cpu_reference():
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as key:
            return winreg.QueryValueEx(key,'ProcessorNameString')[0].strip().encode('ascii')[:160]
    except (OSError,UnicodeError):return None

def hostname(s):
    if not isinstance(s,str):return None
    s=s.lower().rstrip('.')
    if s.endswith(':80'):s=s[:-3]
    elif s.endswith(':443'):s=s[:-4]
    if len(s)>253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in s.split('.')):return None
    return s

def versions(root):
    result=set();status='not_found'
    root=safe_path(root)
    for path in (root/'.build.info',root/'_retail_' /'.build.info'):
        if not path.exists():continue
        try:
            safe_path(path)
            if path.stat().st_size>1048576:status='too_large';continue
            lines=path.read_text(encoding='utf-8-sig').splitlines();header=lines[0].split('|')
            vi=next(i for i,x in enumerate(header) if x.startswith('Version!'))
            pi=next(i for i,x in enumerate(header) if x.startswith('Product!'))
            for line in lines[1:]:
                cells=line.split('|')
                if len(cells)>max(pi,vi) and cells[pi]=='wow' and re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,10}',cells[vi]):result.add(cells[vi])
            status='read'
        except Exception:status='unreadable_or_unrecognized'
    return {'status':status,'retail_versions':sorted(result)}

SIGNATURE=r'''$ErrorActionPreference='Stop';$s=Get-AuthenticodeSignature -LiteralPath $env:LOCAL_MONITOR_VERIFY_PATH; $ok=$s.Status -eq 'Valid';$publisher=$false;if($ok -and $null -ne $s.SignerCertificate){$name=$s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false);$publisher=$name -in @('Blizzard Entertainment, Inc.','Blizzard Entertainment, Inc','Blizzard Entertainment Inc.','Blizzard Entertainment')};ConvertTo-Json -Compress -InputObject @{valid=[bool]$ok;blizzard=[bool]$publisher;status=[string]$s.Status}'''

def signature(path):
    env=clean_env();env['LOCAL_MONITOR_VERIFY_PATH']=str(path)
    exe=Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'powershell.exe'
    r=subprocess.run([str(exe),'-NoLogo','-NoProfile','-NonInteractive','-Command',SIGNATURE],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,check=False,creationflags=0x08000000)
    if r.returncode or len(r.stdout)>4096:raise ValueError('signature_check_failed')
    d=json.loads(r.stdout.decode('utf-8-sig'))
    if set(d)!={'valid','blizzard','status'} or type(d['valid']) is not bool or type(d['blizzard']) is not bool:raise ValueError('signature_check_rejected')
    if d['status'] not in ('Valid','NotSigned','HashMismatch','NotTrusted','UnknownError','NotSupportedFileFormat','Incompatible'):d['status']='other'
    return d

def bounded(frida,operation):
    c=frida.Cancellable();t=threading.Timer(8,c.cancel);t.daemon=True;t.start()
    try:
        with c:return operation()
    finally:t.cancel()

def decoded_cpu_match(raw,needle):
    if not needle:return None
    if needle in raw:return True
    # Bounded best-effort gzip/deflate only; not a claim that arbitrary encodings are covered.
    if b'\r\n\r\n' not in raw:return False
    head,body=raw.split(b'\r\n\r\n',1);lower=head.lower()
    mode=31 if b'content-encoding: gzip' in lower else 15 if b'content-encoding: deflate' in lower else None
    if mode is not None:
        try:return needle in zlib.decompressobj(mode).decompress(body,65536)
        except zlib.error:pass
    return False

class Collector:
    def __init__(self,frida,needle,fixture_pid=None):
        self.frida=frida;self.needle=needle;self.fixture_pid=fixture_pid
        self.device=frida.get_local_device();self.rows={};self.sessions=[];self.scripts=[]
        self.events=[];self.counts=Counter();self.flows={};self.carry={};self.clock=time.monotonic()
        self.phase='before_user_update';self.lock=threading.RLock();self.stop=threading.Event()
        self.thread=None;self.sampler_errors=0;self.flow_limit=False;self.event_limit=False;self.process_limit=False
        self.private_paths={};self.retry_at={};self.closed=False
    def message(self,key,msg,data):
        with self.lock:
            row=self.rows[key]
            if msg.get('type')!='send' or not isinstance(msg.get('payload'),dict):row['script_errors']+=1;return
            e=msg['payload'];kind=e.get('kind')
            if kind=='ready':row['hook_ready']=True;return
            if kind=='installed':
                if e.get('api') in HOOKS and e['api'] not in row['installed_hooks']:row['installed_hooks'].append(e['api'])
                return
            if kind=='limit':
                row['hook_limit_hit']=True;return
            if kind in ('install_error','read_error'):row['script_errors']+=1;return
            if kind!='input' or e.get('api') not in APIS:return
            raw=bytes(data or b'');declared=e.get('declared_bytes');code=e.get('return_code');tag=e.get('socket');accepted=e.get('accepted_bytes')
            if not (type(declared) is int and 0<=declared<=16777216 and len(raw)<=16384 and type(code) is int and re.fullmatch(r'(?:s|ctx)\d{1,6}',str(tag))):
                row['script_errors']+=1;return
            if accepted is not None and (type(accepted) is not int or not 0<=accepted<=declared):row['script_errors']+=1;return
            if e['api']=='EncryptMessage' and not str(tag).startswith('ctx'):row['script_errors']+=1;return
            if e['api']!='EncryptMessage' and not str(tag).startswith('s'):row['script_errors']+=1;return
            # Metadata is derived immediately; no raw body/header/URL is kept in report or queue.
            meta=analyze_body(raw,declared)
            direct=hostname(meta['http_host']);channel=(key,tag)
            prior=self.carry.get(channel,{'tail':b'','host':None})
            hint=direct or prior['host']
            hit=decoded_cpu_match(raw,self.needle)
            if self.needle and not hit:hit=self.needle in prior['tail']+raw
            if len(self.carry)<4096 or channel in self.carry:
                self.carry[channel]={'tail':raw[-max(1,len(self.needle or b''))-1:],'host':hint}
            else:row['hook_limit_hit']=True
            success=code==0 if e['api']=='EncryptMessage' else accepted is not None and accepted>0
            # 'success' here is local API evidence only, never server receipt.
            row['input_events']+=1
            aggregate_key=(hint or 'unattributed',e['api'],success,hit is True)
            if len(self.counts)>=4096 and aggregate_key not in self.counts:
                self.event_limit=True;aggregate_key=('unattributed',e['api'],success,hit is True)
            self.counts[aggregate_key]+=1
            event={'elapsed_seconds':round(time.monotonic()-self.clock,2),'phase':self.phase,
                'process_index':key,'api':e['api'],'host_hint':hint,
                'host_evidence':'same_buffer_header' if direct else 'channel_history_hint' if hint else 'unavailable',
                'declared_bytes':declared,'observed_prefix_bytes':len(raw),'truncated':e.get('truncated') is True,
                'return_code':code,'accepted_bytes':accepted,'local_api_success':success,
                'reference_cpu_literal_match':hit,'format':meta['format'],'field_name_hints':meta['field_name_hints']}
            if len(self.events)<2048:self.events.append(event)
            else:self.event_limit=True
    def attach(self,pid,name,fixture=False):
        info=identity(pid);path=safe_path(info['path']);token=(pid,info['creation'])
        if token in self.private_paths:return
        if len(self.rows)>=64:self.process_limit=True;return
        if fixture:
            if pid!=self.fixture_pid or path.resolve()!=Path(__import__('sys').executable).resolve():raise ValueError('fixture_identity_refused')
        elif name not in NAMES or path.name.lower()!=name or not 0<path.stat().st_size<=128*1024**2:raise ValueError('image_refused')
        key=len(self.rows)+1
        row={'index':key,'pid':pid,'process_name':'owned_fixture' if fixture else name,'sha256':None,'authenticode_valid':False,
             'blizzard_publisher':False,'status':'checking','hook_ready':False,'installed_hooks':[],
             'script_errors':0,'input_events':0,'hook_limit_hit':False,'late_attach':True,'error_code':None}
        with self.lock:self.rows[key]=row
        self.private_paths[token]=key
        try:
            if not fixture:
                sig=signature(path);row['authenticode_valid']=sig['valid'];row['blizzard_publisher']=sig['blizzard']
                if not sig['valid'] or not sig['blizzard']:raise ValueError('signature_refused')
            if self.stop.is_set():raise ValueError('observer_stopping')
            row['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
            again=identity(pid)
            if again['creation']!=info['creation'] or again['path'].lower()!=str(path).lower():raise ValueError('pid_identity_changed')
            if self.stop.is_set():raise ValueError('observer_stopping')
            session=bounded(self.frida,lambda:self.device.attach(pid));self.sessions.append(session)
            # Attach ONLY. No spawn, child-gating, resume, suspend, or process termination.
            again=identity(pid)
            if again['creation']!=info['creation'] or again['path'].lower()!=str(path).lower():raise ValueError('pid_identity_changed')
            script=bounded(self.frida,lambda:session.create_script(Path(__file__).with_name('hook.js').read_text()))
            self.scripts.append(script);script.on('message',lambda msg,data:self.message(key,msg,data))
            bounded(self.frida,script.load)
            deadline=time.monotonic()+3
            while not row['hook_ready'] and time.monotonic()<deadline:time.sleep(.02)
            if not row['hook_ready'] or row['script_errors']:raise ValueError('hook_not_ready')
            row['status']='attached'
        except Exception as exc:
            row['status']='not_attached';row['error_code']=str(exc) if isinstance(exc,ValueError) and re.fullmatch('[a-z_]{1,80}',str(exc)) else 'attach_failed'
    def run(self):
        while not self.stop.is_set():
            try:
                snap=snapshot(NAMES)
                for p in snap['processes']:
                    if self.stop.is_set():break
                    try:self.attach(p['ProcessId'],p['Name'].lower())
                    except Exception:self.sampler_errors+=1
                pid_keys={pid:k for (pid,creation),k in self.private_paths.items() if self.rows[k]['status']=='attached'}
                for c in snap['connections']:
                    pid=c['OwningProcess'];k=pid_keys.get(pid)
                    if not k:continue
                    # Recheck creation identity before associating a sampled TCP destination.
                    info=identity(pid)
                    if self.private_paths.get((pid,info['creation']))!=k:continue
                    addr=ipaddress.ip_address(c['RemoteAddress'])
                    if not addr.is_global:continue
                    key=(k,str(addr),c['RemotePort'])
                    if key not in self.flows:
                        if len(self.flows)>=1024:self.flow_limit=True;continue
                        self.flows[key]={'process_index':k,'remote_address':str(addr),'remote_port':c['RemotePort'],'sample_observations':0}
                    self.flows[key]['sample_observations']+=1
            except Exception:self.sampler_errors+=1
            self.stop.wait(.5)
    def start(self):
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def ready(self):
        with self.lock:
            candidates=[(pid,creation,k) for (pid,creation),k in self.private_paths.items()
                if self.rows[k]['status']=='attached' and self.rows[k]['process_name']=='agent.exe'
                and self.rows[k]['hook_ready'] and not self.rows[k]['script_errors']
                and APIS<=set(self.rows[k]['installed_hooks'])]
        for pid,creation,k in candidates:
            try:
                if identity(pid)['creation']==creation:return True
            except Exception:pass
        return False
    def close(self):
        if self.closed:return
        self.closed=True
        self.stop.set()
        if self.thread:self.thread.join(timeout=50)
        # Unload observers and detach only; never alter the user's process lifecycle.
        for script in reversed(self.scripts):
            try:bounded(self.frida,script.unload)
            except Exception:pass
        for session in reversed(self.sessions):
            try:bounded(self.frida,session.detach)
            except Exception:pass
        self.carry.clear();self.private_paths.clear()
    def report(self):
        with self.lock:return {'processes':list(self.rows.values()),'events':list(self.events),
            'aggregate_inputs':[{'host_hint':h if h!='unattributed' else None,'api':a,'local_api_success':s,'cpu_literal_match':c,'input_events':n} for (h,a,s,c),n in sorted(self.counts.items())],
            'public_tcp_destinations':list(self.flows.values()),'sampler_errors':self.sampler_errors,
            'limits_hit':{'event_detail':self.event_limit,'flows':self.flow_limit,'processes':self.process_limit,'hooks':any(x['hook_limit_hit'] for x in self.rows.values())},
            'sampling_thread_stopped':not self.thread or not self.thread.is_alive()}
