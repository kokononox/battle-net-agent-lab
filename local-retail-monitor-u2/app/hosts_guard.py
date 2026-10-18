"""Only an explicitly chosen temporary hosts entry. No firewall or game operations."""
import base64
import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import queue
import socket
import stat
import threading
import uuid

TARGET='telemetry-in.battle.net'
EXTRA_TARGETS=(
    'breaking-news.support.blizzard.com',
    'oauth.battle.net',
    'distribution.version.battle.net',
    'us.version.battle.net',
    'level3.ssl.blizzard.com',
    'level3.blizzard.com',
)
ALLOWED_TARGETS=(TARGET,)+EXTRA_TARGETS

def trial_targets(extra=None):
    if extra is not None and extra not in EXTRA_TARGETS:raise ValueError('target_not_in_fixed_menu')
    return (TARGET,) if extra is None else (TARGET,extra)

def checked_targets(targets):
    if type(targets) not in (tuple,list) or not 1<=len(targets)<=2:raise ValueError('invalid_target_set')
    if tuple(targets)!=trial_targets(targets[1] if len(targets)==2 else None):raise ValueError('invalid_target_set')
    return tuple(targets)

def combined_resolution(states):
    if states and all(s=='loopback_only' for s in states.values()):return 'loopback_only'
    return 'other_or_failed'

def digest(b):return hashlib.sha256(b).hexdigest()
def safe_path(path):
    path=Path(path).absolute()
    for p in (path,*path.parents):
        try:s=p.lstat()
        except FileNotFoundError:continue
        if stat.S_ISLNK(s.st_mode) or getattr(s,'st_file_attributes',0)&1024:
            raise ValueError('reparse_path_refused')
    return path

def target_entry(b,targets=(TARGET,)):
    text=b.decode('utf-8-sig')
    return any(set(targets).intersection(x.split('#',1)[0].lower().split()[1:]) for x in text.splitlines())

def resolve(target=TARGET):
    if target not in ALLOWED_TARGETS:raise ValueError('target_not_in_fixed_menu')
    q=queue.Queue(1)
    def work():
        try:
            ips={ipaddress.ip_address(r[4][0]) for r in socket.getaddrinfo(target,443,type=socket.SOCK_STREAM)}
            state='loopback_only' if ips and all(i.is_loopback for i in ips) else 'public_only' if ips and all(i.is_global for i in ips) else 'other_or_failed'
            q.put(state)
        except Exception:q.put('other_or_failed')
    threading.Thread(target=work,daemon=True).start()
    try:return q.get(timeout=8)
    except queue.Empty:return 'timeout'

def flush():
    f=ctypes.WinDLL('dnsapi').DnsFlushResolverCache;f.argtypes=[];f.restype=ctypes.c_int
    return bool(f())

class HostsGuard:
    def __init__(self,hosts,journal,flush_fn=flush,resolve_fn=None,targets=(TARGET,)):
        self.hosts=Path(hosts);self.journal=Path(journal);self.flush=flush_fn;self.resolve=resolve_fn
        self.targets=checked_targets(targets);self.resolutions={}
        self.changed=False;self.restored=False;self.restore_status='not_needed';self.at_launch='not_tested'
    def check_resolution(self):
        # Legacy injected fixture resolvers take no arguments; real calls always
        # resolve EACH exact target through the OS resolver.
        self.resolutions={t:(self.resolve() if self.resolve is not None else resolve(t)) for t in self.targets}
        return combined_resolution(self.resolutions)
    def apply(self):
        safe_path(self.hosts);safe_path(self.journal)
        if self.journal.exists():raise ValueError('recovery_pending')
        if self.hosts.stat().st_size>1048576:raise ValueError('hosts_size_limit')
        original=self.hosts.read_bytes()
        # Refuse ANY pre-existing entry from the trial menu, not just this target:
        # otherwise a supposedly single-extra trial could contain stale blockers.
        if target_entry(original,ALLOWED_TARGETS):raise ValueError('existing_target_entry_refused_no_changes')
        tag=uuid.uuid4().hex
        block=('\r\n# local-retail-monitor '+tag+'\r\n'+''.join('127.0.0.1 '+t+'\r\n::1 '+t+'\r\n' for t in self.targets)).encode()
        changed=original+block
        state={'schema':'local-hosts-recovery-1','original_base64':base64.b64encode(original).decode(),
            'original_sha256':digest(original),'modified_sha256':digest(changed),'block_base64':base64.b64encode(block).decode()}
        self.journal.parent.mkdir(parents=True,exist_ok=True)
        # Journal first, exclusive: never overwrite any previous backup.
        with self.journal.open('x',encoding='utf-8') as f:
            json.dump(state,f);f.flush();os.fsync(f.fileno())
        safe_path(self.hosts)
        if self.hosts.read_bytes()!=original:raise ValueError('hosts_changed_before_write')
        # Set before write so a partial write leads to explicit recovery attention.
        self.changed=True
        with self.hosts.open('r+b') as f:
            f.write(changed);f.truncate();f.flush();os.fsync(f.fileno())
        if not self.flush():raise ValueError('dns_flush_failed')
        self.at_launch=self.check_resolution()
        if self.at_launch!='loopback_only':raise ValueError('block_resolution_failed')
    def restore(self):
        if not self.journal.exists():return self.restore_status
        try:
            safe_path(self.hosts);safe_path(self.journal)
            if self.journal.stat().st_size>2*1048576:raise ValueError('journal_size')
            r=json.loads(self.journal.read_text(encoding='utf-8'))
            if set(r)!={'schema','original_base64','original_sha256','modified_sha256','block_base64'} or r['schema']!='local-hosts-recovery-1':raise ValueError('journal_schema')
            original=base64.b64decode(r['original_base64'],validate=True);block=base64.b64decode(r['block_base64'],validate=True)
            if len(original)>1048576 or digest(original)!=r['original_sha256'] or digest(original+block)!=r['modified_sha256']:raise ValueError('journal_hash')
            if self.hosts.stat().st_size>2*1048576:raise ValueError('hosts_size')
            current=self.hosts.read_bytes()
            if current==original:
                self.journal.unlink();self.restored=True;self.restore_status='already_original';return self.restore_status
            if digest(current)!=r['modified_sha256']:raise ValueError('hosts_changed_by_other_tool')
            with self.hosts.open('r+b') as f:
                f.write(original);f.truncate();f.flush();os.fsync(f.fileno())
            if self.hosts.read_bytes()!=original:raise ValueError('restore_verification_failed')
            if not self.flush():raise ValueError('restore_dns_flush_failed')
            self.journal.unlink();self.restored=True;self.restore_status='restored_exactly'
        except Exception:self.restore_status='needs_manual_attention_journal_kept'
        return self.restore_status
