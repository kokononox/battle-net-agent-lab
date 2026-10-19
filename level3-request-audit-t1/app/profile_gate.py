"""Read-only DNS precondition. Accept Windows NO_DATA only with explicit HOSTS sink."""
import ipaddress
import os
from pathlib import Path
import socket
import sys
from hosts_guard import safe_path

NO_DATA_WITH_EXPLICIT_SINK='explicit_hosts_sink_windows_no_data'

def classify_addresses(addresses):
    try:ips={ipaddress.ip_address(a) for a in addresses}
    except ValueError:return 'invalid_address'
    if not ips:return 'no_addresses'
    if all(a.is_loopback or a.is_unspecified for a in ips):return 'sink_only'
    if all(a.is_global for a in ips):return 'public_only'
    return 'mixed_or_nonpublic'

def explicit_zero_sink_hosts(path,names):
    """Require a real 0.0.0.0 entry, and reject any conflicting/invalid address."""
    entries={h:[] for h in names}
    try:
        path=safe_path(path)
        with path.open('rb') as f:data=f.read(1048577)
        if len(data)>1048576 or b'\x00' in data:return set()
        text=data.decode('utf-8-sig')
        for line in text.splitlines():
            parts=line.partition('#')[0].split()
            if len(parts)<2:continue
            for token in parts[1:]:
                h=token.lower().rstrip('.')
                if h in entries:entries[h].append(parts[0])
    except (OSError,UnicodeError,ValueError):return set()
    accepted=set()
    for h,values in entries.items():
        if '0.0.0.0' not in values:continue
        try:ips=[ipaddress.ip_address(a) for a in values]
        except ValueError:continue
        if all(a.is_loopback or a.is_unspecified for a in ips):accepted.add(h)
    return accepted

def resolution_probe(blocked,target,hosts_path=None,resolver=None,platform=None):
    resolver=resolver or socket.getaddrinfo;platform=sys.platform if platform is None else platform
    if hosts_path is None:
        hosts_path=Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32/drivers/etc/hosts'
    explicit=explicit_zero_sink_hosts(hosts_path,blocked)
    result={}
    for h in (*blocked,target):
        try:result[h]=classify_addresses(x[4][0] for x in resolver(h,None,0,socket.SOCK_STREAM))
        except socket.gaierror as exc:
            # Windows 11004 by itself is NOT block proof. The narrow branch below
            # needs an exact HOSTS zero sink with no contradictory address too.
            result[h]=NO_DATA_WITH_EXPLICIT_SINK if platform=='win32' and exc.errno==11004 and h in explicit and h!=target else 'resolution_failed'
        except OSError:result[h]='resolution_failed'
    return result

def check_profile(states,blocked,target):
    return set(states)==set((*blocked,target)) and all(states[h] in {'sink_only',NO_DATA_WITH_EXPLICIT_SINK} for h in blocked) and states[target]=='public_only'
