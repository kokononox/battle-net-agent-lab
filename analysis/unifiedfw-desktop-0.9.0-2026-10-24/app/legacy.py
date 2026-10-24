"""Read-only staging. Never invokes, overwrites or restores either legacy program."""
import ipaddress,json,re
from pathlib import Path
from policy import PolicyError,blacklist_entry,interval

def read_json(path):
    from state import assert_local_tree
    p=assert_local_tree(path)
    if not p.is_file() or p.stat().st_size>1048576:raise PolicyError('legacy_file_missing_or_large')
    return json.loads(p.read_text('utf-8-sig'))

def parse_blacklist(text):
    if not isinstance(text,str) or len(text)>65536:raise PolicyError('legacy_blacklist_text')
    entries=[]
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        match=re.fullmatch(r'(?:\[([^\]]+)\]|([^\s:]+)):(\d{1,5})\s+(TCP|UDP)',line,re.I)
        if not match:raise PolicyError('legacy_blacklist_line_needs_review')
        target=match[1] or match[2];protocol=match[4].upper();port=int(match[3])
        if not 1<=port<=65535:raise PolicyError('legacy_port')
        entries.append((interval(target).text(),protocol,port))
    if len(entries)>256:raise PolicyError('legacy_blacklist_limit')
    return entries

def stage_blacklist(store,settings_path,generation):
    raw=read_json(settings_path)
    if not isinstance(raw,dict) or not isinstance(raw.get('program'),str) or not raw['program']:raise PolicyError('legacy_program_missing')
    parsed=parse_blacklist(raw.get('text',''));checked=store.inspector(raw['program'])
    from policy import windows_path,program_id,path_key
    path=windows_path(checked['path'])
    if path_key(path)!=path_key(raw['program']):raise PolicyError('legacy_program_identity_mismatch')
    p=dict(id=program_id(path),path=path,sha256=checked['sha256'],enabled=True)
    # Check the old recorded hash; do not silently adopt an updated executable.
    if raw.get('program_sha256') and raw['program_sha256']!=p['sha256']:raise PolicyError('legacy_binary_changed_reselect_first')
    entries=[blacklist_entry([p['id']],*e) for e in parsed]
    def change(c):
        existing={x['id']:x for x in c['programs']};existing[p['id']]=p;c['programs']=list(existing.values())
        byid={x['id']:x for x in c['blacklist']};byid.update({x['id']:x for x in entries});c['blacklist']=list(byid.values())
        if not any(x['kind']=='blacklist' for x in c['legacy_imports']):c['legacy_imports'].append(dict(kind='blacklist',rules_may_still_be_active=True))
    return store.update(generation,change)

def stage_whitelist(store,path,generation):
    raw=read_json(path)
    if not isinstance(raw,dict) or raw.get('schema') not in ('sstp-allowlist-config-1','sstp-allowlist-config-2') or not isinstance(raw.get('ip_addresses'),list) or not isinstance(raw.get('domains'),list):raise PolicyError('legacy_whitelist_schema')
    # Domains need explicit DNS consent/snapshot integration. Reject atomically rather
    # than silently importing only IPs and losing the user's domain policy.
    if raw['domains']:raise PolicyError('legacy_domains_need_dns_snapshot_integration; nothing_imported')
    targets=[interval(x).text() for x in raw['ip_addresses']]
    def change(c):
        c['whitelist']=sorted(set(c['whitelist']+targets))
        if not any(x['kind']=='whitelist' for x in c['legacy_imports']):c['legacy_imports'].append(dict(kind='whitelist',rules_may_still_be_active=True))
    return store.update(generation,change)
