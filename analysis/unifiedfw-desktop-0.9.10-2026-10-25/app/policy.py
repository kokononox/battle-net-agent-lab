"""Pure policy compiler. NO Windows firewall operations. All generated rules are proposals."""
from __future__ import annotations
import hashlib, ipaddress as ip, json, ntpath, re
from dataclasses import dataclass

class PolicyError(ValueError): pass
MAX_PROGRAMS=32
MAX_BLACKLIST=256
SPECIAL={4:('0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.0.0.0/24','192.0.2.0/24','192.88.99.0/24','192.168.0.0/16','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/3'),6:('::/96','::ffff:0:0/96','2001::/23','2001:db8::/32','2002::/16','3fff::/20','fc00::/7','fe80::/10','fec0::/10','ff00::/8')}

def canonical_json(obj): return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def digest(obj): return hashlib.sha256(canonical_json(obj).encode()).hexdigest()
def windows_path(text):
    if not isinstance(text,str) or not text or len(text)>32760: raise PolicyError('invalid_program_path')
    text=text.replace('/','\\')
    if not re.match(r'^[A-Za-z]:\\',text) or any(c in text for c in '\x00\r\n*?"<>|') or ':' in text[2:]: raise PolicyError('local_absolute_exe_required')
    pieces=text[3:].split('\\')
    if any(p in ('','.','..') or p.endswith((' ','.')) for p in pieces): raise PolicyError('ambiguous_program_path')
    if any(re.fullmatch(r'(?i)(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?',p) for p in pieces): raise PolicyError('reserved_program_path')
    if ntpath.splitext(text)[1].casefold()!='.exe': raise PolicyError('exe_required')
    return ntpath.normpath(text)
def path_key(text): return windows_path(text).casefold()
def program_id(text): return hashlib.sha256(path_key(text).encode()).hexdigest()[:24]

@dataclass(frozen=True,order=True)
class Interval:
    version:int
    low:int
    high:int
    def text(self):
        cls=ip.IPv4Address if self.version==4 else ip.IPv6Address
        return str(cls(self.low)) if self.low==self.high else f'{cls(self.low)}-{cls(self.high)}'
    def overlaps(self,other): return self.version==other.version and self.low<=other.high and other.low<=self.high

def interval(text,public=True):
    if not isinstance(text,str): raise PolicyError('invalid_address_type')
    text=text.strip()
    if not text or len(text)>160 or re.search(r'\s|%',text): raise PolicyError('invalid_address')
    try:
        if '/' in text:
            if not re.fullmatch(r'.+/(?:0|[1-9][0-9]{0,2})',text): raise ValueError('numeric_prefix_required')
            n=ip.ip_network(text,strict=True); a,b=n.network_address,n.broadcast_address
        elif '-' in text:
            left,right=text.split('-');a,b=ip.ip_address(left),ip.ip_address(right)
        else: a=b=ip.ip_address(text)
        if a.version!=b.version or int(a)>int(b): raise ValueError('invalid_range')
        if (a.version==6 and (a.ipv4_mapped is not None or b.ipv4_mapped is not None)): raise ValueError('mapped_address')
    except ValueError as e: raise PolicyError('invalid_address_or_cidr_host_bits') from e
    v=Interval(a.version,int(a),int(b))
    if public:
        for forbidden in SPECIAL[v.version]:
            n=ip.ip_network(forbidden)
            if v.overlaps(Interval(n.version,int(n.network_address),int(n.broadcast_address))): raise PolicyError('special_use_interval_intersection')
    return v

def merge(values):
    out=[]
    for item in sorted(values):
        if out and item.version==out[-1].version and item.low<=out[-1].high+1:
            out[-1]=Interval(item.version,out[-1].low,max(item.high,out[-1].high))
        else: out.append(item)
    return out

def complement(values,version):
    cursor=0;out=[];limit=(1<<(32 if version==4 else 128))-1
    for item in merge(x for x in values if x.version==version):
        if cursor<item.low: out.append(Interval(version,cursor,item.low-1))
        cursor=item.high+1
    if cursor<=limit: out.append(Interval(version,cursor,limit))
    return out

def cidrs(values,limit=2048):
    out=[]
    for item in merge(values):
        cls=ip.IPv4Address if item.version==4 else ip.IPv6Address
        for n in ip.summarize_address_range(cls(item.low),cls(item.high)):
            # Exact two halves, avoiding provider-specific IPv6 /0 handling.
            out.extend(str(s) for s in (n.subnets(prefixlen_diff=1) if n.prefixlen==0 else [n]))
            if len(out)>limit: raise PolicyError('cidr_rule_limit')
    return out

def whitelist_spec(text):
    if not isinstance(text,str):raise PolicyError('whitelist_string_required')
    parts=text.strip().split('|')
    if len(parts)==1:return dict(target=interval(parts[0]).text(),protocol='Any',port=0,port_end=0)
    if len(parts)!=3 or parts[1].upper() not in ('TCP','UDP','ANY'):raise PolicyError('whitelist_format_target_protocol_ports')
    target=interval(parts[0]).text();proto=parts[1].upper()
    if proto=='ANY':
        if parts[2]!='*':raise PolicyError('whitelist_Any_requires_explicit_star')
        return dict(target=target,protocol='Any',port=0,port_end=0)
    m=re.fullmatch(r'(\d{1,5})(?:-(\d{1,5}))?',parts[2])
    if not m:raise PolicyError('whitelist_port_range')
    first=int(m[1]);last=int(m[2] or m[1])
    if not 1<=first<=last<=65535:raise PolicyError('whitelist_port_range')
    return dict(target=target,protocol=proto,port=first,port_end=last)
def whitelist_text(spec):
    target=interval(spec['target']).text()
    if spec['protocol']=='Any':return target+'|ANY|*'
    return target+'|'+spec['protocol']+'|'+str(spec['port'])+(('-'+str(spec['port_end'])) if spec['port_end']!=spec['port'] else '')
def whitelist_matches(value,endpoint,port,protocol):
    w=whitelist_spec(value)
    return interval(w['target']).overlaps(endpoint) and (w['protocol']=='Any' or (w['protocol']==protocol and w['port']<=port<=w['port_end']))

def new_config():
    return dict(schema='unified-firewall-policy-1',generation=0,mode='blacklist_only',programs=[],whitelist=[],blacklist=[],legacy_imports=[])

def validate(c):
    if not isinstance(c,dict) or set(c)!={'schema','generation','mode','programs','whitelist','blacklist','legacy_imports'} or c.get('schema')!='unified-firewall-policy-1': raise PolicyError('config_schema')
    if type(c['generation']) is not int or c['generation']<0 or c['mode'] not in ('blacklist_only','vpn_allowlist','full_isolation','direct_isolation'): raise PolicyError('config_mode_or_generation')
    if not all(isinstance(c[k],list) for k in ('programs','whitelist','blacklist','legacy_imports')): raise PolicyError('config_arrays')
    if len(c['programs'])>MAX_PROGRAMS or len(c['whitelist'])>256 or len(c['blacklist'])>MAX_BLACKLIST: raise PolicyError('config_limit')
    ids=set();paths=set()
    for p in c['programs']:
        if not isinstance(p,dict) or set(p)!={'id','path','sha256','enabled'}: raise PolicyError('program_schema')
        key=path_key(p['path'])
        if p['id']!=program_id(p['path']) or p['id'] in ids or key in paths or type(p['enabled']) is not bool or not isinstance(p['sha256'],str) or not re.fullmatch('[a-f0-9]{64}',p['sha256']): raise PolicyError('program_identity')
        ids.add(p['id']);paths.add(key)
    for value in c['whitelist']: whitelist_spec(value)
    ruleids=set()
    for e in c['blacklist']:
        if not isinstance(e,dict) or set(e)!={'id','program_ids','target','protocol','port'}: raise PolicyError('blacklist_schema')
        if not isinstance(e['id'],str) or not re.fullmatch('[a-f0-9]{24}',e['id']) or e['id'] in ruleids: raise PolicyError('blacklist_id')
        ruleids.add(e['id']);interval(e['target'])
        if not isinstance(e['program_ids'],list) or not e['program_ids'] or any(not isinstance(p,str) for p in e['program_ids']) or len(set(e['program_ids']))!=len(e['program_ids']) or any(p not in ids for p in e['program_ids']): raise PolicyError('blacklist_program_scope')
        if e['protocol'] not in ('TCP','UDP'): raise PolicyError('blacklist_transport')
        port_span(e['port'])
    for source in c['legacy_imports']:
        if not isinstance(source,dict) or set(source)!={'kind','rules_may_still_be_active'} or source['kind'] not in ('blacklist','whitelist') or source['rules_may_still_be_active'] is not True: raise PolicyError('legacy_import_schema')
    if c['mode']!='blacklist_only' and not c['whitelist']: raise PolicyError('whitelist_empty')
    return c

def port_span(value):
    if type(value) is int and 1<=value<=65535:return value,value
    if isinstance(value,str) and re.fullmatch(r'[1-9][0-9]{0,4}-[1-9][0-9]{0,4}',value):
        first,last=map(int,value.split('-'))
        if 1<=first<last<=65535:return first,last
    raise PolicyError('invalid_port_or_native_range_1_65535')

def port_matches(value,number):
    first,last=port_span(value);return first<=number<=last

def blacklist_entry(program_ids,target,protocol,port):
    if not isinstance(program_ids,list) or not program_ids or any(not isinstance(p,str) for p in program_ids):raise PolicyError('program_selection_required')
    if isinstance(target,str):
        try:
            address=ip.ip_address(target.strip())
            if address.version==6 and address.ipv4_mapped is not None:target=str(address.ipv4_mapped)
        except ValueError:pass
    base=dict(program_ids=sorted(set(program_ids)),target=interval(target).text(),protocol=protocol,port=port)
    return dict(id=digest(base)[:24],**base)

def decision(c,pid,address,port,protocol,interface):
    validate(c)
    if c['mode'] in ('blacklist_only','vpn_allowlist') and pid not in {p['id'] for p in c['programs'] if p['enabled']}: raise PolicyError('selected_enabled_program_required')
    if interface not in ('vpn','outside','unknown') or protocol not in ('TCP','UDP') or type(port) is not int or not 1<=port<=65535: raise PolicyError('invalid_flow')
    endpoint=interval(address,public=False)
    if endpoint.low!=endpoint.high: raise PolicyError('single_destination_required')
    reasons=[]
    if c['mode']=='full_isolation' and interface!='vpn': reasons.append('outside_tunnel_or_unknown_route')
    if c['mode']=='direct_isolation':
        if not any(whitelist_matches(x,endpoint,port,protocol) for x in c['whitelist']): reasons.append('outside_system_whitelist')
    elif c['mode']!='blacklist_only':
        if interface=='unknown': reasons.append('whitelist_route_unknown')
        elif interface=='vpn' and not any(whitelist_matches(x,endpoint,port,protocol) for x in c['whitelist']): reasons.append('outside_vpn_whitelist')
    hits=[e['id'] for e in c['blacklist'] if pid in e['program_ids'] and port_matches(e['port'],port) and e['protocol']==protocol and interval(e['target']).overlaps(endpoint)]
    if hits and not ((c['mode']=='direct_isolation' or c['mode']!='blacklist_only' and interface=='vpn') and any(whitelist_matches(x,endpoint,port,protocol) for x in c['whitelist'])): reasons.append('explicit_program_blacklist')
    return dict(outcome='block' if reasons else 'eligible_not_effectively_verified',reasons=reasons,blacklist_ids=hits,policy_only=True,actual_packet_result='not_measured')

def compile_plan(c,owner):
    validate(c)
    if not re.fullmatch('[a-f0-9]{32}',owner): raise PolicyError('invalid_owner')
    enabled={p['id']:p for p in c['programs'] if p['enabled']}; rules=[];conflicts=[];rule_names=set()
    def add(component,spec):
        spec.update(profile='Any',local_addresses=['Any'],local_port='Any',interface_alias='Any',service='Any',edge_traversal='Block',authentication='NotRequired',encryption='NotRequired',override_block_rules=False)
        ident=digest(dict(component=component,spec=spec))[:24]
        name=f'UnifiedFW-{owner}-{component}-{ident}'
        if name not in rule_names:
            rules.append(dict(name=name,owner=owner,component=component,spec=spec));rule_names.add(name)
    for e in c['blacklist']:
        addresses=cidrs([interval(e['target'])])
        for pid in e['program_ids']:
            if pid not in enabled: continue
            add('blacklist',dict(program_id=pid,program=enabled[pid]['path'],action='Block',direction='Outbound',interface_type='Any',protocol=e['protocol'],port=e['port'],remote_addresses=addresses))
    if c['mode']!='blacklist_only':
        allowed=merge(interval(whitelist_spec(x)['target']) for x in c['whitelist'])
        for version in (4,6):
            blocked=cidrs(complement(allowed,version))
            if blocked and all(whitelist_spec(x)['protocol']=='Any' for x in c['whitelist']):add('whitelist',dict(program_id=None,program='Any',action='Block',direction='Outbound',interface_type='RemoteAccess',protocol='Any',port='Any',remote_addresses=blocked))
        for e in c['blacklist']:
            affected=[p for p in e['program_ids'] if p in enabled]
            if affected and any(interval(e['target']).overlaps(a) for a in allowed):
                conflicts.append(dict(kind='whitelist_exempts_owned_blacklist_inside_VPN',severity='notice',entry_id=e['id'],program_ids=affected,protocol=e['protocol'],port=e['port'],resolution='whitelist_priority_only_inside_selected_VPN; isolation_guard_and_foreign_blocks_are_not_overridden'))
    blockers=['use_dedicated_isolation_backend_for_transport_aware_whitelist_priority','production_firewall_activation_not_enabled','shared_restore_not_windows_tested','legacy_feature_migration_incomplete']
    if c['legacy_imports']:blockers.append('legacy_rules_may_still_be_active; no_automatic_deletion_or_adoption')
    if c['mode']=='full_isolation':blockers+=['sstp_transport_exceptions_unresolved','disconnect_monitor_not_implemented','foreign_allow_management_unimplemented']
    return dict(schema='unified-firewall-plan-1',config_digest=digest(c),owner=owner,rules=rules,overlaps=conflicts,blockers=blockers,activation_allowed=False,policy_scope='whitelist_global_on_RemoteAccess; blacklist_per_selected_executable',no_leak_certified=False,existing_rule_effects='not_loaded_or_verified',hosts_changes=[])

def reconcile_registry(existing,desired,owner,components=('blacklist','whitelist')):
    """Pure dry diff; refuse unowned/altered records. NEVER performs a firewall call."""
    if not re.fullmatch('[a-f0-9]{32}',owner) or not components or not set(components)<= {'blacklist','whitelist'}:raise PolicyError('invalid_reconcile_scope')
    for collection in (existing,desired):
        names=set()
        for r in collection:
            if not isinstance(r,dict) or set(r)!={'name','owner','component','spec'} or r['owner']!=owner or r['component'] not in ('blacklist','whitelist'):raise PolicyError('registry_ownership_conflict')
            name=f"UnifiedFW-{owner}-{r['component']}-{digest(dict(component=r['component'],spec=r['spec']))[:24]}"
            if r['name']!=name or name in names:raise PolicyError('registry_image_conflict')
            names.add(name)
    old={r['name']:r for r in existing if r['component'] in components}
    new={r['name']:r for r in desired if r['component'] in components}
    return dict(create=[new[k] for k in sorted(new.keys()-old.keys())],remove=[old[k] for k in sorted(old.keys()-new.keys())],unchanged=[new[k] for k in sorted(new.keys()&old.keys())],preserved_other_components=[r for r in existing if r['component'] not in components],dry_run_only=True)
