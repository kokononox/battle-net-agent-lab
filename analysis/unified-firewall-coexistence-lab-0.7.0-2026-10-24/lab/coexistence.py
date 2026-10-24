"""Bounded projection of the shared compiler; never production/global activation."""
from pathlib import Path
import copy,json,sys,uuid
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'app'),str(ROOT/'lab')]
from policy import new_config,compile_plan,blacklist_entry,program_id,windows_path,digest,interval
from state import inspect_file
from traffic_common import endpoint,classify
PHASES=(('wl_allows',True,()),('wl_denies',False,()),('wl_allows_bl_A',True,('A',)),('wl_allows_bl_B',True,('B',)),('wl_allows_bl_both',True,('A','B')),('wl_denies_bl_A',False,('A',)))
EXPECTED={'baseline':set(),**{name:(set(bl) if allowed else {'A','B'}) for name,allowed,bl in PHASES}}
SCOPE='two_bundled_images_one_ipv4_one_tcp_port_RemoteAccess_whitelist_projection'

def build_coexistence_request(address,port,root=ROOT,inspector=inspect_file):
    address,port=endpoint(address,port)
    programs=[dict(role=role,id=program_id(path),path=path,sha256=inspector(Path(path)),enabled=True) for role,name in (('A','python.exe'),('B','pythonw.exe')) for path in [windows_path(str(root/'runtime'/name))]]
    owner=uuid.uuid4().hex
    # This address is only policy data; the lab NEVER contacts it.
    sentinel='8.8.8.8' if address!='8.8.8.8' else '8.8.4.4'
    phases=[];target=interval(address)
    for name,allowed,blacklisted in PHASES:
        c=new_config();c.update(mode='vpn_allowlist',programs=[{k:v for k,v in p.items() if k!='role'} for p in programs],whitelist=[address if allowed else sentinel])
        if blacklisted:c['blacklist']=[blacklist_entry([p['id'] for p in programs if p['role'] in blacklisted],address,'TCP',port)]
        full=compile_plan(c,owner);rules=[]
        for original in full['rules']:
            if not any(interval(a,public=False).overlaps(target) for a in original['spec']['remote_addresses']):continue
            selected=programs if original['component']=='whitelist' else [p for p in programs if p['id']==original['spec']['program_id']]
            for p in selected:
                spec=copy.deepcopy(original['spec']);spec.update(program=p['path'],program_id=p['id'],protocol='TCP',port=port,remote_addresses=[address+'/32'])
                ident=digest(dict(component=original['component'],spec=spec))[:24]
                rules.append(dict(name=f"UnifiedFW-{owner}-{original['component']}-{ident}",owner=owner,component=original['component'],spec=spec))
        plan=dict(schema='unified-firewall-plan-1',owner=owner,rules=rules,activation_allowed=False,lab_scope=SCOPE,source_config_digest=digest(c),source_plan_digest=digest(full),no_leak_certified=False)
        phases.append(dict(name=name,request=dict(schema='unified-lab-request-1',mode='vpn_allowlist',legacy_imports=[],legacy_acknowledged=False,programs=c['programs'],plan=plan)))
    return dict(schema='unifiedfw-coexistence-request-1',address=address,port=port,programs=programs,scope=SCOPE,phases=phases)

def classify_coexistence(report):
    if report.get('restore_verified') is not True or report.get('firewall_mutation_attempted') is not True or report.get('errors')!=[] or report.get('scope')!=SCOPE or report.get('route_checks_ok') is not True or type(report.get('route_check_count')) is not int or report['route_check_count']<2:
        return dict(outcome='inconclusive',reason='coexistence_scope_or_route_snapshots_not_verified')
    result=classify(report,expected=EXPECTED)
    if result['outcome']=='passed':
        result.update(scope=SCOPE,scoped_whitelist_projection_tested=True,blacklist_with_whitelist_projection_tested=True,global_whitelist_tested=False,whitelist_tested=False,vpn_route_verified=False,route_snapshot_guard_passed=True)
    return result
