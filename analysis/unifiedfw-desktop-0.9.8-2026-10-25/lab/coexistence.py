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

def build_coexistence_request(address,port,root=ROOT,inspector=inspect_file,https_url=None):
    https_config=None
    if https_url is None:address,port=endpoint(address,port)
    else:
        from https_common import https_endpoint
        https_config=https_endpoint(https_url,address)
        if type(port) is not int or port!=443:raise ValueError('https_requires_exact_port_443')
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
    result=dict(schema='unifiedfw-coexistence-request-1',address=address,port=port,programs=programs,scope=SCOPE,phases=phases)
    if https_config:result.update(transport='https_php',https_url=https_config['url'],https_host=https_config['host'],https_path=https_config['path'])
    return result

def classify_coexistence(report):
    if report.get('restore_verified') is not True or report.get('firewall_mutation_attempted') is not True or report.get('errors')!=[] or report.get('scope')!=SCOPE or report.get('route_checks_ok') is not True or type(report.get('route_check_count')) is not int or report['route_check_count']<2:
        return dict(outcome='inconclusive',reason='coexistence_scope_or_route_snapshots_not_verified')
    is_https=report.get('transport')=='https_php'
    if report.get('transport') not in (None,'https_php'):return dict(outcome='inconclusive',reason='unsupported_transport')
    if is_https:
        from https_common import https_endpoint
        try:
            https_endpoint(report['endpoint']['https_url'],report['endpoint']['address'])
            if report['endpoint']['port']!=443:raise ValueError('port')
        except (KeyError,TypeError,ValueError):return dict(outcome='inconclusive',reason='invalid_https_report_endpoint')
        phases=report.get('phases')
        if not isinstance(phases,list):return dict(outcome='inconclusive',reason='invalid_https_phases')
        for phase in phases:
            if not isinstance(phase,dict):return dict(outcome='inconclusive',reason='invalid_https_phase')
            for stage in ('during','after_restore'):
                rows=phase.get(stage,[])
                if not isinstance(rows,list):return dict(outcome='inconclusive',reason='invalid_https_matrix')
                for row in rows:
                    if not isinstance(row,dict) or row.get('transport')!='https_php':return dict(outcome='inconclusive',reason='https_transport_not_verified')
                    if row.get('handshake_ok') is True and (row.get('tls_verified') is not True or row.get('http_status')!=200):return dict(outcome='inconclusive',reason='https_TLS_or_HTTP_not_verified')
    # Legacy reports remain readable; every new 0.8.1 HTTPS report declares pacing.
    if is_https and 'https_pacing' in report:
        pacing=report['https_pacing']
        if not isinstance(pacing,dict) or pacing!={'minimum_gap_ms':4000,'automatic_retries':0,'tcp_connect_timeout_seconds':3,'applies_across_matrix_and_restore_boundaries':True}:
            return dict(outcome='inconclusive',reason='invalid_https_pacing_declaration')
        rows=[row for phase in report['phases'] for stage in ('during','after_restore') for row in phase.get(stage,[])]
        for index,row in enumerate(rows):
            if type(row.get('pacing_sequence')) is not int or row['pacing_sequence']!=index:
                return dict(outcome='inconclusive',reason='https_pacing_sequence_invalid')
            gap=row.get('gap_since_previous_probe_ms')
            if (index==0 and gap is not None) or (index>0 and (type(gap) not in (int,float) or not 4000<=gap<1e12)):
                return dict(outcome='inconclusive',reason='https_gap_not_observed')
    result=classify(report,expected=EXPECTED)
    if result['outcome']=='passed':
        result.update(scope=SCOPE,scoped_whitelist_projection_tested=True,blacklist_with_whitelist_projection_tested=True,global_whitelist_tested=False,whitelist_tested=False,vpn_route_verified=False,route_snapshot_guard_passed=True)
        if is_https:result.update(transport='https_php',https_challenge_verified=True,server_reported_peer_is_not_tunnel_proof=True)
    return result
