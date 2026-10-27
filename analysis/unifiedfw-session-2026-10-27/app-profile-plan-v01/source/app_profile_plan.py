"""Pure, non-executable application-bound profile plan. No native or file/network I/O.
Untrusted path/hash/config values are draft material, NEVER identity or consent proof.
"""
import hashlib
import ipaddress
import json
import ntpath
import re


class PlanError(ValueError):
    pass


def _keys(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        raise PlanError('profile_plan_shape')


def _id(value):
    if type(value) is not str or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', value):
        raise PlanError('profile_plan_id')
    return value


def _array(value, maximum, code):
    if type(value) is not list or not 1 <= len(value) <= maximum:
        raise PlanError(code)
    return value


def _path(value):
    # Text validation only. Canonical native file identity, ACL, reparse, hard-link,
    # Authenticode, WOW64 and change-after-hash checks remain separate native gates.
    if (type(value) is not str or not 8 <= len(value) <= 260
            or not re.match(r'^[A-Z]:\\', value)
            or any(ord(c) < 32 for c in value)
            or any(c in value for c in '/*?%"<>|')
            or ':' in value[2:] or ntpath.normpath(value) != value):
        raise PlanError('profile_plan_exact_local_exe_path')
    pieces = value[3:].split('\\')
    reserved = {'con', 'prn', 'aux', 'nul'} | {f'{p}{i}' for p in ('com', 'lpt') for i in range(1, 10)}
    if any(not p or p in ('.', '..') or p[-1] in ' .' or p.split('.')[0].casefold() in reserved for p in pieces):
        raise PlanError('profile_plan_exact_local_exe_path')
    if not pieces[-1].lower().endswith('.exe'):
        raise PlanError('profile_plan_exact_local_exe_path')
    if pieces[-1].casefold() in {'svchost.exe', 'rundll32.exe', 'dllhost.exe'}:
        raise PlanError('profile_plan_shared_host_needs_service_scoped_design')
    return value


def _ip(value):
    if type(value) is not str or any(c in value for c in '/%[]*?,') or value.strip() != value:
        raise PlanError('profile_plan_exact_ip')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise PlanError('profile_plan_exact_ip') from None
    if (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified
            or (address.version == 6 and (address.ipv4_mapped or address.is_site_local))
            or (address.version == 4 and (int(address) >> 24 == 0 or int(address) >> 24 >= 224))):
        raise PlanError('profile_plan_unicast_destination')
    # Private destinations are permitted only when explicitly configured; never a LAN exemption.
    return address.compressed


def _normalize(config):
    _keys(config, ('schema', 'generation', 'active_profile_id', 'profiles'))
    if config['schema'] != 'ufw-app-profiles-01':
        raise PlanError('profile_plan_schema')
    if type(config['generation']) is not int or not 1 <= config['generation'] <= 2147483647:
        raise PlanError('profile_plan_generation')
    active = _id(config['active_profile_id'])
    profiles, seen = [], set()
    for p in _array(config['profiles'], 8, 'profile_plan_profile_count'):
        _keys(p, ('id', 'kind', 'programs', 'grants'))
        pid = _id(p['id'])
        if pid in seen:
            raise PlanError('profile_plan_duplicate_profile')
        seen.add(pid)
        if p['kind'] not in ('browser', 'game', 'installer'):
            raise PlanError('profile_plan_kind')
        programs, program_ids, paths = [], set(), set()
        for program in _array(p['programs'], 16, 'profile_plan_program_count'):
            _keys(program, ('id', 'path', 'sha256'))
            ident, path = _id(program['id']), _path(program['path'])
            if ident in program_ids or path.casefold() in paths:
                raise PlanError('profile_plan_duplicate_program')
            pin = program['sha256']
            if type(pin) is not str or not re.fullmatch(r'[a-f0-9]{64}', pin):
                raise PlanError('profile_plan_program_sha256')
            program_ids.add(ident)
            paths.add(path.casefold())
            programs.append(dict(id=ident, path=path, sha256=pin))
        grants, grant_keys, used_programs = [], set(), set()
        for grant in _array(p['grants'], 256, 'profile_plan_grant_count'):
            _keys(grant, ('program_id', 'ip', 'protocol', 'port'))
            ident = _id(grant['program_id'])
            if ident not in program_ids:
                raise PlanError('profile_plan_unknown_program')
            ip = _ip(grant['ip'])
            if type(grant['protocol']) is not str or grant['protocol'] not in ('TCP', 'UDP'):
                raise PlanError('profile_plan_exact_protocol')
            if type(grant['port']) is not int or not 1 <= grant['port'] <= 65535:
                raise PlanError('profile_plan_exact_port')
            key = (ident, ip, grant['protocol'], grant['port'])
            if key in grant_keys:
                raise PlanError('profile_plan_duplicate_grant')
            grant_keys.add(key)
            used_programs.add(ident)
            grants.append(dict(program_id=ident, ip=ip, protocol=grant['protocol'], port=grant['port']))
        if used_programs != program_ids:
            raise PlanError('profile_plan_program_without_grant')
        profiles.append(dict(id=pid, kind=p['kind'], programs=sorted(programs, key=lambda x: x['id']),
                             grants=sorted(grants, key=lambda x: (x['program_id'], x['ip'], x['protocol'], x['port']))))
    if active not in seen:
        raise PlanError('profile_plan_active_missing')
    return dict(schema=config['schema'], generation=config['generation'], active_profile_id=active,
                profiles=sorted(profiles, key=lambda x: x['id']))


BLOCKERS = (
    'live_protected_baseline_revalidation_required',
    'explicit_program_and_destination_review_and_apply_consent_required',
    'native_executable_identity_and_change_detection_not_implemented',
    'foreign_allow_inventory_quarantine_and_effective_policy_not_verified',
    'scoped_rule_transaction_and_native_recovery_not_implemented',
    'approved_exact_sstp_transport_service_filter_not_verified',
    'fresh_sstp_binding_and_disconnect_suspension_not_implemented',
    'dns_certificate_underlay_cold_bootstrap_not_qualified',
    'profile_switch_and_existing_flow_revocation_not_qualified',
    'hostname_resolution_refresh_and_shared_ip_semantics_not_implemented',
    'packet_reboot_and_reconnect_qualification_not_passed',
)


def compile_profile_plan(config):
    """Return non-executable draft; invalid input always yields zero rule templates.

    Only the selected profile contributes rules. Each grant is a program/destination
    edge, not a Cartesian product of programs and destinations. No OS calls occur.
    """
    result = dict(schema='ufw-app-profile-draft-01', input_valid=False, code='profile_plan_invalid_input',
                  normalized_config=None, config_digest=None, active_profile_id=None, application_templates=[],
                  isolation_scope='whole_system', application_scope='active_profile_program_grants_only',
                  default_outbound_intent='Block_all_profiles_not_a_blanket_Block_rule',
                  firewall_disable_requested=False, inactive_profile_rules_included=False,
                  automatic_child_process_permission=False, external_dns_exception_requested=False,
                  sstp_transport_scope='separate_preapproved_exact_service_endpoint_only_never_program_Any',
                  physical_adapter_alias_or_index_used=False, application_identity_verified=False,
                  endpoint_approval_verified=False, baseline_verified_by_this_compiler=False,
                  capture_is_approval=False, mode_switch_atomic=False, native_executor_implemented=False,
                  journal_mutation_requested=False, firewall_mutation_requested=False,
                  plan_executable=False, ready_for_apply=False, no_leak_certified=False,
                  fingerprint_prevention_certified=False, blockers=list(BLOCKERS))
    try:
        normalized = _normalize(config)
        selected = next(p for p in normalized['profiles'] if p['id'] == normalized['active_profile_id'])
        programs = {p['id']: p for p in selected['programs']}
        templates = []
        for grant in selected['grants']:
            program = programs[grant['program_id']]
            templates.append(dict(kind='non_executable_application_rule_template', profile_id=selected['id'],
                                  program_id=program['id'], program_path=program['path'],
                                  unverified_program_sha256=program['sha256'], direction='Outbound', action='Allow',
                                  remote_address=grant['ip'], protocol=grant['protocol'], remote_port=grant['port'],
                                  sstp_binding_token='REQUIRES_FRESH_VERIFIED_SSTP_BINDING',
                                  initial_enabled=False, trusted_native_identity_required=True))
        digest = hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
        result.update(input_valid=True, code='profile_plan_draft_only_no_authority', normalized_config=normalized,
                      config_digest=digest, active_profile_id=selected['id'], application_templates=templates)
    except PlanError as exc:
        result['code'] = str(exc)
    except (TypeError, ValueError, KeyError, AttributeError):
        result['code'] = 'profile_plan_invalid_input'
    return result


def summarize_profile_plan(plan):
    """Diagnostic summary for this compiler's own output, not an imported trusted receipt.
    Raw plans include private paths and IPs and must remain local for real inputs.
    """
    return dict(schema='ufw-app-profile-draft-summary-01', input_valid=plan['input_valid'], code=plan['code'],
                profile_count=len(plan['normalized_config']['profiles']) if plan['input_valid'] else 0,
                active_template_count=len(plan['application_templates']),
                program_scope='active_profile_program_grants_only', blockers=list(plan['blockers']),
                plan_executable=False, ready_for_apply=False, firewall_mutation_requested=False,
                no_leak_certified=False)
