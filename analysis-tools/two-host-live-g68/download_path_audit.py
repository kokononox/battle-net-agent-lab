"""Exact public-path lookup only. Never fetch an installer-provided path."""
import json
import hashlib
import re
from pathlib import Path

# Set from the independently acquired, pre-observation public metadata snapshot.
REFERENCE_SHA256 = '31451e27e5d4f4af1d1737315c42ad36b2ee513224dac804ad13b57ab6add65b'

def load_reference(base):
    raw = (Path(base)/'public-download-reference.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != REFERENCE_SHA256:
        raise ValueError('public_path_reference_pin_failed')
    j = json.loads(raw)
    if j.get('installer_input_used') is not False or j.get('runtime_permission') is not False:
        raise ValueError('reference_scope_rejected')
    if not isinstance(j.get('paths'),dict) or len(j['paths']) > 10000:
        raise ValueError('reference_bound')
    return j['paths'], {
        'reference_sha256': REFERENCE_SHA256, 'public_path_count':len(j['paths']),
        'independent_of_installer_input':True, 'runtime_permission':False,
        'archive_ranges_validated':False, 'raw_observed_paths_exported':False}

def classify(path, method, headers, body, public_paths):
    route, sep, query = path.partition('?')
    refs = public_paths.get(route,[])
    exact = bool(refs) and not sep
    # A different spelling, query, trailing slash or appended identifier is not
    # accepted simply because the content hash or prefix looks familiar.
    sizes = {r['public_encoded_bytes'] for r in refs if r.get('public_encoded_bytes') is not None}
    ranges = headers.get('range',[])
    bound = None
    if ranges and len(ranges)==1 and len(sizes)==1:
        m = re.fullmatch(r'bytes=([0-9]+)-([0-9]+)',ranges[0])
        if m:
            lo,hi=map(int,m.groups())
            bound = 0 <= lo <= hi < next(iter(sizes))
        else:
            bound = False
    names = set(headers)
    return {
        'whole_path_exactly_in_independent_public_reference':exact,
        'public_reference_kinds':sorted({r['kind'] for r in refs}) if exact else [],
        'public_reference_products':sorted({r['product'] for r in refs}) if exact else [],
        'query_present':bool(sep), 'method_is_GET':method=='GET',
        'body_empty':not body, 'range_present':bool(ranges),
        'range_inside_public_object_size_if_checkable':bound,
        'range_matches_public_archive_record':False,
        'range_semantics':'not_evaluated_as_fingerprinting_channel' if ranges else 'absent',
        'unexpected_header_names_present':bool(names - {'host','accept','user-agent','range'}),
        'credential_header_present':bool(names & {'cookie','authorization','proxy-authorization'}),
        'verdict':'public_object_selection_observed_not_privacy_clearance' if exact
                  and method=='GET' and not body else 'unknown_requires_more_evidence',
        'raw_path_range_header_values_exported':False,
        'fingerprinting_absence_proven':False}