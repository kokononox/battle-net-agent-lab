"""Exact public-path lookup only. Never fetch an installer-provided path."""
import json
import hashlib
import re
from pathlib import Path

# Set from the independently acquired, pre-observation public metadata snapshot.
REFERENCE_SHA256 = '050cedf4d95b863efd41947272513c3670569654646f8ff6017cdcee817942a6'

class Reference(dict):
    pass

def load_reference(base):
    raw = (Path(base)/'public-download-reference.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != REFERENCE_SHA256:
        raise ValueError('public_path_reference_pin_failed')
    j = json.loads(raw)
    if j.get('installer_input_used') is not False or j.get('runtime_permission') is not False:
        raise ValueError('reference_scope_rejected')
    if not isinstance(j.get('paths'),dict) or len(j['paths']) > 10000:
        raise ValueError('reference_bound')
    result=Reference(j['paths'])
    result.ranges=j.get('range_references',{})
    result.origins=j.get('public_key_origins',{})
    result.prefixes={x.rsplit('/',3)[0] for x in result}
    return result, {
        'reference_sha256': REFERENCE_SHA256, 'public_path_count':len(j['paths']),
        'independent_of_installer_input':True, 'runtime_permission':False,
        'range_reference_object_count':len(result.ranges),
        'archive_ranges_validated':False, 'raw_observed_paths_exported':False}

def full_object_size(route, public_paths):
    # Exact whole-path lookup only. Two independent metadata formats must agree
    # for the same product; missing, malformed or conflicting sizes fail closed.
    rows = public_paths.get(route, [])
    kinds = {'public_download_manifest_entry', 'public_encoding_EKey_entry'}
    selected = [r for r in rows if r.get('kind') in kinds]
    if not selected or any(type(r.get('public_encoded_bytes')) is not int or
            not 0 < r['public_encoded_bytes'] <= 2**63-1 for r in selected):
        return None
    sizes = {r['public_encoded_bytes'] for r in selected}
    products = {r.get('product') for r in selected}
    if len(sizes) != 1 or any(not isinstance(p, str) or not p for p in products):
        return None
    if not any({r['kind'] for r in selected if r.get('product') == p} == kinds
               for p in products):
        return None
    return next(iter(sizes))

def range_semantics(route, ranges, public_paths):
    out={'present':bool(ranges),'exact_public_boundary_match':False,
         'public_boundary_basis':[], 'within_single_public_archive_record':False,
         'raw_values_exported':False,'fingerprinting_absence_proven':False}
    if not ranges:
        return out
    if len(ranges)!=1:
        out['status']='multiple_header_values_unknown'
        return out
    m=re.fullmatch(r'bytes=([0-9]{1,20})-([0-9]{1,20})',ranges[0])
    if not m:
        out['status']='unsupported_range_syntax'
        return out
    lo,hi=map(int,m.groups())
    if lo>hi:
        out['status']='reversed_range'
        return out
    ref=getattr(public_paths,'ranges',{}).get(route)
    out['offset_is_zero']=lo==0
    out['length_class']=str(hi-lo+1) if hi-lo+1 in (8,12,4096,65536) else 'other'
    if not ref:
        size = full_object_size(route, public_paths)
        out['full_object_comparison'] = {
            'independent_DL_EN_size_agreement': size is not None,
            'starts_at_zero': lo == 0,
            'end_equals_public_size_minus_one': hi == size-1 if size is not None else None,
            'range_length_equals_public_size': hi-lo+1 == size if size is not None else None}
        if size is not None and lo == 0 and hi == size-1:
            out.update(exact_public_boundary_match=True,
                       public_boundary_basis=['entire_public_object_DL_EN_size_agreement'],
                       status='exact_entire_public_encoded_object')
        else:
            out['status'] = ('not_exact_entire_public_encoded_object' if size is not None
                             else 'no_independent_range_reference')
        return out
    exact=[r for r in ref['ranges'] if r['start']==lo and r['end']==hi]
    if exact:
        out.update(exact_public_boundary_match=True,
                   public_boundary_basis=sorted({r['basis'] for r in exact}),
                   status='exact_public_structure_boundary')
        return out
    archive=[r for r in ref['ranges'] if r['basis']=='complete_verified_archive_record']
    out['within_single_public_archive_record']=any(r['start']<=lo<=hi<=r['end'] for r in archive)
    # Accept a union only if every byte is a whole contiguous verified record;
    # merely lying between two known boundaries is not enough.
    starts={r['start']:r for r in archive}
    at=lo;count=0
    while at in starts and count<128:
        r=starts[at];count+=1;at=r['end']+1
        if at==hi+1:
            out.update(exact_public_boundary_match=True,
                       public_boundary_basis=['contiguous_whole_public_archive_records'],
                       status='exact_public_structure_boundary')
            return out
        if at>hi:
            break
    out['status']='not_an_exact_public_structure_boundary'
    return out

def key_origin(route,public_paths):
    m=re.fullmatch(r'(/tpr/[A-Za-z0-9_-]+/(?:data|patch|config))/([0-9a-f]{2})/([0-9a-f]{2})/([0-9a-f]{32})(\.index)?',route)
    out={'canonical_hash_path_shape':bool(m),'raw_values_exported':False}
    if not m:
        return out
    prefix,a,b,k,suffix=m.groups()
    out.update(canonical_fanout_matches_key=a==k[:2] and b==k[2:4],
               prefix_in_public_reference=prefix in getattr(public_paths,'prefixes',set()),
               suffix_class='index' if suffix else 'none',
               key_public_origins=sorted(getattr(public_paths,'origins',{}).get(k,[])),
               semantic_endpoint_confirmed=False)
    return out

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
    semantics=range_semantics(path,ranges,public_paths)
    return {
        'whole_path_exactly_in_independent_public_reference':exact,
        'public_reference_kinds':sorted({r['kind'] for r in refs}) if exact else [],
        'public_reference_products':sorted({r['product'] for r in refs}) if exact else [],
        'query_present':bool(sep), 'method_is_GET':method=='GET',
        'body_empty':not body, 'range_present':bool(ranges),
        'range_inside_public_object_size_if_checkable':bound,
        'range_matches_public_archive_record':any(x in semantics['public_boundary_basis'] for x in
             ('complete_verified_archive_record','contiguous_whole_public_archive_records')),
        'range_semantics':semantics,
        'public_key_origin_diagnostic':key_origin(route,public_paths),
        'unexpected_header_names_present':bool(names - {'host','accept','user-agent','range'}),
        'credential_header_present':bool(names & {'cookie','authorization','proxy-authorization'}),
        'verdict':'public_object_selection_observed_not_privacy_clearance' if exact
                  and method=='GET' and not body else 'unknown_requires_more_evidence',
        'raw_path_range_header_values_exported':False,
        'fingerprinting_absence_proven':False}