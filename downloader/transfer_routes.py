"""Turn an exact verified-catalog row into a bounded owned-lab fetch spec.

Unknown route kinds fail closed. In particular, archive_range is NOT a direct
EKey request. No direct guesses, host fallback, HTTP or game writes.
"""
import re
import repair_core as core
import plan_storage as store


def spec(target, binding, row):
    if store.binding_id(binding) != ('wow','eu',target.version,target.build_config,target.cdn_config):
        raise core.RepairError('transfer_target_binding_conflict')
    if row['mapping_state'] != 'mapped' or row['transfer_supported'] != 1:
        raise core.RepairError('transfer_object_not_supported')
    if any(not isinstance(row[k],bytes) or len(row[k])!=16 for k in ('ekey','ckey')):
        raise core.RepairError('transfer_full_content_keys_required')
    kind=row['route_kind']
    if kind=='archive_range':
        key=row['archive_key'];offset=row['archive_offset']
        if type(offset) is not int or offset<0:
            raise core.RepairError('catalog_archive_offset_required')
    elif kind=='advertised_direct':
        key=row['ekey'].hex();offset=None
        if row['archive_key'] != '' or row['archive_offset'] is not None:
            raise core.RepairError('catalog_direct_geometry_conflict')
    else:
        raise core.RepairError('unsupported_catalog_route_kind_no_fallback')
    if not isinstance(key,str) or not re.fullmatch('[0-9a-f]{32}',key):
        raise core.RepairError('catalog_archive_key_required')
    if not target.origins or not isinstance(row['index_key'],str) or not re.fullmatch('[0-9a-f]{32}',row['index_key']):
        raise core.RepairError('catalog_provenance_required')
    url=target.origins[0]+'/tpr/wow/data/'+key[:2]+'/'+key[2:4]+'/'+key
    return core.Spec('_retail_/verified-objects/'+row['ekey'].hex()+'.bin',
        row['ckey'].hex(),row['decoded_size'],row['ekey'].hex(),row['encoded_size'],url,offset).validate()
