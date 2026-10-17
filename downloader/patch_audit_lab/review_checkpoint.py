"""Position-only continuation, bound to unchanged saved inputs. Never a proof cache.

The SHA-256 is an input-identity comparison, NOT a signature or hostile-writer
protection. Editing a position never establishes verified content or install scope.
"""
import hashlib,json,re
import source_binding as b
FORMAT='readonly-review-position-1'

def binding(prior):
    obj={'contract':FORMAT,'target':prior['target'],'plan_id':prior['plan_id'],
         'snapshot_id':prior['snapshot_id'],'snapshot':prior['local_storage_snapshot'],
         'files':sorted(prior['watched_files'],key=lambda row:row['path'])}
    return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def position(identity,after=None):
    return {'format':FORMAT,'input_binding':identity,'after_ekey':after}

def validate(value,identity):
    b.need(isinstance(value,dict) and set(value)=={'format','input_binding','after_ekey'},'continuation_cursor_shape')
    b.need(value['format']==FORMAT and isinstance(value['input_binding'],str)
           and re.fullmatch('[0-9a-f]{64}',value['input_binding']) and value['input_binding']==identity,'continuation_inputs_changed')
    after=value['after_ekey']
    b.need(after is None or isinstance(after,str) and re.fullmatch('[0-9a-f]{32}',after),'continuation_cursor_key')
    return after

def from_report(report,identity):
    b.need(report.get('format')=='readonly-local-update-review-1','continuation_report_format')
    section=report.get('continuation')
    b.need(isinstance(section,dict) and 'next_cursor' in section,'legacy_report_has_no_bound_continuation')
    # Ignore ALL old object states, counters, success flags and payload proofs.
    return validate(section['next_cursor'],identity)

def selection_status(sanitized):
    policy=sanitized.get('policy')
    if policy=='all_download_manifest_records':status='all_manifest_records_not_install_profile'
    elif policy=='matching_or_unclassified_per_dimension;OR_locales;AND_dimensions' and 'profile' in sanitized:status='saved_profile_projection_not_active_install_proof'
    else:status='saved_install_profile_not_established'
    return {'status':status,'active_installed_profile_verified':False,
            'vendor_install_policy_proven':False,'actual_required_install_set_known':False,
            'profile_guessed':False,'game_build_info_read':False,
            'missing_evidence':['active_installed_profile_not_established_in_this_review',
                                'no_recomputed_target_Download_tag_projection_in_this_review'],
            'new_install_profile_filter_applied':False}
