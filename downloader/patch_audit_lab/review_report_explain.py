"""Explain an existing public report OFFLINE. No Lab, payload or proof import.
The input is a user-supplied claim, not evidence authorizing installation.
"""
import argparse,json
from collections import Counter
from pathlib import Path
import source_binding as b

def number(v):b.need(type(v)is int and v>=0,'report_counter_invalid');return v

def explain(q):
    b.need(isinstance(q,dict) and q.get('format')=='readonly-local-update-review-1','report_format')
    actions=q.get('actions');b.need(isinstance(actions,dict) and set(actions)<={'reuse','full_download','patch','needs_verification'},'report_actions')
    total=number(q.get('target_objects_evaluated'));counts={k:number(v) for k,v in actions.items()}
    b.need(sum(counts.values())==total,'report_count_conflict')
    rows=q.get('rows');b.need(isinstance(rows,list) and len(rows)<=4096 and len(rows)+number(q.get('rows_omitted'))==total,'report_preview_count')
    observed=Counter()
    for row in rows:
        b.need(isinstance(row,dict) and row.get('action') in counts,'report_row_action')
        observed[row['action']]+=1
        b.need((row.get('local_state')=='fresh_encoded')==(row['action']=='reuse'),'report_local_claim_conflict')
    b.need(all(v<=counts[k] for k,v in observed.items()),'report_preview_action_conflict')
    v=q.get('local_verification');b.need(isinstance(v,dict),'report_verification_required')
    used=number(v.get('archive_payload_bytes_read'));budget=number(v.get('archive_read_budget_bytes'))
    calls=number(v.get('archive_read_calls'));cap=number(v.get('max_read_calls'))
    b.need(used<=budget and calls<=cap,'report_read_limit_conflict')
    scope=q.get('scope');b.need(isinstance(scope,dict) and isinstance(scope.get('tag_selection'),dict),'report_scope_required')
    for field in ('unresolved_objects','conditional_payload_bytes'):
        if q.get(field) is not None:number(q[field])
    policy=scope['tag_selection'].get('policy')
    if policy not in ('all_download_manifest_records','matching_or_unclassified_per_dimension;OR_locales;AND_dimensions'):
        policy='unknown_saved_policy'
    unknown=total-counts.get('reuse',0)
    return {'format':'offline-local-review-explanation-1','input_claims_only_not_new_content_proof':True,
            'target_objects_evaluated':total,'target_objects_fresh_verified_claimed':counts.get('reuse',0),
            'target_objects_not_fresh_verified':unknown,'conditional_full_download_options_not_missing':counts.get('full_download',0),
            'legacy_unresolved_objects_means_transfer_options_only':q.get('unresolved_objects'),
            'required_network_download_bytes':None,'conditional_payload_bytes_not_required_network':q.get('conditional_payload_bytes'),
            'archive_payload_bytes_read_claimed':used,'read_call_limit_reached':calls==cap,
            'byte_limit_reached':used==budget,'scope_policy':policy,
            'actual_required_install_set_known':False,'prior_results_imported_as_reuse_proof':False,
            'bound_continuation_available':isinstance(q.get('continuation'),dict) and isinstance(q['continuation'].get('next_cursor'),dict),
            'legacy_report_can_be_upgraded_to_bound_cursor_without_Lab':False,
            'network_requests':0,'archive_payload_bytes_read_by_explainer':0,'input_files_modified':False,
            'apply_authorized':False,'installation_ready':False}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--report',type=Path,required=True);x=p.parse_args()
    try:
        w=b.Watch();q=b.json_object(w.read(x.report,limit=4*1024**2));result=explain(q);w.check()
        print(json.dumps(result,indent=2));return 0
    except (b.BindingError,OSError,KeyError,TypeError,ValueError):
        print(json.dumps({'status':'stopped_safely','installation_ready':False}));return 1
if __name__=='__main__':raise SystemExit(main())
