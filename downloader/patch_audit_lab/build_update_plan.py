"""Offline, bounded update-decision preview. Never a game writer or downloader.

Adapters: existing content-plan SQLite; verified Portable fixture; owned sample
workspace. Only the pinned sample has an executable patch capability. Saved PA
relations alone NEVER authorize a generic patch or establish local possession.
"""
from dataclasses import dataclass, asdict
from collections import Counter, defaultdict
from pathlib import Path
import argparse
import json
import re
import sqlite3
import patch_audit as a
import source_binding as b

@dataclass(frozen=True)
class Target:
    ekey: str
    ckey: str | None
    encoded_size: int
    decoded_size: int | None
    mapped: bool = True
    full_route: bool = False
    local: str = 'unknown'

@dataclass(frozen=True)
class Patch:
    target_ckey: str
    target_size: int
    source_ekey: str
    source_size: int
    patch_key: str
    patch_size: int
    ordinal: int
    source: str = 'unknown'
    patch_local: bool = False
    patch_route: bool = False
    capability: str = 'unproven'

LOCALS = {'unknown','candidate','prior_encoded','decoded_only','fresh_encoded'}
CAPABILITY = 'pinned-single-pair-exact-reencode'
PINNED_TARGET_EKEY = 'faedca88d0a0ab30dae5519239582d31'

def key(value):
    b.need(isinstance(value,str) and re.fullmatch('[0-9a-f]{32}',value),'plan_key')

def integer(value, positive=False):
    b.need(type(value) is int and value >= (1 if positive else 0),'plan_size')

def validate_target(t):
    key(t.ekey); integer(t.encoded_size,True)
    if t.ckey is not None:key(t.ckey)
    if t.decoded_size is not None:integer(t.decoded_size)
    b.need(type(t.mapped)is bool and type(t.full_route)is bool and t.local in LOCALS,'plan_target_state')
    b.need(not t.mapped or (t.ckey is not None and t.decoded_size is not None),'plan_mapped_identity')

def validate_patch(p):
    for v in (p.target_ckey,p.source_ekey,p.patch_key):key(v)
    for v in (p.target_size,p.source_size,p.ordinal):integer(v)
    integer(p.patch_size,True)
    b.need(p.source in LOCALS and type(p.patch_local)is bool and type(p.patch_route)is bool
           and p.capability in ('unproven',CAPABILITY),'plan_patch_state')
    # This capability describes ONE observed PA edge/encoding, not a generic
    # decoder, vendor ordinal policy, or an assertion accepted from JSON input.
    if p.capability==CAPABILITY:
        import staging_sample as s
        b.need(all(getattr(p,k)==v for k,v in s.OPTION.items()),'unsupported_patch_capability')

def decide(t, patches):
    validate_target(t); eligible=[]; diagnostics=Counter()
    for p in patches:
        validate_patch(p)
        b.need((p.target_ckey,p.target_size)==(t.ckey,t.decoded_size),'plan_patch_target_conflict')
        supported=p.capability==CAPABILITY
        if supported:
            b.need(t.ekey==PINNED_TARGET_EKEY and t.encoded_size==158,'unsupported_target_encoding')
        if p.source!='fresh_encoded':diagnostics['source_needs_fresh_full_verification']+=1
        elif not supported:diagnostics['patch_order_and_target_encoding_capability_unproven']+=1
        elif not (p.patch_local or p.patch_route):diagnostics['patch_route_unavailable']+=1
        elif t.mapped:
            eligible.append((0 if p.patch_local else p.patch_size,p.patch_key,p.ordinal,p))
    result={'target_ekey':t.ekey,'target_ckey':t.ckey,'encoded_size':t.encoded_size,
            'decoded_size':t.decoded_size,'local_state':t.local,'patch_options':len(patches),
            'patch_diagnostics':dict(sorted(diagnostics.items())), 'apply_authorized':False,
            'conditional_full_fallback_bytes':t.encoded_size if t.mapped and t.full_route else None}
    if not t.mapped:action='needs_verification';reason='target_mapping_unresolved';cost=None;transfer=None
    elif t.local=='fresh_encoded':action='reuse';reason='fresh_full_encoded_and_decoded_verification';cost=0;transfer=None
    elif t.local=='prior_encoded':action='needs_verification';reason='prior_proof_requires_fresh_target_read';cost=None;transfer=None
    else:
        full_cost=t.encoded_size if t.full_route else None
        best=min(eligible,key=lambda v:v[:3]) if eligible else None
        if best and (full_cost is None or best[0]<full_cost):
            cost,_,_,p=best;action='patch';reason='supported_pinned_edge_smaller_or_only_supported_route'
            transfer=None if p.patch_local else ('patch',p.patch_key,p.patch_size)
            result['selected_patch']={k:getattr(p,k) for k in ('source_ekey','source_size','patch_key','patch_size','ordinal')}
            result['patch_already_verified_locally']=p.patch_local
        elif full_cost is not None:
            action='full_download';reason='conditional_verified_catalogue_route_not_http_tested';cost=full_cost
            transfer=('encoded',t.ekey,t.encoded_size)
        else:action='needs_verification';reason='no_verified_local_target_or_supported_transfer';cost=None;transfer=None
    result.update(action=action,reason=reason,conditional_payload_bytes=cost)
    return result,transfer

def plan(targets, patches, *, target_binding, scope, preview_limit=128):
    b.need(type(preview_limit)is int and 0<=preview_limit<=4096,'plan_preview_limit')
    # This is a code API, not a JSON proof import. Adapters produce the states.
    grouped=defaultdict(list); object_sizes={}
    for p in patches:
        validate_patch(p);grouped[p.target_ckey,p.target_size].append(p)
        k=('patch',p.patch_key)
        b.need(k not in object_sizes or object_sizes[k]==p.patch_size,'transfer_object_size_conflict')
        object_sizes[k]=p.patch_size
    seen={};transfers={};counts=Counter();rows=[];unknown=0;known=0;duplicates=0
    for t in targets:
        validate_target(t)
        b.need(len(seen)<100000 or t.ekey in seen,'bounded_plan_limit')
        if t.ekey in seen:
            b.need(t==seen[t.ekey],'duplicate_target_conflict');duplicates+=1;continue
        seen[t.ekey]=t
        d,transfer=decide(t,grouped[t.ckey,t.decoded_size]);counts[d['action']]+=1
        if d['conditional_payload_bytes'] is None:unknown+=1
        else:known+=d['conditional_payload_bytes']
        if transfer:
            kind,k,size=transfer;identity=(kind,k)
            b.need(identity not in transfers or transfers[identity]==size,'transfer_object_size_conflict')
            transfers[identity]=size
        if len(rows)<preview_limit:rows.append(d)
    total=sum(transfers.values())
    b.need(sum(counts.values())==len(seen),'plan_count_reconciliation')
    return {'format':'readonly-update-decision-plan-1','target':target_binding,'scope':scope,
            'target_objects_evaluated':len(seen),'duplicate_target_rows_ignored':duplicates,
            'actions':dict(sorted(counts.items())),'rows':rows,'rows_omitted':len(seen)-len(rows),
            'unresolved_objects':unknown,'known_payload_bytes_before_shared_object_dedup':known,
            'known_unique_transfer_objects':len(transfers),'known_unique_payload_bytes_subtotal':total,
            'conditional_payload_bytes':None if unknown else total,
            'required_network_download_bytes':None,'http_availability_tested':False,
            'bytes_model':'encoded_or_patch_object_bodies_only;no_HTTP_overhead;no_fallback_reserve',
            'selection_policy':'per_target_minimum_supported_cost;not_global_shared_patch_optimization',
            'not_found_means_missing_or_corrupt':False,'apply_authorized':False,
            'full_game_build_plan':False,'installed_build_detected':False,
            'network_requests':0,'input_files_modified':False,'installation_ready':False}

def saved_plan(plan_path,audit_dir,*,limit=4096,preview_limit=128):
    """Read existing content_plan.build output, no queue success flags imported.

    Intentionally bounded preview of selected target catalogue, not a new
    inventory, complete vendor install closure, or executable acquisition queue.
    """
    b.need(type(limit)is int and 1<=limit<=100000,'bounded_plan_limit')
    w=b.Watch();options,pa,expected=b.load_metadata(audit_dir,w)
    path=w.file(plan_path);db=sqlite3.connect(':memory:',uri=True)
    try:
        db.execute('PRAGMA trusted_schema=OFF');b.attach(db,w,path,'p')
        b.schema(db,'p','plan',('ekey','ckey','encoded_size','decoded_size','mapping_state','transfer_supported','route_kind'))
        binding=b.metadata(db,'p','target_binding')
        b.need(isinstance(binding,dict) and all(binding.get(k)==v for k,v in expected.items()),'plan_exact_target_binding_conflict')
        b.need(b.metadata(db,'p','plan_id')==path.stem,'plan_id_conflict')
        summary=b.metadata(db,'p','plan_summary');total=db.execute('SELECT COUNT(*) FROM p.plan').fetchone()[0]
        b.need(type(summary.get('selected_unique_objects'))is int and total==summary['selected_unique_objects'],'plan_summary_count_conflict')
        b.need(isinstance(summary.get('tag_selection'),dict),'plan_selection_policy_required')
        # Do not trust an arbitrary view, duplicated keys or a corrupted plan.
        b.need(db.execute('SELECT 1 FROM p.plan GROUP BY ekey HAVING COUNT(*)!=1 LIMIT 1').fetchone() is None,'duplicate_plan_ekey')
        def records():
            for ek,ck,es,ds,mapped,supported,route in db.execute('SELECT ekey,ckey,encoded_size,decoded_size,mapping_state,transfer_supported,route_kind FROM p.plan ORDER BY ekey LIMIT ?',(limit,)):
                b.need(isinstance(ek,bytes) and len(ek)==16 and (ck is None or isinstance(ck,bytes) and len(ck)==16),'plan_database_key_shape')
                b.need(type(supported)is int and supported in (0,1),'plan_transfer_flag')
                yield Target(ek.hex(),ck.hex() if ck is not None else None,es,ds,mapped=='mapped',bool(supported and route in ('archive_range','advertised_direct')))
        patches=[Patch(**asdict(o)) for o in options]
        result=plan(records(),patches,target_binding=binding,
                    scope={'kind':'saved_content_plan_bounded_preview','catalogue_unique_objects':total,
                           'requested_object_limit':limit,'evaluated_all_saved_rows':total<=limit,
                           'tag_selection':summary['tag_selection'],'source_inventory':'not_loaded',
                           'saved_queue_success_flags_used':False,'pa_metadata_checksums_verified':True},preview_limit=preview_limit)
        w.check();return result
    finally:db.close()

def portable_plan(root,preview_limit=128):
    import portable_run
    import staging_sample as s
    root=b.safe(root);w=b.Watch()
    # Keep the same file identities before/after full verification and all reads.
    for name in sorted(portable_run.FIXED|{'PORTABLE-MANIFEST.json'}):w.file(root/name)
    proof=portable_run.run(root)
    _,_,binding=b.load_metadata(root/'pinned_metadata',w)
    b.need(any(x.get('exact_target_ekey_reproduced') and x['ekey']==PINNED_TARGET_EKEY for x in proof['encoding_options']),'plan_exact_reencode_required')
    p=Patch(**s.OPTION,source='fresh_encoded',patch_local=True,capability=CAPABILITY)
    t=Target(PINNED_TARGET_EKEY,s.OPTION['target_ckey'],158,33940)
    result=plan([t],[p],target_binding=binding,scope={'kind':'verified_portable_single_pair','source_inventory':'one_fixture_not_game_installation','target_fixture_not_treated_as_installed_encoded_object':True},preview_limit=preview_limit)
    w.check();return result

def workspace_plan(root,preview_limit=128):
    import retail_sample_updater as app
    import staging_sample as s
    import retail_update_cycle as cycle
    with app.locked(root) as (root,origin,oracles):
        state=app.engine.status(root/'cycle',*oracles)
        # status executes the lookup -> direct locked archive -> span -> Python
        # payload verification gate, not merely a persisted success flag.
        published=state['target_published']
        t=Target(cycle.TARGET,s.OPTION['target_ckey'],158,33940,local='fresh_encoded' if published else 'unknown')
        p=Patch(**s.OPTION,source='fresh_encoded',patch_local=True,capability=CAPABILITY)
        # Exact fixture identity is enforced by app/engine and pinned constants.
        binding={'build_config':a.BUILD,'cdn_config':a.CDN,'version':a.VERSION,'product':'wow','region':'eu'}
        result=plan([t],[p],target_binding=binding,scope={'kind':'owned_sample_workspace_single_pair','source_inventory':'owned_research_cycle_not_game_installation','fresh_native_lookup_and_direct_read_gate':True},preview_limit=preview_limit)
        result['target_published']=published;return result

def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='mode',required=True)
    for mode in ('portable','workspace','saved-plan'):
        p=sub.add_parser(mode);p.add_argument('--preview-limit',type=int,default=128)
        if mode=='saved-plan':
            p.add_argument('--plan-db',type=Path,required=True);p.add_argument('--audit-dir',type=Path,required=True);p.add_argument('--object-limit',type=int,default=4096)
        else:p.add_argument('--root',type=Path,required=True)
    x=parser.parse_args()
    try:
        if x.mode=='saved-plan':result=saved_plan(x.plan_db,x.audit_dir,limit=x.object_limit,preview_limit=x.preview_limit)
        else:result=globals()[x.mode+'_plan'](x.root,x.preview_limit)
        print(json.dumps(result,indent=2));return 0
    except (a.AuditError,b.BindingError,OSError,sqlite3.Error,KeyError,TypeError,ValueError):
        print(json.dumps({'status':'stopped_safely','installation_ready':False}));return 1
if __name__=='__main__':raise SystemExit(main())
