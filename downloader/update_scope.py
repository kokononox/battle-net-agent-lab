"""Offline profile projection + old/new catalogue + existing full local proofs.

A diagnostic scope, NOT a download authorization, exact network size, vendor
selection policy, installed active-generation proof or CASC writer. Common old
catalogue entries are never assumed locally possessed. Original queue/state and
all prior local proof checkpoints remain unchanged.
"""
import re
import shutil
import threading
import content_plan
import downloader_controller as controller
import installed_metadata as installed
import local_casc as local
import local_review
import metadata_delta
import plan_storage as store
import repair_core as core
import reuse_coordinator as reuse

ALLOWED_AVAILABILITY = ('encoded_available', 'decoded_content_only',
                        'conditional_download', 'unresolved_plan')
PLATFORMS = {'Windows', 'OSX'}
ARCHITECTURES = {'x86_32', 'x86_64', 'ARM64'}
REGIONS = {'EU', 'US', 'KR', 'TW', 'CN'}
LOCALES = {'deDE','enUS','enGB','esES','esMX','frFR','itIT','koKR','ptBR',
           'ptPT','ruRU','zhCN','zhTW'}


TAG_DIAGNOSTIC_FIELDS = ('token_count', 'optional_suffix_count', 'known_token_count',
    'account_qualifier_count', 'geoip_qualifier_count', 'unknown_plain_count',
    'unknown_optional_count', 'malformed_token_count')


class ProfileTagError(core.RepairError):
    def __init__(self, reason, counts):
        super().__init__(reason)
        # Counts only, never original labels, identifiers, account/geoip values.
        self.safe_profile_tag_diagnostic = {k:counts[k] for k in TAG_DIAGNOSTIC_FIELDS}


def profile_details(identity):
    """Supported tag grammar, not a vendor expression evaluator.

    A single trailing '?' is recognized as syntax and removed only from KNOWN
    profile/category tokens. Explicit acct-*/geoip-* optional qualifiers are
    counted but never mapped to a region or used for exclusion. This is solely
    an overinclusive diagnostic projection; unknown tags still fail closed.
    Raw labels/qualifier values never enter reports or exception messages.
    """
    raw = identity.row['tags']
    counts = dict.fromkeys(TAG_DIAGNOSTIC_FIELDS, 0)
    if not raw or len(raw)>4096 or any(not clause.strip() for clause in raw.split(':')):
        raise ProfileTagError('update_scope_installed_tags_empty_or_malformed', counts)
    tokens = set()
    for clause in raw.split(':'):
        for token in clause.split():
            counts['token_count'] += 1
            optional = token.endswith('?')
            counts['optional_suffix_count'] += int(optional)
            name = token[:-1] if optional else token
            if re.fullmatch(r'[A-Za-z0-9_]+', name) and name in installed.TAG_VALUES:
                counts['known_token_count'] += 1; tokens.add(name)
            elif optional and re.fullmatch(r'acct-[A-Za-z0-9_]{1,32}', name):
                counts['account_qualifier_count'] += 1
            elif optional and re.fullmatch(r'geoip-[A-Za-z0-9_]{1,32}', name):
                counts['geoip_qualifier_count'] += 1
            else:
                counts['unknown_optional_count' if optional else 'unknown_plain_count'] += 1
                if not re.fullmatch(r'[A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)*', name):
                    counts['malformed_token_count'] += 1
    if counts['unknown_optional_count'] or counts['unknown_plain_count']:
        raise ProfileTagError('update_scope_unknown_installed_tag_no_guess', counts)
    choices = [tokens & values for values in (PLATFORMS, ARCHITECTURES, REGIONS)]
    if any(len(v) != 1 for v in choices) or not tokens & LOCALES:
        raise ProfileTagError('update_scope_installed_profile_missing_or_ambiguous', counts)
    platform, architecture, region = (next(iter(v)) for v in choices)
    profile = content_plan.Profile(tuple(sorted(tokens & LOCALES)), platform, architecture, region)
    try:
        profile.validate()  # Currently Windows x86_64 EU; unsupported => no fallback.
    except core.RepairError:
        raise ProfileTagError('unsupported_plan_profile', counts) from None
    return profile, counts


def installed_profile(identity):
    return profile_details(identity)[0]


def _selected(db, alias, input_db, mask, policy, cancel, notify):
    db.execute('CREATE TEMP TABLE '+alias+'(ekey BLOB PRIMARY KEY,encoded_size INTEGER NOT NULL) WITHOUT ROWID')
    pending = []; selected_rows = 0
    for ordinal, ek, size in input_db.execute('SELECT ordinal,ekey,encoded_size FROM entries ORDER BY ordinal'):
        if ordinal % 4096 == 0:
            core.check(cancel)
            notify({'stage':'profile_metadata_selection','catalogue':alias,
                    'records_processed':ordinal,'network_requests':0})
        if mask[ordinal // 8] & (0x80 >> (ordinal % 8)):
            pending.append((ek,size)); selected_rows += 1
        if len(pending) >= 4096:
            db.executemany('INSERT OR IGNORE INTO '+alias+' VALUES (?,?)',pending); pending.clear()
    if pending: db.executemany('INSERT OR IGNORE INTO '+alias+' VALUES (?,?)',pending)
    if selected_rows != policy['selected_record_bits']:
        raise core.RepairError('update_scope_selected_bitmap_count_mismatch')


def project(workspace,old_path,target_path,lab,plan_path,queue_path,profile,
            cancel=None,notify=lambda _:None):
    """Write a separate non-executable scope table; never replace active queue."""
    cancel = cancel or threading.Event(); core.check(cancel); profile.validate()
    old_path,target_path = (store.owned(workspace,p) for p in (old_path,target_path))
    plan_path,queue_path = (store.owned(lab,p) for p in (plan_path,queue_path))
    reuse.checked_queue(lab,plan_path,queue_path)
    if shutil.disk_usage(workspace.root).free < max(1024**3,3*(old_path.stat().st_size+target_path.stat().st_size)):
        raise core.RepairError('update_scope_insufficient_workspace_space')
    with store.input_db(workspace,old_path) as (old,_), \
            store.input_db(workspace,target_path) as (new,binding), \
            store.input_db(lab,plan_path,binding) as (plan,_), \
            store.input_db(lab,queue_path,binding) as (queue,_), \
            store.Writer(workspace,'update-scope',cancel) as out:
        for p in (old_path,target_path,plan_path,queue_path):out.watch(p)
        target_ck = local._meta(new,'manifest_ckey')
        if binding.get('download_ckey') != target_ck:
            raise core.RepairError('update_scope_target_manifest_binding_conflict')
        if local._meta(plan,'target_binding').get('download_ckey') != target_ck:
            raise core.RepairError('update_scope_plan_download_identity_conflict')
        db = out.db
        for alias,path in (('o',old_path),('n',target_path),('q',queue_path)):
            db.execute('ATTACH DATABASE ? AS '+alias,(path.as_uri()+'?mode=ro',))
        masks=[];policies=[]
        for source in (old,new):
            # Assert supported kind/name assignment; never infer a kind by name
            # if a format/build uses a different tagging model.
            for name,kind in source.execute('SELECT name,kind FROM tags'):
                expected=next((i for i,values in enumerate((PLATFORMS,ARCHITECTURES,LOCALES,REGIONS),1) if name in values),None)
                if expected is not None and kind not in (expected,expected|0x4000):
                    raise core.RepairError('update_scope_tag_kind_model_unsupported')
            mask,policy=content_plan.selection_mask(source,profile)
            masks.append(mask);policies.append(policy)
        for alias,source,mask,policy in zip(('old_selected','new_selected'),(old,new),masks,policies):
            _selected(db,alias,source,mask,policy,cancel,notify)
        core.check(cancel)
        notify({'stage':'profile_scope_join_existing_local_proofs','network_requests':0})
        if db.execute('''SELECT 1 FROM new_selected s LEFT JOIN q.queue q USING(ekey)
                WHERE q.ekey IS NULL OR s.encoded_size!=q.encoded_size LIMIT 1''').fetchone():
            raise core.RepairError('update_scope_target_queue_missing_or_size_conflict')
        if db.execute('SELECT 1 FROM q.queue WHERE availability NOT IN (?,?,?,?) OR availability IS NULL LIMIT 1',ALLOWED_AVAILABILITY).fetchone():
            raise core.RepairError('update_scope_unknown_queue_availability')
        db.executescript('''CREATE TEMP TABLE old_catalogue AS SELECT ekey,encoded_size FROM o.objects;
            CREATE UNIQUE INDEX old_catalogue_key ON old_catalogue(ekey);
            CREATE TABLE scope(ekey BLOB PRIMARY KEY,encoded_size INTEGER NOT NULL,
                change_class TEXT NOT NULL,availability TEXT NOT NULL,
                conditional_transfer INTEGER NOT NULL) WITHOUT ROWID;
            INSERT INTO scope SELECT s.ekey,s.encoded_size,
                CASE WHEN a.ekey IS NULL THEN 'added_to_catalogue'
                     WHEN p.ekey IS NULL THEN 'common_catalogue_new_to_profile'
                     ELSE 'retained_profile' END,
                q.availability,q.conditional_transfer
                FROM new_selected s LEFT JOIN old_catalogue a USING(ekey)
                LEFT JOIN old_selected p USING(ekey) JOIN q.queue q USING(ekey);''')
        # A data integrity conflict is not a new-download requirement.
        if db.execute('SELECT 1 FROM new_selected n JOIN old_catalogue o USING(ekey) WHERE n.encoded_size!=o.encoded_size LIMIT 1').fetchone():
            raise core.RepairError('update_scope_old_target_shared_size_conflict')
        rows=[]
        for change,avail,count,total,conditional in db.execute('''SELECT change_class,availability,COUNT(*),SUM(encoded_size),
                SUM(CASE WHEN conditional_transfer=1 THEN encoded_size ELSE 0 END)
                FROM scope GROUP BY change_class,availability ORDER BY change_class,availability'''):
            rows.append({'change_class':change,'availability':avail,'objects':count,
                         'full_encoded_bytes':total,'conditional_full_encoded_body_bytes':conditional})
        selected = db.execute('SELECT COUNT(*) FROM new_selected').fetchone()[0]
        all_target = local._meta(new,'inventory_summary')['unique_encoded_objects']
        # Independent count from original entries + mask UDF, not the projection
        # tables/join. SQLite DISTINCT keeps a disk-backed set instead of a
        # million-key Python set. Full-scale test also checks raw binary directly.
        db.create_function('selected_ordinal',1,lambda ordinal:int(bool(masks[1][ordinal//8] & (0x80>>(ordinal%8)))))
        independent = db.execute('SELECT COUNT(DISTINCT ekey) FROM n.entries WHERE selected_ordinal(ordinal)=1').fetchone()[0]
        if selected!=sum(r['objects'] for r in rows) or selected!=independent or selected>all_target:
            raise core.RepairError('update_scope_independent_reconciliation_failed')
        added_check = db.execute('''SELECT COUNT(*) FROM (SELECT ekey FROM new_selected
                EXCEPT SELECT ekey FROM old_catalogue)''').fetchone()[0]
        if added_check!=sum(r['objects'] for r in rows if r['change_class']=='added_to_catalogue'):
            raise core.RepairError('update_scope_new_key_reconciliation_failed')
        unproven_new = [r for r in rows if r['change_class']!='retained_profile' and r['availability']!='encoded_available']
        unproven_common = [r for r in rows if r['change_class']=='retained_profile' and r['availability']!='encoded_available']
        result={'policy':policies[1],
            'profile_source':'whitelisted_active_build_info_tags;Windows_x86_64_EU_supported_only',
            'locale_clause_relationships':'union_all_observed_locales;may_overinclude',
            'category_and_alternate_tags_used_for_exclusion':False,
            'unclassified_records_preserved_per_dimension':True,
            'vendor_install_policy_proven':False,'scope_is_download_authorization':False,
            'all_target_catalogue_objects':all_target,'profile_selected_unique_objects':selected,
            'excluded_from_this_profile_projection_objects':all_target-selected,
            'breakdown':rows,
            'newly_selected_without_encoded_proof_objects':sum(r['objects'] for r in unproven_new),
            'newly_selected_without_encoded_proof_full_bytes':sum(r['full_encoded_bytes'] for r in unproven_new),
            'retained_profile_without_encoded_proof_objects':sum(r['objects'] for r in unproven_common),
            'retained_common_objects_not_assumed_present':True,
            'unsupported_or_encrypted_not_classified_as_corrupt':True,
            'decoded_only_not_subtracted_as_encoded':True,
            'independent_reconciliation_passed':True,
            'patch_savings_applied':False,'target_is_latest_online_proven':False,
            'availability_source':'exact_saved_queue;new_download_session_cache_not_merged_here',
            'existing_queue_or_proof_checkpoints_modified':False,
            'asset_payloads_reread':False,'network_requests':0,
            'required_network_download_bytes':None,'installation_ready':False}
        core.check(cancel);reuse.checked_queue(lab,plan_path,queue_path)
        out.metadata('target_binding',binding);out.metadata('source_plan_id',local._meta(plan,'plan_id'))
        out.metadata('scope_summary',result)
    return result


def plan_from_queue(lab,plan_path,queue_path,cancel=None,notify=lambda _:None):
    """Use exact saved active queue, fail if local proofs have not been merged."""
    cancel=cancel or threading.Event();core.check(cancel)
    plan_path,queue_path=(store.owned(lab,p) for p in (plan_path,queue_path))
    state_path=controller._state_path(lab)
    state_fp=core.fingerprint(core.regular(state_path).stat())
    plan_fp=core.fingerprint(plan_path.stat());queue_fp=core.fingerprint(queue_path.stat())
    def check():
        core.check(cancel)
        if core.fingerprint(core.regular(state_path).stat())!=state_fp or controller.load_state(lab)!=(plan_path,queue_path):
            raise core.RepairError('update_scope_active_session_changed')
        if core.fingerprint(core.regular(plan_path).stat())!=plan_fp or core.fingerprint(core.regular(queue_path).stat())!=queue_fp:
            raise core.RepairError('update_scope_queue_or_plan_changed')
        if local_review.queue_needs_refresh(lab):
            raise core.RepairError('update_scope_refresh_existing_local_proofs_first')
        reuse.checked_queue(lab,plan_path,queue_path)
    check()
    with store.input_db(lab,queue_path) as (q,_):
        snapshots=local._meta(q,'source_snapshot')['local_snapshots']
        if len(snapshots)!=1:raise core.RepairError('update_scope_requires_one_recorded_storage')
        storage=core.safe(snapshots[0]['directory'])
    # Reject unsupported profile before metadata extraction or workspace writes.
    identity=installed.read(storage.parent.parent,cancel);profile,tag_counts=profile_details(identity)
    def analyze(workspace,old,new,actual_identity,event,notice):
        check();identity.check()
        if installed_profile(actual_identity)!=profile:raise core.RepairError('update_scope_installed_profile_changed')
        r=project(workspace,old,new,lab,plan_path,queue_path,profile,event,notice)
        r['installed_tag_syntax_counts']=tag_counts
        r['account_geoip_qualifiers_used_for_selection']=False
        check();identity.check();return r
    return metadata_delta.plan(lab,plan_path,storage,cancel,notify,
                               scope_analyzer=analyze,publication_check=check)
