"""Bounded fresh read-only review of an EXISTING saved Lab inventory.

No scan/migration/download/queue mutation, native game activation or patch write.
Saved fingerprints gate reads; saved success flags never substitute for hashing.
"""
from collections import Counter,defaultdict
from dataclasses import asdict,replace
from pathlib import Path
import argparse,json,os,re,sqlite3,time,uuid,sys
import patch_audit as a
import source_binding as b
import source_check
import refs_source_check as decode
import build_update_plan as planner

MAX_BYTES=32*1024**2
MAX_CHECKS=256
MAX_READS=32

def public_selection(tag):
    """Do not copy arbitrary saved labels/paths/account qualifiers into reports."""
    policies={'all_download_manifest_records','matching_or_unclassified_per_dimension;OR_locales;AND_dimensions'}
    out={'policy':tag.get('policy') if tag.get('policy') in policies else 'saved_policy_not_reproduced',
         'vendor_install_policy_proven':False}
    bits=tag.get('selected_record_bits')
    if type(bits)is int and bits>=0:out['selected_record_bits']=bits
    profile=tag.get('profile')
    locales={'deDE','enUS','esES','esMX','frFR','itIT','koKR','ptBR','ruRU','zhCN','zhTW'}
    if isinstance(profile,dict) and profile.get('platform')=='Windows' and profile.get('architecture')=='x86_64' and profile.get('region')=='EU':
        observed=profile.get('locales')
        if isinstance(observed,list) and observed and all(isinstance(x,str) and x in locales for x in observed):
            out['profile']={'platform':'Windows','architecture':'x86_64','region':'EU','locales':sorted(set(observed))}
    return out

DIAGNOSTICS_VERSION='local-review-diag-3'
PHASES=frozenset(('start','select_lab','validate_arguments','bind_saved_checkpoint',
    'restore_watched_files','validate_saved_snapshot','read_saved_references',
    'load_pinned_metadata','verify_portable_fixture','open_readonly_databases',
    'read_target_plan','verify_target_payloads','verify_patch_sources','assemble_plan',
    'final_input_recheck','prepare_report_output','publication_recheck',
    'create_report_directory','write_pending_report','publish_report_noreplace',
    'postpublication_recheck','complete'))
TRACE_MODULES=frozenset(('__main__','local_review_launcher','local_update_review',
    'source_binding','source_check','patch_audit','portable_run','encoding_target',
    'refs_source_check','build_update_plan','staging_sample','pathlib','pathlib._local',
    'pathlib._abc','genericpath','ntpath','posixpath','os','tkinter',
    'tkinter.filedialog','tkinter.commondialog','sqlite3'))

class Progress:
    def __init__(self):self.stage='start'
    def mark(self,stage):
        b.need(stage in PHASES,'invalid_diagnostic_phase');self.stage=stage

def safe_trace(ex):
    # No exception messages, source lines, filesystem paths or local variables.
    frames=[];tb=ex.__traceback__
    while tb is not None:
        frame=tb.tb_frame;module=frame.f_globals.get('__name__');function=frame.f_code.co_name
        if module in TRACE_MODULES:
            function=function if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,79}',function) else 'internal'
            frames.append({'module':module,'function':function,'line':tb.tb_lineno})
        tb=tb.tb_next
    return frames[-12:]

def public_error(ex,*,stage=None):
    result={'status':'stopped_safely','error_type':type(ex).__name__,'installation_ready':False,
            'diagnostics_version':DIAGNOSTICS_VERSION,
            'stage':stage if stage in PHASES else 'unknown',
            'platform':sys.platform if sys.platform in ('win32','linux','darwin') else 'other',
            'python_version':list(sys.version_info[:3])}
    if isinstance(ex,(a.AuditError,b.BindingError)) and re.fullmatch('[a-z0-9_]{1,100}',str(ex)):
        result['code']=str(ex)
    if isinstance(ex,OSError):
        for field in ('errno','winerror'):
            value=getattr(ex,field,None)
            if type(value)is int:result[field]=value
    result['safe_trace']=safe_trace(ex)
    return result

class Reader:
    def __init__(self,db,snapshot,watch,*,budget=MAX_BYTES,max_reads=MAX_READS,max_checks=MAX_CHECKS,cancel=lambda:False):
        b.need(type(budget)is int and 0<=budget<=MAX_BYTES and type(max_reads)is int and 0<=max_reads<=MAX_READS
               and type(max_checks)is int and 0<=max_checks<=MAX_CHECKS,'review_read_limits')
        self.db=db;self.snapshot=snapshot;self.watch=watch;self.budget=budget
        self.max_reads=max_reads;self.max_checks=max_checks;self.cancel=cancel
        self.spent=self.reads=self.checks=0;self.raw={};self.verified={};self.results={};self.reasons=Counter()
    def verify(self,ekey,decoded_size,encoded_size=None,ckey=None):
        planner.key(ekey);planner.integer(decoded_size,True)
        if encoded_size is not None:planner.integer(encoded_size,True)
        if ckey is not None:planner.key(ckey)
        request=(ekey,decoded_size,encoded_size,ckey)
        if request in self.results:return self.results[request]
        for proof in self.verified.get((ekey,decoded_size),[]):
            if (encoded_size is None or encoded_size==proof['encoded_size']) and (ckey is None or ckey==proof['derived_source_ckey']):
                self.results[request]=True;return True
        if decoded_size>a.MAX_METADATA:
            self.reasons['decoded_size_outside_supported_limit']+=1;self.results[request]=False;return False
        b.need(not self.cancel(),'review_cancelled_or_time_limit')
        rows=self.db.execute('''SELECT c.id,c.ekey,c.archive_id,c.payload_offset,c.encoded_size,c.ckey,c.decoded_size,
                a.name,a.size,a.ambiguous FROM i.candidates c LEFT JOIN i.archives a ON a.archive_id=c.archive_id
                WHERE c.ekey=? ORDER BY c.id LIMIT 65''',(bytes.fromhex(ekey),)).fetchall()
        b.need(len(rows)<=64,'review_source_alias_limit')
        if not rows:self.reasons['outside_saved_candidate_inventory_not_global_absence']+=1
        for cid,ek,aid,offset,es,ck,ds,name,size,ambiguous in rows:
            b.need(not self.cancel(),'review_cancelled_or_time_limit')
            if self.checks>=self.max_checks:
                self.reasons['candidate_check_limit']+=1;break
            self.checks+=1
            valid=(type(cid)is int and type(aid)is int and aid>=0 and type(offset)is int and offset>=0
                   and type(es)is int and 0<es<=8*1024**2 and type(ds)is int and ds==decoded_size
                   and isinstance(ck,bytes) and len(ck)==16 and ek==bytes.fromhex(ekey)
                   and isinstance(name,str) and re.fullmatch(r'data\.[0-9]{3,}',name)
                   and ambiguous==0 and name in self.snapshot['files'] and type(size)is int
                   and size==self.snapshot['files'][name][2] and offset+es<=size
                   and (encoded_size is None or es==encoded_size) and (ckey is None or ck.hex()==ckey))
            if not valid:self.reasons['candidate_metadata_not_compatible']+=1;continue
            location=(name,offset,es)
            if location not in self.raw:
                if self.reads>=self.max_reads or es>self.budget-self.spent:
                    self.reasons['archive_read_budget_or_call_limit']+=1;continue
                path=self.watch.file(Path(self.snapshot['directory'])/name,self.snapshot['files'][name]);before=self.watch.files[path]
                self.watch.check()
                with path.open('rb') as f:
                    b.need(b.fp(os.fstat(f.fileno()))==before,'review_archive_changed')
                    f.seek(offset);raw=f.read(es);self.spent+=len(raw);self.reads+=1
                    b.need(len(raw)==es and b.fp(os.fstat(f.fileno()))==before,'review_archive_short_or_changed')
                self.watch.check();self.raw[location]=raw
            try:
                content,proof=decode.decode_source(self.raw[location],ekey,decoded_size)
            except a.AuditError:
                self.reasons['candidate_payload_not_verified_or_unsupported']+=1;continue
            if a.md5(content)!=ck.hex():
                self.reasons['candidate_ckey_not_verified']+=1;continue
            self.watch.check();self.verified.setdefault((ekey,decoded_size),[]).append(proof)
            self.results[request]=True;return True
        self.results[request]=False;return False
    def report(self):
        return {'archive_payload_bytes_read':self.spent,'archive_read_calls':self.reads,'candidate_checks':self.checks,
                'archive_read_budget_bytes':self.budget,'max_read_calls':self.max_reads,'max_candidate_checks':self.max_checks,
                'fresh_full_ekey_and_decoded_ckey_verified_objects':len(self.verified),
                'candidate_diagnostics_not_corruption_verdicts':dict(sorted(self.reasons.items())),
                'whole_archives_scanned':False,'new_indexes_created':False,'saved_success_flags_used_as_proof':False}

def review(lab,audit_dir,*,portable=None,object_limit=256,preview_limit=128,byte_budget=MAX_BYTES,
           max_reads=MAX_READS,max_checks=MAX_CHECKS,time_limit=120,cancel=lambda:False,progress=lambda _:None):
    progress('validate_arguments')
    b.need(type(object_limit)is int and 1<=object_limit<=4096 and type(time_limit)is int and 1<=time_limit<=600,'review_metadata_limits')
    # Validate budgets before any saved metadata/payload work.
    b.need(type(byte_budget)is int and 0<=byte_budget<=MAX_BYTES and type(max_reads)is int and 0<=max_reads<=MAX_READS
           and type(max_checks)is int and 0<=max_checks<=MAX_CHECKS,'review_read_limits')
    b.need(type(preview_limit)is int and 0<=preview_limit<=4096,'plan_preview_limit')
    started=time.monotonic()
    stopped=lambda:cancel() or time.monotonic()-started>time_limit
    b.need(not stopped(),'review_cancelled_or_time_limit')
    progress('bind_saved_checkpoint')
    binding_report,prior=b.bind(lab,audit_dir,time_limit=time_limit,max_private=1,cancel=stopped)
    progress('restore_watched_files')
    w=b.Watch()
    for row in prior['watched_files']:w.file(row['path'],row['fingerprint'])
    progress('validate_saved_snapshot')
    snapshot=prior['local_storage_snapshot'];w.snapshot(snapshot)
    progress('read_saved_references')
    lab=b.safe(lab);audit_dir=b.safe(audit_dir);state=b.json_object(w.read(lab/'objects/downloader-ui-session.json'))
    record=state['local_review'];objects=lab/'objects'
    plan_path=b.ref(objects,record['plan_file'],'content-plan',w)
    inv_path=b.ref(objects,record['local_inventory'],'local-casc-inventory',w)
    progress('load_pinned_metadata')
    options,_,expected=b.load_metadata(audit_dir,w)
    # bind() already validated every full binding, exact plan/checkpoint and snapshot.
    binding=prior['target'];b.need(binding==binding_report['target'],'review_binding_conflict')
    b.need(all(binding.get(k)==v for k,v in expected.items() if k!='cdn_config') and binding['cdn_config'] in b.OFFLINE_CDN_IDENTITIES,'review_binding_conflict')
    portable_ok=False
    if portable is not None:
        progress('verify_portable_fixture')
        import portable_run
        portable=b.safe(portable)
        for name in sorted(portable_run.FIXED|{'PORTABLE-MANIFEST.json'}):w.file(portable/name)
        fixture=portable_run.run(portable)
        import staging_sample as sample
        portable_ok=fixture['target_ckey']==sample.OPTION['target_ckey'] and any(x.get('exact_target_ekey_reproduced') and x['ekey']=='faedca88d0a0ab30dae5519239582d31' for x in fixture['encoding_options'])
        b.need(portable_ok,'review_portable_capability')
    progress('open_readonly_databases')
    db=sqlite3.connect(':memory:',uri=True)
    try:
        db.execute('PRAGMA trusted_schema=OFF');db.set_progress_handler(lambda:int(stopped()),10000)
        b.attach(db,w,plan_path,'p');b.attach(db,w,inv_path,'i')
        b.schema(db,'p','plan',('ekey','ckey','encoded_size','decoded_size','mapping_state','transfer_supported','route_kind'))
        progress('read_target_plan')
        summary=b.metadata(db,'p','plan_summary');total=db.execute('SELECT COUNT(*) FROM p.plan').fetchone()[0]
        b.need(type(summary.get('selected_unique_objects'))is int and total==summary['selected_unique_objects'] and isinstance(summary.get('tag_selection'),dict),'review_plan_summary')
        b.need(db.execute('SELECT 1 FROM p.plan GROUP BY ekey HAVING COUNT(*)!=1 LIMIT 1').fetchone() is None,'duplicate_plan_ekey')
        targets=[]
        for ek,ck,es,ds,mapping,supported,route in db.execute('SELECT ekey,ckey,encoded_size,decoded_size,mapping_state,transfer_supported,route_kind FROM p.plan ORDER BY ekey LIMIT ?',(object_limit,)):
            b.need(isinstance(ek,bytes) and len(ek)==16 and (ck is None or isinstance(ck,bytes) and len(ck)==16) and type(supported)is int and supported in (0,1),'review_target_row')
            t=planner.Target(ek.hex(),ck.hex() if ck is not None else None,es,ds,mapping=='mapped',bool(supported and route in ('archive_range','advertised_direct')))
            planner.validate_target(t);targets.append(t)
        reader=Reader(db,snapshot,w,budget=byte_budget,max_reads=max_reads,max_checks=max_checks,cancel=stopped)
        # Spend limited reads on current targets FIRST, then sources of unresolved
        # targets. Do not probe every PA source or perform another archive scan.
        progress('verify_target_payloads')
        targets=[replace(t,local='fresh_encoded') if t.mapped and t.decoded_size and reader.verify(t.ekey,t.decoded_size,t.encoded_size,t.ckey) else t for t in targets]
        wanted={(t.ckey,t.decoded_size) for t in targets if t.local!='fresh_encoded' and t.mapped}
        patches=[];source_tries=set()
        progress('verify_patch_sources')
        for option in options:
            b.need(not stopped(),'review_cancelled_or_time_limit')
            if (option.target_ckey,option.target_size) not in wanted:continue
            source_tries.add((option.source_ekey,option.source_size))
            fresh=reader.verify(option.source_ekey,option.source_size)
            capability='unproven';local_patch=False
            if fresh and portable_ok:
                import staging_sample as sample
                matching_encodings={(t.ekey,t.encoded_size) for t in targets if (t.ckey,t.decoded_size)==(option.target_ckey,option.target_size)}
                if asdict(option)==sample.OPTION and matching_encodings=={('faedca88d0a0ab30dae5519239582d31',158)}:
                    capability=planner.CAPABILITY;local_patch=True
            patches.append(planner.Patch(**asdict(option),source='fresh_encoded' if fresh else 'unknown',patch_local=local_patch,capability=capability))
        progress('assemble_plan')
        scope={'kind':'existing_saved_inventory_bounded_fresh_review','catalogue_unique_objects':total,
               'requested_object_limit':object_limit,'evaluated_all_saved_rows':total<=object_limit,
               'tag_selection':public_selection(summary['tag_selection']),'profile_selection_recomputed':False,
               'source_inventory':'saved_target_projected_candidates_not_all_old_patch_bases',
               'patch_source_requests_for_unreused_selected_targets':len(source_tries),
               'whole_installation_or_active_generation_verified':False,
               'cdn_policy':'existing_offline_same_build_download_binding_only;no_route_equivalence_claim',
               'portable_fixture_verified_for_single_edge_only':portable_ok}
        result=planner.plan(targets,patches,target_binding=binding,scope=scope,preview_limit=preview_limit)
        result.update(format='readonly-local-update-review-1',local_verification=reader.report(),
                      prior_full_source_proof_flags_used_for_fresh_decisions=False,
                      consistency_model='saved_file_set_and_stat_fingerprints;not_OS_snapshot_or_hostile_writer_protection')
        progress('final_input_recheck')
        w.check();b.need(not stopped(),'review_cancelled_or_time_limit')
        private={'local_storage_snapshot':snapshot,'watched_files':[{'path':str(p),'fingerprint':fp} for p,fp in w.files.items()],
                 'protected_roots':[str(p) for p in (lab,audit_dir,portable) if p is not None],
                 'closed_databases':[str(p) for p in w.files if p.suffix=='.sqlite']}
        return result,private
    finally:db.close()

def publish_report_noreplace(temp,final):
    """Same-directory publication; never replace an existing destination.

    Windows os.rename uses a no-replace move, unlike POSIX rename. It does not
    require filesystem hardlink support. Do not use os.replace or emulate this
    with an existence check followed by an overwriting rename.
    """
    if sys.platform=='win32':
        os.rename(temp,final)
    else:
        os.link(temp,final)

def publish(lab,report,private,out,*,progress=lambda _:None):
    progress('prepare_report_output')
    out=source_check.output_path(lab,private,out)
    for root in private['protected_roots']:
        p=Path(root);b.need(out!=p and p not in out.parents and out not in p.parents,'review_output_overlaps_input')
    # No report under a recognizable installation, even outside its Data tree.
    for p in (out,*out.parents):b.need(not (p/'.build.info').exists() and not (p/'.build.db').exists(),'review_output_in_game')
    progress('publication_recheck')
    w=b.Watch()
    for row in private['watched_files']:w.file(row['path'],row['fingerprint'])
    w.databases=[Path(p) for p in private['closed_databases']]
    w.snapshot(private['local_storage_snapshot']);w.check()
    progress('create_report_directory')
    out.mkdir(parents=True)
    temp=out/('review-'+uuid.uuid4().hex+'.pending');final=out/'LOCAL-UPDATE-REVIEW-to-share.json'
    published=False
    try:
        progress('write_pending_report')
        with temp.open('x',encoding='utf-8') as f:json.dump(report,f,ensure_ascii=False,indent=2)
        w.check()
        # Atomic no-replace publication inside the newly created report folder.
        progress('publish_report_noreplace')
        publish_report_noreplace(temp,final);published=True
        progress('postpublication_recheck')
        w.check()
    except BaseException:
        if published:final.unlink()
        raise
    finally:
        if temp.exists():temp.unlink()
    # Private provenance never enters public report or uploaded result files.
    return out

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab',type=Path,required=True);p.add_argument('--audit-dir',type=Path,required=True)
    p.add_argument('--portable',type=Path);p.add_argument('--object-limit',type=int,default=256)
    p.add_argument('--preview-limit',type=int,default=128);p.add_argument('--byte-budget',type=int,default=MAX_BYTES)
    p.add_argument('--max-reads',type=int,default=MAX_READS);p.add_argument('--max-checks',type=int,default=MAX_CHECKS)
    p.add_argument('--out-new',type=Path)
    x=p.parse_args();progress=Progress()
    try:
        report,private=review(x.lab,x.audit_dir,portable=x.portable,object_limit=x.object_limit,preview_limit=x.preview_limit,byte_budget=x.byte_budget,max_reads=x.max_reads,max_checks=x.max_checks,progress=progress.mark)
        if x.out_new is not None:publish(x.lab,report,private,x.out_new,progress=progress.mark)
        print(json.dumps(report,ensure_ascii=False,indent=2));return 0
    except KeyboardInterrupt:
        print(json.dumps({'status':'cancelled_safely','installation_ready':False}));return 130
    except (a.AuditError,b.BindingError,OSError,sqlite3.Error,KeyError,TypeError,ValueError) as ex:
        print(json.dumps(public_error(ex,stage=progress.stage)));return 1
if __name__=='__main__':raise SystemExit(main())
