"""GUI-independent preparation/session logic. Never installs game content."""
import json
from pathlib import Path
import re
import shutil
import threading
import uuid
import acquisition_runner as runner
import content_plan
import download_inventory
import legacy_reuse
import local_casc
import plan_pipeline
import plan_storage as store
import repair_core as core
import reuse_coordinator as reuse


def new_lab(path):
    return core.Lab.create(runner.external_workspace(path))


def open_lab(path):
    return core.Lab(runner.external_workspace(path))


def parse_limits(objects,mebibytes):
    if not isinstance(objects,str) or not re.fullmatch('[0-9]{1,2}',objects):
        raise core.RepairError('object_limit_must_be_1_to_64')
    if not isinstance(mebibytes,str) or not re.fullmatch('[0-9]{1,4}',mebibytes):
        raise core.RepairError('payload_limit_must_be_1_to_1024_MiB')
    n,b=int(objects),int(mebibytes)
    if not 1<=b<=1024:raise core.RepairError('payload_limit_must_be_1_to_1024_MiB')
    return runner.Limits(max_objects=n,payload_bytes=b*runner.MiB).validate()


def _state_path(lab):return core.safe(lab.root/'objects'/'downloader-ui-session.json')


def save_state(lab,plan,queue):
    plan,queue=store.owned(lab,plan),store.owned(lab,queue)
    core.atomic_json(_state_path(lab),{'format':'queue-downloader-ui-1','plan':plan.name,'queue':queue.name})


def load_state(lab):
    path=_state_path(lab)
    if not path.exists():return None
    state=core.load_json(path)
    if state.get('format')!='queue-downloader-ui-1':raise core.RepairError('ui_session_format_invalid')
    out=[]
    for key,prefix in (('plan','content-plan'),('queue','acquisition-queue')):
        name=state.get(key)
        if not isinstance(name,str) or not re.fullmatch(prefix+r'-[0-9a-f]{32}\.sqlite',name):
            raise core.RepairError('ui_session_owned_filename_required')
        out.append(store.owned(lab,lab.root/'objects'/name))
    return tuple(out)


def report_error(lab,exc):
    info=runner.error_info(exc)
    # Parser failures can expose safe aggregate counts, never raw .build.info
    # tags, account/geoip values or arbitrary exception attributes.
    details=getattr(exc,'safe_profile_tag_diagnostic',None)
    fields={'token_count','optional_suffix_count','known_token_count',
            'account_qualifier_count','geoip_qualifier_count','unknown_plain_count',
            'unknown_optional_count','malformed_token_count'}
    if (isinstance(details,dict) and set(details)==fields and
            all(type(v) is int and 0<=v<=4096 for v in details.values())):
        info['profile_tag_syntax_counts']=dict(details)
    if lab is not None:
        path=core.safe(lab.root/'objects'/('Retail-Queue-UI-Error-to-share-'+uuid.uuid4().hex+'.json'))
        core.atomic_json(path,dict(tool='WoW Queue Download Windows Preview',status='stopped_error',
                                  game_files_modified=False,installation_ready=False,**info))
    return info


def prepare(lab,local_storage=None,legacy_import=None,locales=(),transport=None,cancel=None,notify=lambda _:None):
    """Explicit metadata-network operation; NOT covered by asset batch byte cap.

    Selected local storage is read-only; only ONE bounded local verification batch
    (256 MiB / 4096 candidates) and reuse batch are attempted, then pending remains.
    Default selection includes all DL records and is not a vendor install policy.
    """
    cancel=cancel or threading.Event();core.check(cancel)
    runner.external_workspace(lab.root)
    if shutil.disk_usage(lab.root).free<5*1024**3:raise core.RepairError('metadata_preparation_needs_5_GiB_free_lab_space')
    profile=content_plan.Profile(tuple(locales)).validate() if locales else None
    # No outer lab lock: each existing pipeline step owns its lock. The UI allows
    # only one worker. Immutable outputs bind exact metadata across steps.
    notify({'stage':'metadata','message':'Preparing official EU Download metadata; no game assets.'})
    _,download=download_inventory.prepare_inventory(lab,transport,cancel,lambda s:notify({'stage':'metadata','message':s}))
    result,plan=plan_pipeline.prepare(lab,download,profile,transport,cancel,
                                     lambda s:notify({'stage':'metadata','message':s}))
    local_inputs=[];local_summary=None
    if local_storage is not None:
        _,inv=local_casc.inventory(lab,plan,local_storage,cancel,
                                  lambda s:notify({'stage':'local_read_only','message':s}))
        local_summary,ev=local_casc.verify_batch(lab,plan,inv,cancel=cancel,byte_budget=256*runner.MiB)
        local_inputs=[(inv,ev)]
    _,inventory=reuse.inventory(lab,plan,imports=[legacy_import] if legacy_import else (),
                                local_inputs=local_inputs,cancel=cancel)
    verification,evidence=reuse.verify_batch(lab,plan,inventory,cancel=cancel,byte_budget=256*runner.MiB)
    queue_summary,queue=reuse.make_queue(lab,plan,inventory,evidence,cancel)
    core.check(cancel)
    with lab.lock():save_state(lab,plan,queue)
    report={'tool':'WoW Queue Download Windows Preview','status':'conditional_queue_prepared',
        'target_version':result['target_version'],'queue_summary':queue_summary,
        'local_verification_summary':local_summary,'reuse_verification_summary':verification,
        'user_locale_was_explicit':bool(locales),'default_is_full_catalog_not_exact_installation_diff':not bool(locales),
        'game_files_modified':False,'installation_ready':False}
    path=core.safe(lab.root/'objects'/('Retail-Queue-Prepare-to-share-'+uuid.uuid4().hex+'.json'))
    core.atomic_json(path,report)
    return report,plan,queue


def display_preview(summary):
    next_item=summary.get('next_catalog_candidate')
    pending=summary.get('candidate_rows_pending',0)
    return ('فقط کشِ جدا از بازی — نصب و تعمیر CASC غیرفعال است.\n'
            'تعداد کل اشیای برنامه: '+str(summary.get('target_objects',0))+'\n'
            'encoded قابل‌بازاستفاده: '+str(summary.get('verified_encoded_objects_reusable',0))+'\n'
            'نامزدهای مشروط دریافت: '+str(summary.get('remaining_conditional_transfer_candidates',0))+'\n'
            'نامزدهای ثبت‌شدهٔ ادغامِ هنوز بررسی‌نشده (نه کل بازی): '+str(pending)+'\n'
            'اندازهٔ encoded اولین نامزد کاتالوگ: '+(str(next_item['encoded_size'])+' بایت' if next_item else 'ندارد')+'\n'
            'این اعداد حجم آپدیت لازم تو را مشخص نمی‌کنند؛ صف، مشروط است.\n'
            'کش دانلودهای همین برنامه موقع اجرا دوباره بررسی/از رسید معتبر ادامه داده می‌شود.')
