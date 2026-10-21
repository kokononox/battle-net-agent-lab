"""Build an explicitly shared analysis bundle; never copy raw private state or change firewall policy."""
import hashlib,ipaddress,json,os,re,zipfile
from pathlib import Path
from capture_store import utc_now,STAGES,stage_identity,stage_codes
MAX_CAPTURES=50
MAX_RECORDS=20000
def record_count(capture):return len(capture['endpoints'])+len(capture.get('event_evidence',{}).get('events',[]))

def snapshot_text(snapshot):
 if snapshot.get('available') is not True:return '# UNVERIFIED / UNAVAILABLE: do not interpret as an empty active blacklist.\n'
 lines=['# Verified rule configuration snapshot, not proof of packet drops.','# Scope: this installation and the selected Wow executable only.','# Checked UTC: '+str(snapshot.get('checked_utc',''))]
 for e in snapshot.get('entries',[]):
  target='['+e['ip']+']' if ':' in e['ip'] else e['ip'];lines.append(target+':'+str(e['port'])+' '+e['protocol'])
 return '\n'.join(lines)+'\n'

def readable(report):
 lines=['WoW — گزارش تحلیلی رصدها','زمان خروجی UTC: '+report['exported_utc'],'این گزارش شواهد نمونه‌برداری و برچسب دستی است، نه اثبات افت بسته یا هویت دامنه.','', '=== ۱. بلک‌لیست فعال تأییدشده در زمان خروجی ===',snapshot_text(report['active_blacklist_at_export']), '=== ۲. لیست ذخیره‌شده؛ الزاماً فعال نیست ===',report['saved_desired_blacklist'].get('text','[نامعتبر / در دسترس نیست]'),'', '=== ۳. پیش‌نویس جدول؛ الزاماً ذخیره یا اعمال نشده ===',report['editor_draft'].get('text','[وارد خروجی نشده]'),'', '=== ۴. رصدها و وضعیت قوانین در زمان ضبط ===']
 for capture in report['captures']:
  lines+=['','--- ضبط: '+capture['capture_id']+' ---','شروع UTC: '+capture['capture_started_utc']+' | پایان UTC: '+capture['capture_ended_utc'],'مدت: '+str(capture['seconds'])+' | خطای خواندن: '+str(capture['query_errors'])+' | ضبط ناقص: '+str(capture['truncated']),'رکوردهای حذف‌شده و خارج از این خروجی: '+str(capture.get('deleted_record_count',0)),'Block در شروع ضبط:',snapshot_text(capture['block_snapshot_start']),'Block در پایان ضبط:',snapshot_text(capture['block_snapshot'])]
  lines+=['مرحلهٔ جاری: انتخاب کاربر، نه تشخیص بازی؛ وضعیت: '+capture.get('phase_recording',{}).get('status','not_recorded')+' | خطای journal مرحله: '+str(capture.get('phase_recording',{}).get('read_errors',0))]
  for transition in capture.get('phase_recording',{}).get('transitions',[]):lines+=['  '+transition['selected_utc']+' -> '+STAGES[transition['stage']]]
  for row in capture['endpoints']:
   lines+=['  مرحله‌های نمونه‌برداری تحت انتخاب کاربر: '+', '.join(STAGES[x] for x in row.get('phase_context',{}).get('stages',[]))]
   for code,hit in row.get('phase_context',{}).get('sample_hits',{}).items():lines+=['    '+STAGES[code]+' | نمونه: '+str(hit['samples'])+' | اول/آخر UTC: '+hit['first_seen_utc']+' / '+hit['last_seen_utc']+' | حضور پیوسته اثبات نشده']
   ptr=row['ptr'];context=row['context'];states=', '.join(k+'='+str(v) for k,v in row['state_samples'].items())
   lines+=['  مقصد: '+row['ip']+':'+str(row['port'])+' '+row['protocol']+' | PID: '+str(row['pid']),'  سابقهٔ مقصد: '+{'previously_seen':'قدیمی؛ قبلاً رصدشده','first_in_local_history':'تازه در سابقهٔ محلی','history_uncertain':'سابقه نامطمئن'}.get(row.get('destination_history'),'سابقه ثبت نشده')+' | شمارهٔ کشف در این ضبط: '+str(row.get('discovery_sequence','ثبت نشده')),'  مرحله همین ضبط: '+context.get('current_label',context['label'])+' | سابقه ضبط‌های دیگر: '+', '.join(STAGES[x] for x in context.get('history_stages',[]))+' | منبع برچسب: '+context['source']+' | زمان ثبت دستی UTC: '+context['annotated_utc'],'  شروع فرایند UTC: '+row['process_started_utc']+' | فرایند تازه: '+str(row['fresh_process_seen']),'  اولین/آخرین مشاهده UTC: '+row['first_seen_utc']+' / '+row['last_seen_utc'],'  حالت‌ها: '+states+' | دفعات مشاهده: '+str(row['samples']),'  تطابق Block پایان ضبط: '+str(row['covered_by_verified_block'])+' | افت بسته تأیید نشده','  PTR: '+ptr['status']+' | '+', '.join(ptr['names'])+' | زمان UTC: '+str(ptr.get('checked_utc_epoch','')),'']
  evidence=capture.get('event_evidence',{})
  lines+=['  === شواهد رویدادهای DNS / منع اتصال ===','  وضعیت منابع: '+json.dumps(evidence.get('streams',{}),ensure_ascii=False),'  نبود رویداد، نبود تلاش یا مجازبودن را ثابت نمی‌کند. نگاشت hosts، اثبات مسدودشدن واقعی نیست.']
  for e in evidence.get('events',[]):
   lines+=['  مرحلهٔ جاری در زمان رویداد: '+', '.join(STAGES[x] for x in e.get('phase_context',{}).get('stages',[]))]
   lines+=['  زمان UTC: '+e['observed_utc']+' | PID: '+str(e['pid'])+' | منبع: '+e['source']+' | مرحله همین ضبط: '+e['context'].get('current_label',e['context']['label'])+' | سابقه دیگر: '+', '.join(STAGES[x] for x in e['context'].get('history_stages',[]))]
   if e['kind']=='dns_query':lines+=['  درخواست DNS ثبت‌شده: '+e['domain']+' | وضعیت DNS: '+e['dns_status']+' | hosts: '+e['hosts_mapping']+' | '+', '.join(e['hosts_addresses'])+' | اثر واقعی hosts تأیید نشده']
   else:lines+=['  منع اتصال خروجی ثبت‌شده در WFP: '+e['ip']+':'+str(e['port'])+' '+e['protocol']+' | منشأ قانون/مالکیت تعیین نشده']
 return '\n'.join(lines)+'\n'

def export_bundle(manager,payload,job):
 ids=payload.get('capture_ids')
 if not isinstance(ids,list) or not ids or len(ids)>MAX_CAPTURES or len(set(ids))!=len(ids):raise ValueError('select_1_to_50_distinct_captures')
 captures=[manager.captures.read(ident) for ident in ids]
 if sum(record_count(c) for c in captures)>MAX_RECORDS:raise ValueError('analysis_export_max_20000_records_select_fewer_captures')
 saved_annotation_id=None;pending=payload.get('annotations')
 prepared=None
 if pending is not None:
  if not isinstance(pending,dict):raise ValueError('invalid_stage_annotations')
  ident=pending.get('capture_id')
  if ident not in ids:raise ValueError('annotation_capture_must_be_selected')
  prepared=(ident,*manager.captures.prepared_annotations(ident,pending.get('entries')))
  for capture in captures:
   if capture['capture_id']==ident:manager.captures.with_annotations(capture,prepared[1])
  # Project pending labels into the entire selected bundle without persisting before ZIP success.
  projected={k:[dict(x) for x in values if x['capture_id']!=ident] for k,values in manager.captures.stage_history().items()}
  changed_capture=next(c for c in captures if c['capture_id']==ident)
  for row in changed_capture['endpoints']+changed_capture['event_evidence']['events']:
   if row['context']['stages'] or row.get('phase_context',{}).get('stages'):
    values=projected.setdefault(stage_identity(row),[]);existing=next((x for x in values if x['capture_id']==ident),None)
    if existing:
     existing['stages']=stage_codes(existing['stages']+row['context']['stages']+row.get('phase_context',{}).get('stages',[]))
     existing['manual_stages']=stage_codes(existing.get('manual_stages',[])+row['context']['stages'])
     existing['session_stages']=stage_codes(existing.get('session_stages',[])+row.get('phase_context',{}).get('stages',[]))
    else:values.append(dict(capture_id=ident,stages=stage_codes(row['context']['stages']+row.get('phase_context',{}).get('stages',[])),manual_stages=row['context']['stages'],session_stages=row.get('phase_context',{}).get('stages',[]),annotated_utc=row['context']['annotated_utc']))
  for capture in captures:manager.captures.with_annotations(capture,prepared[1] if capture['capture_id']==ident else None,history_override=projected)

 # Current active rules must be read now, never inferred from the saved list or old capture.
 selected=payload.get('program','');program_hash=None
 try:
  program,program_hash=manager.verify_program(selected);owner=manager.owner();active=manager.block_snapshot(owner,program,job)
 except Exception:active=dict(available=False,entries=[],reason='selected_program_or_owned_rule_readback_unavailable',packet_drop_verified=False)
 saved=dict(available=False,reason='saved_list_unavailable')
 try:
  config=manager.config();saved_entries=manager.parse_entries_from_text(config['text']);saved=dict(available=True,text=manager.format_entries(saved_entries),entries=saved_entries,phase=config['phase'],program_sha256=config.get('program_sha256') if isinstance(config.get('program_sha256'),str) and re.fullmatch('[a-f0-9]{64}',config['program_sha256']) else None,effective_rules_verified=False)
 except Exception:pass
 draft=dict(included=False)
 if payload.get('draft_text') is not None:
  entries=manager.parse_entries_from_text(payload['draft_text']);draft=dict(included=True,text=manager.format_entries(entries),entries=entries,dirty=payload.get('draft_dirty') is True,effective_rules_verified=False)
 ptr={item['ip']:item for item in manager.resolver.rows()}
 for capture in captures:
  for row in capture['endpoints']:
   item=ptr.get(row['ip']);row['ptr']=dict(status=item['status'],names=item['names'],checked_utc_epoch=item['checked_utc'],stale=item['stale'],actual_domain_verified=False) if item else dict(status='not_looked_up',names=[],actual_domain_verified=False)
 report=dict(schema='wow-observation-analysis-1',application_version=manager.version,exported_utc=utc_now(),selected_program_sha256=program_hash,scope='selected_saved_captures_all_non_deleted_rows_including_hidden_old_process_and_block_matches',active_blacklist_at_export=active,saved_desired_blacklist=saved,editor_draft=draft,captures=captures,limits=dict(captures=MAX_CAPTURES,records=MAX_RECORDS),privacy=dict(full_executable_paths_included=False,owner_identifiers_included=False,raw_private_files_included=False,hosts_contents_included=False,attempted_domain_hosts_mappings_included=True,packet_payload_included=False,automatic_upload=False),caveats=['Current stages are manual labels. history_stages/history_sources belong to other saved captures, not proof of the current stage. Deleted records are excluded; original local files and previously created exports are not erased.','Capture-time and export-time rules are distinct snapshots; neither proves packet drops.','PTR is cached reverse-DNS information, not verified actual domain.','Active-rule scope excludes other installations and SSTP policies.','Raw capture files are local records, not digitally signed evidence.','Live pulses represent TCP table samples, not requests or packet activity.','Destination freshness compares IP+port+TCP with a bounded local capture baseline, independently of process age.'])
 if len(captures)==2:
  from capture_compare import compare
  report['comparison']=compare(captures)
 output=manager.output/('WoW-Analysis-'+job+'.zip');tmp=output.with_suffix('.zip.tmp')
 help_text='''این بسته برای ارسال دستی جهت تحلیل ساخته شده است؛ هیچ آپلود خودکاری انجام نشده است.
اگر دقیقاً دو ضبط انتخاب شده باشد، comparison.json و comparison.fa.txt هم در بسته هستند؛ تفاوت مشاهدات، اثبات موفقیت بلاک یا مسیر جایگزین نیست.
phase_recording خط زمانی انتخاب مرحله توسط کاربر است؛ phase_context مرحله‌های واقعاً دارای نمونه/رویداد است، نه تشخیص خودکار بازی. تعداد نمونه، درخواست HTTP یا ترافیک بایت نیست.
analysis.json: نسخهٔ ساختاریافته، شامل همهٔ رکوردهای حذف‌نشدهٔ ضبط‌های انتخاب‌شده، حتی موارد پنهان‌شده در فیلتر نمایش. رکورد حذف‌شده صادر نمی‌شود؛ تعداد حذف در هر ضبط مشخص است.
report.fa.txt: نسخهٔ خواندنی جزئیات رصد، برچسب مرحله و snapshotهای قوانین.
active-blacklist-at-export.txt: فقط قوانین تأییدشدهٔ همین نصب برای Wow انتخابی در زمان خروجی؛ نامعتبر بودن خواندن به معنی فهرست خالی نیست.
saved-blacklist.txt: فهرست ذخیره‌شده؛ معادل قواعد فعال نیست.
editor-draft.txt: جدول فعلی، در صورت معتبر بودن و واردشدن به خروجی؛ ممکن است ذخیره/اعمال نشده باشد.
زمان و محدودیت‌های هر ضبط و snapshotهای شروع/پایان جدا هستند. مرحلهٔ مشاهده چندانتخابی و دستی است. context.stages مرحله‌های همین ضبط، history_stages برچسب‌های ضبط‌های دیگر و history_sources منشأ آن‌هاست. سابقه، حضور در مرحلهٔ ضبط فعلی را ثابت نمی‌کند. برچسب قدیمی multi_stage جزئیات مرحله‌ها را ندارد.
IPها، نام‌های PTR، زمان‌ها، PID و hash فایل بازی در بسته هستند؛ پیش از اشتراک‌گذاری بررسی کن. مسیر کامل بازی، شناسهٔ مالکیت و فایل‌های خام private-state یا hosts کپی نمی‌شوند؛ اما نگاشت hosts برای دامنه‌های واقعاً ثبت‌شده در شواهد DNS ممکن است در بسته باشد.
'''
 try:
  with zipfile.ZipFile(tmp,'w',zipfile.ZIP_DEFLATED) as archive:
   if 'comparison' in report:
    from capture_compare import readable as comparison_text
    archive.writestr('comparison.json',json.dumps(report['comparison'],ensure_ascii=False,indent=2,allow_nan=False));archive.writestr('comparison.fa.txt',comparison_text(report['comparison']))
   archive.writestr('analysis.json',json.dumps(report,ensure_ascii=False,indent=2,allow_nan=False))
   archive.writestr('report.fa.txt',readable(report));archive.writestr('active-blacklist-at-export.txt',snapshot_text(active))
   archive.writestr('saved-blacklist.txt',saved.get('text','# Saved list unavailable; not an empty list.'))
   if draft.get('included'):archive.writestr('editor-draft.txt',draft['text'])
   archive.writestr('README.fa.txt',help_text)
  with zipfile.ZipFile(tmp) as archive:
   if archive.testzip() is not None:raise ValueError('analysis_archive_verification_failed')
  os.replace(tmp,output)
  if prepared is not None:
   ident,entries,changed=prepared;path=manager.captures.annotation_path(ident);path.parent.mkdir(exist_ok=True);manager.atomic_json(path,dict(schema='wow-capture-annotations-2',capture_id=ident,entries=entries));saved_annotation_id=ident;manager.captures.__dict__.pop('_stage_cache',None)
 except Exception:
  tmp.unlink(missing_ok=True);raise
 return dict(filename=output.name,sha256=hashlib.sha256(output.read_bytes()).hexdigest(),capture_count=len(captures),record_count=sum(record_count(c) for c in captures),active_blacklist_available=active.get('available') is True,saved_annotation_capture_id=saved_annotation_id,automatic_upload=False)
