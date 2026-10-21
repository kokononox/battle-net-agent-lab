"""Read-only, exact-destination comparison. Absence is never interpreted as a successful block."""
import datetime
from phase_context import instant,phase_stages
from capture_store import STAGES,stage_codes
MAX_COMPARE_RECORDS=6000

def rows_for(c,kind):
 if kind=='tcp':return c['endpoints']
 return [r for r in c.get('event_evidence',{}).get('events',[]) if r['kind']==('dns_query' if kind=='dns' else 'wfp_connection_block')]
def key_for(r,kind):return r['domain'] if kind=='dns' else r['ip'].lower()+'|'+str(r['port'])+'|'+r.get('protocol','TCP')
def group_rows(c,kind):
 out={}
 for r in rows_for(c,kind):
  key=key_for(r,kind)
  if key not in out:
   out[key]=dict(key=key,records=0,samples=0,manual_stages=[],session_stages=[],first_seen_utc='',last_seen_utc='')
   if kind=='dns':out[key]['domain']=r['domain']
   else:out[key].update(ip=r['ip'],port=r['port'],protocol=r.get('protocol','TCP'))
  item=out[key];item['records']+=1
  if kind=='tcp':item['samples']+=r['samples']
  item['manual_stages']=stage_codes(item['manual_stages']+r.get('context',{}).get('stages',[]))
  item['session_stages']=stage_codes(item['session_stages']+phase_stages(r))
  first=r.get('first_seen_utc',r.get('observed_utc',''));last=r.get('last_seen_utc',r.get('observed_utc',''))
  if instant(first) and (not instant(item['first_seen_utc']) or instant(first)<instant(item['first_seen_utc'])):item['first_seen_utc']=first
  if instant(last) and (not instant(item['last_seen_utc']) or instant(last)>instant(item['last_seen_utc'])):item['last_seen_utc']=last
 return out

def capture_summary(c):
 return {key:c.get(key) for key in ('capture_id','program_sha256','capture_started_utc','capture_ended_utc','seconds','query_errors','truncated','deleted_record_count','annotation_state','phase_recording')}
def capture_when(c):
 when=instant(c.get('capture_started_utc'))
 if when:return when
 epoch=c.get('recorded_utc_epoch')
 if type(epoch) in (int,float):
  try:return datetime.datetime.fromtimestamp(epoch,datetime.timezone.utc)
  except (ValueError,OverflowError,OSError):pass
 return None

def compare(captures):
 if not isinstance(captures,list) or len(captures)!=2 or captures[0]['capture_id']==captures[1]['capture_id']:raise ValueError('select_exactly_two_distinct_captures')
 if sum(len(c['endpoints'])+len(c['event_evidence']['events']) for c in captures)>MAX_COMPARE_RECORDS:raise ValueError('comparison_too_many_records')
 a,b=captures;wa,wb=capture_when(a),capture_when(b);warnings=[]
 if wa and wb and wa!=wb:
  if wa>wb:a,b=b,a
  order='capture_start_or_recorded_time_ascending'
 else:order='selection_order_time_missing_or_tied';warnings.append('ترتیب زمانی قطعی نیست؛ ضبط A و B با ترتیب انتخاب مشخص شده‌اند.')
 if a['program_sha256']!=b['program_sha256']:warnings.append('hash بازی در دو ضبط متفاوت است؛ ممکن است نسخه یا فایل بازی عوض شده باشد.')
 if a.get('seconds')!=b.get('seconds'):warnings.append('مدت ضبط‌ها برابر نیست؛ تعداد نمونه/رویداد را نرخ یا معیار موفقیت بلاک تلقی نکن.')
 for label,c in (('A',a),('B',b)):
  if c.get('truncated'):warnings.append('ضبط '+label+' به سقف رسیده یا ناقص است.')
  if c.get('query_errors') is None or c.get('query_errors',0)>0:warnings.append('ضبط '+label+' خطای خواندن دارد یا وضعیت خطا ثبت نشده است.')
  if c.get('deleted_record_count',0)>0:warnings.append('در ضبط '+label+' حذف صریح رکورد انجام شده؛ ردیف‌های حذف‌شده در مقایسه نیستند.')
  if c.get('annotation_state')!='available':warnings.append('برچسب‌های ضبط '+label+' کامل/قابل‌خواندن نیستند.')
  for name,title in (('dns','DNS'),('wfp','WFP')):
   status=c.get('event_evidence',{}).get('streams',{}).get(name,{}).get('status')
   warnings.append('منبع '+title+' در '+label+': '+('خواندنی، اما پوشش ثبت تأیید نشده' if status=='readable_logging_coverage_unverified' else 'شواهد کامل/در دسترس تأیید نشده'))
  if c.get('event_evidence',{}).get('truncated'):warnings.append('شواهد رویداد ضبط '+label+' ناقص است.')
 phases=[]
 for c in (a,b):phases.append({r['stage'] for r in c.get('phase_recording',{}).get('transitions',[]) if r['stage']!='unknown'})
 if phases[0]!=phases[1]:warnings.append('مرحله‌های انتخاب‌شده در دو ضبط یکسان نیستند؛ تفاوت مقصدها ممکن است ناشی از مرحلهٔ بازی باشد.')
 for label,c in (('A',a),('B',b)):
  if c.get('phase_recording',{}).get('status')!='available':warnings.append('ثبت مرحلهٔ جاری در '+label+' موجود یا کاملاً قابل‌خواندن نیست؛ برچسب دستی قدیمی زمان دقیق نمی‌دهد.')
 changes={}
 for kind in ('tcp','dns','wfp'):
  left,right=group_rows(a,kind),group_rows(b,kind);la,lb=set(left),set(right)
  changes[kind]=dict(baseline_unique=len(left),compared_unique=len(right),added=[right[k] for k in sorted(lb-la)],not_seen_again=[left[k] for k in sorted(la-lb)],shared=[dict(key=k,baseline=left[k],compared=right[k]) for k in sorted(la&lb)])
 def rules(c):
  snap=c.get('block_snapshot',{})
  if snap.get('available') is not True:return None
  return {e['ip']+'|'+str(e['port'])+'|'+e['protocol']:e for e in snap.get('entries',[])}
 ar,br=rules(a),rules(b);rule_diff=dict(available=ar is not None and br is not None,scope='this_installation_selected_executable_end_snapshots_only',drop_verified=False)
 if rule_diff['available']:rule_diff.update(added=[br[k] for k in sorted(set(br)-set(ar))],removed=[ar[k] for k in sorted(set(ar)-set(br))])
 else:warnings.append('snapshot پایانِ قوانین یک یا هر دو ضبط نامعتبر است؛ تفاوت قوانین محاسبه نشد.')
 return dict(schema='wow-capture-comparison-1',order=order,baseline=capture_summary(a),compared=capture_summary(b),changes=changes,rule_configuration_changes=rule_diff,warnings=warnings,scope='exact_IP_port_protocol_or_DNS_name_without_PID_and_without_inferred_domain_links',block_success_verified=False,caveat='ندیدن دوباره، نبود تلاش، قطع واقعی یا موفقیت بلاک را ثابت نمی‌کند. مقصد تازه را بدون شواهد، مسیر جایگزین فرض نکن.')

def readable(report):
 a,b=report['baseline'],report['compared'];lines=['مقایسهٔ دو ضبط — فقط اختلاف مشاهدات','A: '+a['capture_id']+' | شروع UTC: '+str(a['capture_started_utc'])+' | مدت: '+str(a['seconds']),'B: '+b['capture_id']+' | شروع UTC: '+str(b['capture_started_utc'])+' | مدت: '+str(b['seconds']),report['caveat'],'برچسب‌های سابقهٔ ضبط‌های دیگر در تشخیص مرحلهٔ این دو ضبط استفاده نشده‌اند.','']
 for kind,title in (('tcp','مقصدهای TCP نمونه‌برداری‌شده'),('dns','نام‌های DNS ثبت‌شده'),('wfp','مقصدهای دارای رویداد منع اتصال WFP')):
  d=report['changes'][kind];lines+=[title,'یکتا در A: '+str(d['baseline_unique'])+' | یکتا در B: '+str(d['compared_unique'])+' | مشترک: '+str(len(d['shared']))]
  for key,label in (('added','فقط در B دیده شد'),('not_seen_again','در A بود، در B دیده نشد')):
   lines+=[label+': '+str(len(d[key]))]
   for r in d[key]:
    target=r['domain'] if kind=='dns' else (('['+r['ip']+']') if ':' in r['ip'] else r['ip'])+':'+str(r['port'])+' '+r['protocol']
    phases='، '.join(STAGES[x] for x in r['session_stages']) or 'نامشخص'
    manual='، '.join(STAGES[x] for x in r['manual_stages']) or 'نامشخص'
    lines+=['  '+target+' | مرحلهٔ جاریِ ثبت‌شده: '+phases+' | برچسب دستی: '+manual+' | رکورد: '+str(r['records'])]
  lines+=['']
 rules=report['rule_configuration_changes'];lines+=['تفاوت تنظیمات Block پایان ضبط؛ نه اثبات افت:']
 if rules['available']:
  for name,title in (('added','فقط در B'),('removed','فقط در A')):
   lines+=[title+': '+str(len(rules[name]))]+['  '+r['ip']+':'+str(r['port'])+' '+r['protocol'] for r in rules[name]]
 else:lines+=['نامعتبر/در دسترس نیست']
 lines+=['','محدودیت‌ها و هشدارها:']+['- '+s for s in report['warnings']]
 return '\n'.join(lines)+'\n'
