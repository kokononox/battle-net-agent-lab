from pathlib import Path
import collections
import datetime
import hashlib
import json
import re
import sys

root=Path('/data/analysis/recon-r1-user02')
raw=Path('/data/raw/recon-r1-user02/recon-02-1792365695406801100.json')
sys.path.insert(0,'/data/local-destination-recon-r1/app')
from recon import validate_report
r=validate_report(json.loads(raw.read_text()))
o=r['observation'];flows=o['public_tcp_samples']
blocked=r['blocked_domains']
checks={}
for key in ('resolution_after_apply','resolution_before_restore'):
    states=r['hosts'][key]
    checks[key]=set(states)==set(blocked) and all(v=='loopback_only' for v in states.values())
    assert checks[key]
assert len(blocked)==20
assert sum(v=='loopback_only' for v in r['hosts']['resolution_after_apply'].values())==20
duration=(datetime.datetime.fromisoformat(r['observation_ended_utc'])-datetime.datetime.fromisoformat(r['ready_utc'])).total_seconds()
pmap={p['index']:p for p in o['processes']}
endpoints={(f['remote_address'],f['remote_port']) for f in flows}
by_endpoint={}
for f in flows:by_endpoint.setdefault((f['remote_address'],f['remote_port']),[]).append(f)
assert len(by_endpoint)==len(endpoints)
assert all(f['process_index'] in pmap for f in flows)
agent_rows=[p for p in o['processes'] if p['process_name']=='agent.exe']
agent_flows=[f for f in flows if pmap[f['process_index']]['process_name']=='agent.exe']
e={
    'schema':'recon-r1-user02-analysis-1',
    'source_sha256':hashlib.sha256(raw.read_bytes()).hexdigest(),
    'source_filename':raw.name,'provenance':'user-uploaded, no signed provenance or independent live observation',
    'profile_id':r['profile_id'],'schema_valid':True,'ready':r['ready'],
    'status':r['status'],'error_code':r['error_code'],'blocked_domains':blocked,
    'blocked_domain_count':len(blocked),'dns_loopback_checks':checks,
    'hosts_restore':r['hosts']['restore_status'],'blocks_remain_after_restore':False,
    'reported_download_behavior':r['user_download_behavior'],
    'reported_final_state':r['user_final_state'],
    'planned_window_seconds':r['window_seconds'],'ready_to_observation_end_seconds':duration,
    'window_duration_caveat':'Timestamp difference, not exact resumed download duration; user_q before 120-second limit',
    'end_reason':r['end_reason'],'initial_versions':r['initial_versions'],
    'final_versions':r['final_versions'],'process_count':len(o['processes']),
    'agent_processes':agent_rows,'agent_public_tcp_rows':agent_flows,
    'tcp_row_count':len(flows),'unique_public_ip_port_pairs':len(endpoints),
    'unique_public_ips':len({f['remote_address'] for f in flows}),
    'sampler_errors':o['sampler_errors'],
    'limits_hit':{'processes':o['process_limit_hit'],'flows':o['flow_limit_hit']},
    'all_processes_valid_blizzard':all(p['signature_valid'] and p['blizzard_publisher'] for p in o['processes']),
    'injection_used':r['limits']['injection_used'],'content_or_cpu_collected':False,
    'whole_update_completion_proven':False,'zero_telemetry_proven':False,
    'next_profile':'03-BAT3-Plus-OAuth.bat',
    'next_change':'Same corrected BAT3 baseline + oauth.battle.net only; not cumulative other extras',
    'next_test_stop':'No READY: do not Resume; record failed trial. Otherwise manual Pause/Exit and report.',
    'profile_warning_resolution':'General profiler cannot flatten this nested report; explicit process and public_tcp_samples arrays used. No rows dropped or deduplicated; endpoint sets are separate distinct counts, not removal of samples.',
    'visual_plan':{'disposition':'prose','reason':'Single diagnostic trial with a gate decision, not a measured traffic-volume comparison or temporal trend. IP rows are sampled TCP socket observations, not bytes, requests or unique connections.'},
    'independent_checks':{'dns_count_by_map_and_list_agrees':True,'endpoint_count_by_grouping_and_set_agrees':True,'all_flow_process_refs_valid':True},
}
(root/'evidence.json').write_text(json.dumps(e,ensure_ascii=False,indent=2)+'\n')
analysis=f"""# R1 / ۰۲ — اولین گزارش کاربر، غربالگری مبنای BAT 3

## نتیجه
Schema گزارش معتبر است؛ READY صادر شده و کاربر در پاسخ ابزار `reported_progress` و در پایان `reported_paused` انتخاب کرده است. پس مبنای اصلاح‌شده BAT 3 برای **غربالگری مرحله بعد قابل استفاده** است. این پاسخ دستی اندازه‌گیری مستقل بایت/درصد دانلود یا اثبات تکمیل آپدیت نیست.

هر ۲۰ نام دامنه پروفایل در بررسی resolver پس از apply و پیش از restore به loopback رفته‌اند. hosts در پایان `restored_exactly` است؛ بعد از خروج دیگر بلوک این ابزار فعال نیست. این بررسی نام‌ها، نبود IP مستقیم/DoH/مسیر دیگر یا قطع قطعی همه اتصال‌ها را ثابت نمی‌کند.

## بازه واقعی و سلامت ثبت
- سقف تنظیم‌شده ۱۲۰ثانیه است ولی کاربر Q زده: فاصله READY تا پایان مشاهده **{duration:.2f} ثانیه** است، نه پنجره کامل ۱۲۰ثانیه. لحظه Resume جداگانه ثبت نشده؛ این مدت دقیق دانلود نیست.
- sampler_errors=0 و process/flow cap هر دو false هستند؛ صفر بودن خطای گزارش‌شده، پوشش کامل اتصال‌های کوتاه یا UDP/QUIC را ثابت نمی‌کند.
- Recon طبق مسیر این نسخه بدون injection و بدون جمع‌آوری payload/CPU/TLS key کار می‌کند؛ بنابراین این گزارش اصلاً نمی‌تواند وجود یا نبود داده سخت‌افزاری در درخواست‌ها را پاسخ دهد.
- نشانگر نسخه ابتدا و انتها `12.1.5.70448` است. این از قبل در اجرای U1 به نسخه جدید تغییر کرده بود؛ ثابت‌بودن آن نه دانلودنکردن را اثبات می‌کند و نه تکمیل نصب را.

## فرایندها و مقصدهای نمونه
- {len(o['processes'])} فرایند ثبت شده‌اند، همگی طبق گزارش دارای امضای معتبر Blizzard. Agent PID 6512 همان SHA256 `b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5` را دارد؛ شناسایی image بر پایه هش است، نه استنباط نسخه از روی PID.
- {len(flows)} ردیف TCP نمونه‌برداری‌شده، معادل {len(endpoints)} زوج متمایز IP:port و {e['unique_public_ips']} IP عمومی است. تعداد sample_observations دفعات مشاهده socketهاست؛ چند اتصال با مقصد یکسان در یک snapshot ممکن است به همان شمارنده اضافه شوند. آن را تعداد درخواست، تعداد اتصال یکتا، زمان اتصال یا بایت آپلود/دانلود نمی‌نامیم.
- برای خود Agent، `8.232.70.12:443`، `2.21.23.18:80` و `2.21.23.82:80` در نمونه دیده شده‌اند. اینها **مقصد مشاهده‌شده Agent** هستند، نه اثبات اینکه تمام ترافیکشان فایل آپدیت است یا نام Host مشخصی دارند.
- باقی ردیف‌ها به Battle.net.exe مربوط‌اند. IPها به‌تنهایی سرویس، Host، ارسال اطلاعات سخت‌افزاری یا server receipt/storage را اثبات نمی‌کنند؛ نسبت‌دادن آنها به CDN/Google/OAuth بدون شاهد جدا انجام نشده است.

## تصمیم بعد
نیازی به تکرار پروفایل ۰۲ صرفاً برای پرکردن ۱۲۰ثانیه یا پاک/rollback کردن بازی نیست. فقط `03-BAT3-Plus-OAuth.bat` اجرا شود: همان ۲۰ نام مبنا + **فقط** oauth.battle.net، بدون block انباشته سایر extras.

پیش‌شرط‌ها: WoW/Battle.net/Agent کامل بسته، auto update خاموش، بکاپ محفوظ، signed out و دانلود تا READY در Pause. اگر READY نیامد Resume نشود؛ همان شکست و پیام گزارش شود. اگر READY آمد، Resume فقط دستی و پایان تایمر هم Pause خودکار نیست؛ کاربر Pause/Exit می‌کند و `output/recon-03-*.json` می‌فرستد.

این غربالگری ممکن است رابطه احتمالی domain و رفتار را نشان دهد؛ تغییر cache/مرحله دانلود و عوامل شبکه مانع نسبت‌دادن قطعی علت‌اند. کارکردن با بلوک OAuth به معنی telemetry بودن آن، و کارنکردن به معنی ضروری بودن همیشگی‌اش نیست.

## منابع و بازتولید
- [گزارش اصلی کاربر](destination-recon-r1-user02.json)
- [شواهد و هش ورودی](destination-recon-r1-user02-analysis.json)
- [کد تحلیل](../analysis/destination-recon-r1-user02.py)

گزارش کاربر provenance امضاشده ندارد؛ ابزار از اینجا زنده روی ویندوز مشاهده نشده است. Schema با validator همان R1 بررسی شد؛ شمارش DNS از مسیر مستقل map/list و شمارش endpoint از grouping/set تطبیق داده شد. profiler عمومی نتوانست JSON تودرتو را به جدول تبدیل کند؛ تحلیل با آرایه‌های صریح انجام شد، نه با حذف داده.
"""
(root/'analysis.fa.md').write_text(analysis)
old_payload=json.loads(Path('/data/r1-status-push.json').read_text())
status=next(f['content'] for f in old_payload['files'] if f['path']=='docs/STATUS.fa.md')
status=re.sub(r'\*\*آخرین به‌روزرسانی: .*? \(UTC\)\*\*','**آخرین به‌روزرسانی: '+datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M')+' (UTC)**',status,count=1)
status=re.sub(r'\*\*مرحلهٔ فعلی: .*?\*\*','**مرحلهٔ فعلی: گزارش واقعی R1/02 دریافت شد؛ کاربر پیشرفت دانلود زیر مبنای ۲۰دامنه‌ای اصلاح‌شده را گزارش کرده، hosts بازیابی و sampler_errors صفر است. مشاهده با Q حدود ۷۵ثانیه پس از READY تمام شد. گام بعد فقط پروفایل ۰۳/OAuth؛ هنوز محتوای ترافیک یا completion معلوم نیست.**',status,count=1)
changes={
    'بسته R1 در پوشه جدید؛ فقط 02-BAT3-Corrected.bat با Administrator. Battle.net/Agent/WoW ابتدا بسته؛ Resume فقط بعد از READY؛ پنجره ۱۲۰ثانیه سپس Pause/Exit دستی و ارسال output/recon-02-*.json. فعلاً سایر پروفایل‌ها اجرا نشوند':
    'فقط 03-BAT3-Plus-OAuth.bat با Administrator؛ همان مبنا + oauth.battle.net. همه پردازش‌ها ابتدا بسته؛ Resume فقط بعد از READY؛ پایان تایمر Pause خودکار نیست. output/recon-03-*.json ارسال شود؛ بقیه پروفایل‌ها فعلاً نه',
    'کاربر U1 را دارد؛ R1 تازه آماده و لینک artifact تحویل می‌شود. دانلود/اجرای R1 توسط کاربر هنوز گزارش نشده؛ ورود مرورگر عامل درخواست نمی‌شود':
    'گزارش اجرای R1/02 دریافت و بررسی شد؛ بسته تازه یا ورود مرورگر لازم نیست. اجرای ۰۳ از همان بسته موجود',
    '**فعلاً R1/02 اجرا شود، نه U2 یا همه نسخه‌ها**':
    '**R1/02 اکنون اجرا و تحلیل شد؛ فعلاً فقط R1/03، نه U2 یا همه نسخه‌ها**',
    'بعد از گزارش ۰۲ مرحله پایش محتوا جدا طراحی می‌شود.':
    'گزارش ۰۲ دریافت شد؛ هنوز مرحله پایش محتوا جداست و اکنون فقط وابستگی OAuth غربالگری می‌شود.',
    'no-hook در R1 پیاده و بسته شد، ولی هنوز اجرای کاربر/مقایسه هم‌شرط نداریم':
    'no-hook در R1 پیاده و اجرای ۰۲ کاربر دریافت شد؛ هنوز A/B هم‌شرط نداریم',
}
for old,new in changes.items():
    assert status.count(old)==1,old
    status=status.replace(old,new,1)
section="""
### نتیجه واقعی R1/02 — مبنای اصلاح‌شده، پیشرفت به گزارش کاربر
- [تحلیل](../reports/destination-recon-r1-user02-analysis.fa.md) · [گزارش اصلی](../reports/destination-recon-r1-user02.json).
- هر ۲۰ نام در resolver پس از apply و پیش از restore، loopback_only؛ restore=restored_exactly؛ پس از خروج بلوک ابزار فعال نیست.
- READY=true؛ کاربر reported_progress و reported_paused انتخاب کرده؛ بدون اندازه‌گیری مستقل بایت/درصد. پایان user_q حدود ۷۵٫۱۵ثانیه پس از READY است، نه تمام ۱۲۰ثانیه و نه زمان دقیق Resume.
- sampler_errors=0 و caps false؛ Agent با همان image hash اصلی دیده شده است. هیچ payload/CPU در R1 جمع‌آوری نشده؛ «CPU دیده نشد» نتیجه این گزارش نیست.
- نسخه ابتدا/انتها 12.1.5.70448؛ از قبل marker تغییر کرده بود و completion را ثابت نمی‌کند.
- اقدام بعد فقط 03-BAT3-Plus-OAuth.bat از همان بسته. اگر READY نیامد Resume نشود؛ خطا گزارش شود. همه extras همزمان/انباشته نشوند، بازی حذف/Repair/rollback نشود.
"""
marker='\n## وضعیت دستگاه و حدود مجوز'
assert status.count(marker)==1;status=status.replace(marker,section+marker,1)
status=status.replace('آخرین وضعیت گزارش‌شده: کاربر پیش‌شرط signed out/آپدیت خودکار خاموش را تأیید کرده و دانلود تا ۳۰٪ را گفته؛ پاسخ پایان ابزار Paused است. نشانگر نسخه از 12.1.0.69933 به 12.1.5.70448 تغییر کرده، اما این اثبات کامل‌بودن فایل‌ها نیست. hosts بازیابی شده؛ وضعیت زندهٔ فعلی از اینجا معلوم نیست.',
    'آخرین گزارش R1/02: پیش‌شرط‌ها تأیید، reported_progress و reported_paused؛ hosts بازیابی شده است. نسخه ابتدا و انتها 12.1.5.70448 است؛ این اثبات کامل‌بودن فایل‌ها نیست. درصد جدید اندازه‌گیری/اعلام نشده و وضعیت زنده از اینجا معلوم نیست.')
row='| 2026-10-18 | R1/02 دریافت شد؛ مبنای اصلاح‌شده برای ادامه غربالگری پذیرفته شد، نه اثبات privacy/completion | هر۲۰ DNS loopback، Q پس از حدود۷۵ثانیه، reported_progress، restore دقیق؛ بعد فقط OAuth/03 |\n'
marker='| 2026-10-18 | مسیر فعال از U2 زمان‌بندی‌شده به R1 بدون hook تغییر کرد | source 4f083a8؛ run 39175413357؛ ابتدا فقط پروفایل ۰۲ |\n'
assert status.count(marker)==1;status=status.replace(marker,marker+row,1)
(root/'STATUS.fa.md').write_text(status)
files=[
    {'path':'docs/STATUS.fa.md','content':status},
    {'path':'reports/destination-recon-r1-user02.json','content':raw.read_text()},
    {'path':'reports/destination-recon-r1-user02-analysis.json','content':(root/'evidence.json').read_text()},
    {'path':'reports/destination-recon-r1-user02-analysis.fa.md','content':analysis},
    {'path':'analysis/destination-recon-r1-user02.py','content':Path(__file__).read_text()},
]
payload=dict(owner='kokononox',repo='battle-net-agent-lab',branch='main',
    message='docs: record R1 baseline progress and select OAuth-only extra trial',files=files)
(root/'push.json').write_text(json.dumps(payload,ensure_ascii=False))
print(json.dumps({k:e[k] for k in ('schema_valid','blocked_domain_count','ready_to_observation_end_seconds','sampler_errors','hosts_restore','reported_download_behavior','reported_final_state','next_profile','independent_checks')},ensure_ascii=False,indent=2))