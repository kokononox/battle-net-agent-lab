from pathlib import Path
from datetime import datetime,timezone
import collections
import csv
import hashlib
import json
import re
import sys

root=Path('/data/analysis/recon-r1-series')
raw=Path('/data/raw/recon-r1-series')
sys.path.insert(0,'/data/local-destination-recon-r1/app')
from recon import validate_report
from recon_profiles import BAT3_FIXED,EXTRAS

rows=[];reports={};sources={}
for path in sorted(raw.glob('recon-*.json')):
    r=validate_report(json.loads(path.read_text()))
    profile=r['profile_id']
    assert profile not in reports
    reports[profile]=r;sources[profile]=path
    expected=list(BAT3_FIXED) if profile=='02' else list(BAT3_FIXED)+[EXTRAS[int(profile)-3]]
    assert r['blocked_domains']==expected
    o=r['observation'];pmap={p['index']:p for p in o['processes']}
    dns=[]
    for key in ('resolution_after_apply','resolution_before_restore'):
        states=r['hosts'][key]
        assert set(states)==set(expected)
        # Independent list-of-domain check vs map value count.
        assert all(states[d]=='loopback_only' for d in expected)
        assert sum(v=='loopback_only' for v in states.values())==len(expected)
        dns.append(True)
    flows=o['public_tcp_samples']
    agent_flows=[f for f in flows if pmap[f['process_index']]['process_name']=='agent.exe']
    endpoints=sorted({(f['remote_address'],f['remote_port']) for f in agent_flows})
    independent=collections.Counter()
    for f in flows:
        assert f['process_index'] in pmap
        if pmap[f['process_index']]['process_name']=='agent.exe':
            independent[(f['remote_address'],f['remote_port'])]+=f['sample_observations']
    assert set(independent)==set(endpoints)
    seconds=(datetime.fromisoformat(r['observation_ended_utc'])-datetime.fromisoformat(r['ready_utc'])).total_seconds() if r['ready_utc'] else None
    rows.append({
        'profile':profile,'extra_target':None if profile=='02' else EXTRAS[int(profile)-3],
        'blocked_domain_count':len(expected),'ready':r['ready'],'status':r['status'],
        'top_level_error':r['error_code'],'reported_download_behavior':r['user_download_behavior'],
        'reported_final_state':r['user_final_state'],'sampler_errors':o['sampler_errors'],
        'ready_to_end_seconds':seconds,'end_reason':r['end_reason'],'planned_window_seconds':r['window_seconds'],
        'dns_after_and_before_restore_all_loopback':all(dns),
        'restore':r['hosts']['restore_status'],'process_cap_hit':o['process_limit_hit'],
        'flow_cap_hit':o['flow_limit_hit'],'initial_versions':r['initial_versions']['retail_versions'],
        'final_versions':r['final_versions']['retail_versions'],'agent_endpoints':endpoints,
        'main_agent_seen':any(p['process_name']=='agent.exe' and p['sha256']=='b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5' and p['signature_valid'] and p['blizzard_publisher'] for p in pmap.values()),
        'source_filename':path.name,'source_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
        'started_utc':r['started_utc'],
    })
assert [r['profile'] for r in rows]==['02','03','04','05','06','07']
assert [r['started_utc'] for r in rows]==sorted(r['started_utc'] for r in rows)
old02=Path('/data/raw/recon-r1-user02/recon-02-1792365695406801100.json')
assert sources['02'].read_bytes()==old02.read_bytes()
assert all(r['main_agent_seen'] for r in rows)
# Independent headline check from the raw reports, not the summary rows.
progress_independent=sum(json.loads(p.read_text())['user_download_behavior']=='reported_progress' for p in sources.values())
assert progress_independent==sum(r['reported_download_behavior']=='reported_progress' for r in rows)==6
restores_independent=sum(json.loads(p.read_text())['hosts']['restore_status']=='restored_exactly' for p in sources.values())
assert restores_independent==6
evidence={
    'schema':'destination-recon-r1-series-analysis-1','profiles':rows,
    'unique_trial_count':6,'new_trials_beyond_previous02':5,
    'reattached02_is_byte_identical_to_previous':True,
    'provenance':'user-uploaded reports, not signed attestations or live access',
    'reported_progress_count':progress_independent,
    'restored_exactly_count':restores_independent,
    'all_ready':all(r['ready'] for r in rows),
    'all_ended_with_q':all(r['end_reason']=='user_q' for r in rows),
    'min_ready_to_end_seconds':min(r['ready_to_end_seconds'] for r in rows),
    'max_ready_to_end_seconds':max(r['ready_to_end_seconds'] for r in rows),
    'sampling_error_profiles':[r['profile'] for r in rows if r['sampler_errors']],
    'unchanged_version_in_all':all(r['initial_versions']==r['final_versions']==['12.1.5.70448'] for r in rows),
    'whole_update_completion_proven':False,'zero_telemetry_proven':False,
    'combined_extras_block_tested':False,'payload_cpu_or_tls_keys_collected':False,
    'causal_fallback_proven':False,
    'independent_checks':{'progress_from_original_reports_matches_summary':True,
        'restores_from_original_reports_match_summary':True,
        'dns_map_counts_match_exact_list':True,'agent_endpoints_set_matches_loop_grouping':True},
    'profile_warning_resolution':'General profiler failed flattening all six nested JSON reports; analysis uses explicit arrays and fields. No trial/event discarded or deduplicated. Reattached profile02 is counted once, not as replication.',
    'comparison_plan':[
        {'question':'Did a single extra domain block stop download in each trial?','grain':'one independently restarted profile','population':'profiles02-07','unit':'user-reported categorical outcome','finding':'progress reported in all six; no reported stall/error','disposition':'table','reason':'Identical categorical outcomes, not numerical effect sizes; a plot adds no information.'},
        {'question':'How complete/comparable is observation?','grain':'one profile','population':'six unequal windows','unit':'uncategorized sampler-error count and timestamp duration','finding':'03/04/05/07 record sampler errors; all end early with Q','disposition':'table','reason':'Diagnostic caveats, not comparable error rates or traffic volumes. Do not rank destinations with these counts.'},
        {'question':'What destinations remain?','grain':'process-attributed sampled public TCP endpoint','population':'signed Agent instances in six windows','unit':'IP:port set, not bytes/requests','finding':'Agent endpoints differ; profile07 has 137.221.64.6/.8:80 rather than sampled 2.21.23.18/.82:80 in02-06','disposition':'table','reason':'Set-membership evidence; IP labels do not establish Host/payload or causal fallback.'},
    ],
    'next_step':'Stop blind blocking. User challenged efficacy: first validate actual connection-level blocking with a positive control and process-attributed drop/connection evidence, not DNS alone; no firewall changes authorized/executed this turn. Then prepare content-level observation on baseline02. Confirm whether real download remains. No new executable/build this turn.',
}
(root/'evidence.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+'\n')
fields=['profile','extra_target','blocked_domain_count','ready','reported_download_behavior','reported_final_state','ready_to_end_seconds','end_reason','sampler_errors','restore']
with (root/'summary.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
    for r in rows:w.writerow({k:r[k] for k in fields})

table='\n'.join('| '+r['profile']+' | '+(r['extra_target'] or 'هیچ؛ مبنای BAT 3 اصلاح‌شده')+' | ادامه به گزارش کاربر | '+f"{r['ready_to_end_seconds']:.2f}"+' | '+str(r['sampler_errors'])+' |' for r in rows)
endpoint_table='\n'.join('| '+r['profile']+' | '+', '.join(f'`{ip}:{port}`' for ip,port in r['agent_endpoints'])+' |' for r in rows)
analysis=f"""# R1 / پروفایل‌های ۰۲ تا ۰۷ — نتیجه غربالگری

## نتیجه اجرایی
شش پروفایل معتبر دریافت شده‌اند؛ فایل ۰۲ عیناً همان فایل قبلی است، نه آزمون تکراری مستقل. در هر شش گزارش READY=true و پاسخ کاربر reported_progress/ reported_paused است. **در این نمونه‌ها توقف دانلود به گزارش کاربر رخ نداده است**؛ ضرورت همیشگی هیچ مقصد یا نبود تله‌متری از آن اثبات نمی‌شود.

## نتایج هر پروفایل
«ادامه» پاسخ دستی کاربر است، نه اندازه‌گیری بایت/درصد. مدت، فاصله READY تا پایان capture است، نه دقیقاً زمان دانلود. همه با Q زودتر از سقف ۱۲۰ثانیه تمام شده‌اند.

| پروفایل | مقصد اضافه بر مبنای ۲۰دامنه‌ای | رفتار ثبت‌شده | READY تا پایان، ثانیه | sampler_errors |
| --- | --- | --- | ---: | ---: |
{table}

تمام نام‌های هر مرحله (۲۰ نام در۰۲ و۲۱ نام دربقیه) در resolver پس از apply و پیش از restore به loopback رفته‌اند. همه restore=restored_exactly، top-level error=null و process/flow cap=false هستند. خطاهای sampler در۰۳/۰۴/۰۵/۰۷ همچنان نقاط کور ناشناخته‌اند؛ چون نوع خطا ثبت نشده، آن را کرش/اخلال عمدی/افت قطعی ترافیک نمی‌نامیم. صفر error در۰۲/۰۶ نیز پوشش کامل را ثابت نمی‌کند.

## دقیقاً چه چیزی شناسایی شد؟
Agent اصلی با همان image hash `b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5` و امضای معتبر Blizzard در همه گزارش‌ها دیده شده است. این شناسایی باینری است، نه اثبات اینکه همه ارتباطاتش صرفاً فایل آپدیت است. Launcher جانبی ممکن است بین نمونه‌ها ظاهر/ناپدید شود؛ آن را با تغییر image اصلی اشتباه نمی‌گیریم.

فقط مقصدهای عمومی TCP منتسب به Agent در نمونه:

| پروفایل | IP:port مشاهده‌شده Agent |
| --- | --- |
{endpoint_table}

برای۰۷ دو مقصد `137.221.64.6:80` و `137.221.64.8:80` دیده شده‌اند؛ نمونه‌های۰۲ تا۰۶ به‌جای آن‌ها `2.21.23.18:80` و `2.21.23.82:80` دارند. این **تفاوت مشاهده‌شده** است، نه اثبات اینکه block باعث fallback شده یا یک IP معادل Host خاص است. در۰۵ نیز `8.232.70.12:443` در نمونه Agent نیست؛ از نبود در نمونه نام دامنه/وظیفه سرویس را استنتاج نمی‌کنیم.

TCP sample_observations حجم دانلود/آپلود، تعداد درخواست یا تعداد اتصال یکتا نیست. اتصال کوتاه/UDP/QUIC می‌تواند دیده نشود. این مرحله بدون injection، plaintext یا CPU collection است و هیچ محتوای رمز‌شده‌ای را معنی نمی‌کند.

## چرا «همه قابل حذف‌اند» نتیجه درستی نیست؟
- extraها جداگانه آزمایش شده‌اند، نه همزمان. ممکن است هرکدام مسیر جایگزین دیگری داشته باشد؛ بستن مجموع پنج مقصد نتیجه آزموده‌شده نیست.
- hosts فقط بخشی از resolution نام را کنترل می‌کند. cache برنامه، IP مستقیم، DoH، alias یا مسیر جایگزین ممکن است باقی بماند.
- میزان پیشرفت/فایل‌ها و cache بین اجراها عوض می‌شود؛ کاربر درصد/بایت مستقل ثبت نکرده و پنجره‌ها هم‌طول نیستند.
- marker نسخه در همه آغاز/پایان `12.1.5.70448` است. قبلاً پیش از تکمیل دانلود تغییر کرده بود؛ نه completion، نه بی‌دانلودبودن و نه صحت همه CASC از آن نتیجه نمی‌شود.
- نبود توقف، دامنه را «تله‌متری» معرفی نمی‌کند؛ وجود TCP هم ارسال سخت‌افزار یا receipt/storage سرور را ثابت نمی‌کند.

## تصمیم بعد
برای همین سؤال غربالگری فعلاً block تازه/تکرار همه تست‌ها لازم نیست. **هیچ IP باقیمانده یا مجموع extraها را کورکورانه block نمی‌کنیم.**

کاربر به‌درستی پرسید آیا این block واقعاً اثر کرده است. **پیش از نتیجه‌گیری بعدی باید اثر واقعی block با کنترل مثبت و شاهد اتصال/افت منتسب به process اعتبارسنجی شود؛ DNS loopback به‌تنهایی کافی نیست.** نمونه کنترل مثبت باید شکست یک ارتباط مشخص را واقعاً نشان دهد و recovery داشته باشد؛ این سند به‌تنهایی مجوز ساخت/اجرای فایروال جدید نیست و هیچ rule تازه‌ای اجرا نشده است.

پس از این اعتبارسنجی، طراحی پایش محتوا با حفظ مبنای۰۲ انجام می‌شود: Agent اصلی و Battle.net هر دو، تا مسیر UI نادیده نماند؛ association واقعی Host/درخواست/API/زمان، محتوا پیش از رمزنگاری فقط در مسیرهای قابل مشاهده و diagnostics پوشش/خطا. مشاهده‌گر جدید هنوز ساخته/تحویل نشده و این گزارش مجوز ادعای دیدن payload نیست.

پیش از آزمون تازه وضعیت واقعی دانلود کاربر مشخص شود: هنوز داده‌ای برای دانلود باقی است یا آپدیت تمام شده؟ اگر تمام شده برای تولید ترافیک بازی پاک/rollback/Repair یا از اول دانلود نشود. اگر هنوز باقی است، آزمون بعد محدود و پس از READY با Resume دستی طراحی شود.

پس از restore موفق هیچ block این ابزار باقی نمی‌ماند. اگر آزمایش فعلاً تمام است Battle.net از tray دستی Exit شود؛ Pause جلوی همه فعالیت پس‌زمینه را نمی‌گیرد.

## منابع و صحت
- [شواهد/هش‌های تمام ورودی‌ها](destination-recon-r1-series-analysis.json)
- [جدول محاسبه‌شده CSV](destination-recon-r1-series-summary.csv)
- گزارش‌های اصلی: {', '.join(f'[{pid}](destination-recon-r1-user{pid}.json)' for pid in reports)}
- [اسکریپت تحلیل](../analysis/destination-recon-r1-series.py)

انتساب به دستگاه بر اساس فایل ارسالی کاربر است، نه signed provenance یا مشاهده زنده عامل. schema هر شش فایل با validator R1 بررسی شد؛ شمارش پیشرفت/restore مستقیماً از raw و مستقل از جدول summary بازشماری شد؛ DNS map/list و endpoint grouping/set تطبیق داده شدند. profiler عمومی توان flatten این شکل تودرتو را نداشت؛ هیچ trial یا sample به این دلیل حذف نشد.
"""
(root/'analysis.fa.md').write_text(analysis)
status=Path('/data/analysis/recon-r1-user02/STATUS.fa.md').read_text()
b=status.encode()
assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()=='1394a947a0a73ff26d17e17033e4341729735924','Remote STATUS changed: reload rather than overwrite'
status=re.sub(r'\*\*آخرین به‌روزرسانی: .*? \(UTC\)\*\*','**آخرین به‌روزرسانی: '+datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')+' (UTC)**',status,count=1)
status=re.sub(r'\*\*مرحلهٔ فعلی: .*?\*\*','**مرحلهٔ فعلی: هر شش پروفایل R1/02–07 دریافت شد؛ همه reported_progress/Paused و restore دقیق. کاربر اثربخشی block را به‌درستی زیر سؤال برد: DNS loopback اثبات قطع شبکه نیست. فعلاً تست تازه نه؛ ابتدا اعتبارسنجی اثر واقعی مسدودسازی، سپس پایش محتوا. ابزار/rule تازه تحویل یا اجرا نشده است.**',status,count=1)
changes={
    'فقط 03-BAT3-Plus-OAuth.bat با Administrator؛ همان مبنا + oauth.battle.net. همه پردازش‌ها ابتدا بسته؛ Resume فقط بعد از READY؛ پایان تایمر Pause خودکار نیست. output/recon-03-*.json ارسال شود؛ بقیه پروفایل‌ها فعلاً نه':
    'فعلاً BAT/block جدید اجرا نکند؛ بگوید هنوز دانلود باقی است یا تمام شده. ابتدا طرح کنترل مثبتِ اثر واقعی block و انتساب اتصال/drop بررسی شود، نه اعتماد به hosts. سپس پایش محتوا؛ هیچ firewall rule تازه‌ای فعلاً اجرا نشده. اگر تستی نیست Battle.net دستی Exit شود',
    'گزارش اجرای R1/02 دریافت و بررسی شد؛ بسته تازه یا ورود مرورگر لازم نیست. اجرای ۰۳ از همان بسته موجود':
    'گزارش‌های R1/02–07 دریافت شد؛ فایل۰۲ تکرار بایت‌به‌بایت همان قبلی است. بسته جدید یا ورود مرورگر برای تحلیل لازم نیست؛ ابزار محتوای جدید هنوز ساخته/تحویل نشده',
    '**R1/02 اکنون اجرا و تحلیل شد؛ فعلاً فقط R1/03، نه U2 یا همه نسخه‌ها**':
    '**اکنون R1/02–07 همگی دریافت شدند؛ فعلاً تست block تازه نه؛ پایش محتوا گام طراحی بعد است**',
    'گزارش ۰۲ دریافت شد؛ هنوز مرحله پایش محتوا جداست و اکنون فقط وابستگی OAuth غربالگری می‌شود.':
    'گزارش‌های۰۲ تا۰۷ دریافت شده‌اند؛ همه reported_progress دارند، اما محتوای ترافیک نامعلوم است. پایش محتوا گام جداگانه بعد است.',
    'اقدام بعد فقط 03-BAT3-Plus-OAuth.bat از همان بسته. اگر READY نیامد Resume نشود؛ خطا گزارش شود. همه extras همزمان/انباشته نشوند، بازی حذف/Repair/rollback نشود.':
    'گام تاریخی بعد از۰۲، پروفایل۰۳ بود؛ اکنون هر۰۳ تا۰۷ هم دریافت شده‌اند. تست بیشتر فعلاً درخواست نمی‌شود؛ extras همزمان/انباشته نشوند و بازی حذف/Repair/rollback نشود.',
}
for old,new in changes.items():
    assert status.count(old)==1,old
    status=status.replace(old,new,1)
section="""
### نتیجه مجموعه R1/02–07 — بدون توقف گزارش‌شده، نه اثبات حریم خصوصی
- [تحلیل مجموعه و جدول کامل](../reports/destination-recon-r1-series-analysis.fa.md) · [شواهد ماشینی](../reports/destination-recon-r1-series-analysis.json).
- شش trial متمایز، پنج مورد جدید؛۰۲ عیناً فایل قبلی است. همه READY، reported_progress، reported_paused و restore دقیق؛ هر مرحله DNS تمام نام‌های همان پروفایل loopback بوده است.
- همه با Q پس از حدود۷۱ تا۱۰۶ثانیه از READY خاتمه یافته‌اند. sampler_errors به ترتیب۰۲…۰۷: ۰،۶،۱،۲،۰،۴؛ انواع خطا معلوم نیست. صفر خطا هم پوشش کامل نیست.
- Agent اصلی با همان هش در همه دیده شده؛ endpointهای TCP بعضی نمونه‌ها فرق دارد. این اثبات Host/fallback/محتوا نیست. R1 اصلاً CPU/payload جمع نکرده است.
- همه نسخه‌نشانگرها ابتدا و انتها12.1.5.70448؛ completion مستقل نداریم. extraها همزمان آزمایش نشده‌اند و همگی قابل حذف اعلام نمی‌شوند.
- تصمیم با پرسش تازه کاربر اصلاح شد: block/runner/build تازه اجرا نشود. DNS loopback به معنی قطع واقعی اتصال نیست. ابتدا کنترل مثبت و شاهد process-attributed connection/drop برای اعتبارسنجی روش؛ سپس پایش محتوا. هیچ firewall rule تازه اجرا نشده و ابزار محتوای تازه هنوز تحویل نشده است.
"""
marker='\n## وضعیت دستگاه و حدود مجوز'
assert status.count(marker)==1;status=status.replace(marker,section+marker,1)
status=status.replace('آخرین گزارش R1/02: پیش‌شرط‌ها تأیید، reported_progress و reported_paused؛ hosts بازیابی شده است. نسخه ابتدا و انتها 12.1.5.70448 است؛ این اثبات کامل‌بودن فایل‌ها نیست. درصد جدید اندازه‌گیری/اعلام نشده و وضعیت زنده از اینجا معلوم نیست.',
    'آخرین مجموعه R1/02–07: پیش‌شرط‌ها تأیید و در همه reported_progress و reported_paused؛ hosts هر بار بازیابی شده است. نسخه ابتدا/انتها12.1.5.70448؛ این اثبات تکمیل نیست. درصد یا بایت جدید نداریم؛ برای گام بعد وضعیت واقعی باقی‌مانده دانلود از کاربر پرسیده شود.')
marker='| 2026-10-18 | R1/02 دریافت شد؛ مبنای اصلاح‌شده برای ادامه غربالگری پذیرفته شد، نه اثبات privacy/completion | هر۲۰ DNS loopback، Q پس از حدود۷۵ثانیه، reported_progress، restore دقیق؛ بعد فقط OAuth/03 |\n'
assert status.count(marker)==1;status=status.replace(marker,marker+'| 2026-10-18 | R1/03–07 دریافت شد؛ با تردید کاربر در اثربخشی، اول اعتبارسنجی block واقعی لازم شد | DNS-only اثبات قطع شبکه نیست؛ هیچ rule جدید اجرا نشده؛ سپس پایش محتوا |\n',1)
(root/'STATUS.fa.md').write_text(status)
files=[
    {'path':'docs/STATUS.fa.md','content':status},
    {'path':'reports/destination-recon-r1-series-analysis.fa.md','content':analysis},
    {'path':'reports/destination-recon-r1-series-analysis.json','content':(root/'evidence.json').read_text()},
    {'path':'reports/destination-recon-r1-series-summary.csv','content':(root/'summary.csv').read_text()},
    {'path':'analysis/destination-recon-r1-series.py','content':Path(__file__).read_text()},
]
for profile,path in sources.items():
    if profile!='02':files.append({'path':f'reports/destination-recon-r1-user{profile}.json','content':path.read_text()})
(root/'push.json').write_text(json.dumps(dict(owner='kokononox',repo='battle-net-agent-lab',branch='main',
    message='docs: analyze six R1 profiles and stop blind destination blocking',files=files),ensure_ascii=False))
print(json.dumps({k:evidence[k] for k in ('unique_trial_count','reported_progress_count','restored_exactly_count','min_ready_to_end_seconds','max_ready_to_end_seconds','sampling_error_profiles','independent_checks')},ensure_ascii=False,indent=2))