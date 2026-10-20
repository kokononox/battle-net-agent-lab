# تحویل جلسهٔ مدیریت شبکه و حریم خصوصی — ۲۰۲۶-۱۰-۲۰

این سند خلاصهٔ ساختاریافتهٔ تصمیم‌ها/نتایج برای ادامهٔ کار است، نه رونویسی خام همهٔ پیام‌ها. تاریخ‌های داخلی گزارش‌های کاربر فقط برای هویت نمونه‌اند؛ از ساعت نام فایل، ترتیب قطعی همهٔ وقایع استنتاج نشده است.

## وضعیت فعلی و خواستهٔ کاربر
هدف: کنترل ارتباط‌های WoW Retail و آپدیت رسمی در محیط آزمایشی، برای کاربرد احتمالی ۲۵ سیستم، با حساسیت ویژه به ارسال CPU/BIOS. کاربر راه دانلود مستقیم فایل رسمی را قبلاً دنبال کرده ولی به‌علت دشواری فعلاً کنار گذاشته است. سیستم آزمایشی است؛ عامل دسترسی مستقیم به Windows ندارد. کاربر خواهان کاهش تست‌های تکراری است.
آخرین خواسته: تحلیل ایستای ZIP حاوی بازی و sync کد/نتیجه/جلسه در مخزن موجود. [یافتهٔ جدید CPU/BIOS در schema](WOW-STATIC-2026-10-20.fa.md) مرحلهٔ فعلی است. فعلاً اقدام/نصب/تست دیگری روی Windows درخواست نشده است.

## ۱. ایزولاسیون و Level3
- برنامهٔ whitelist با Apply + exit و Restore ساخته شد؛ آخرین snapshot منبع محلی 0.1.2 در `user-tools/session-20261020/sstp-whitelist-0.1.2` حفظ شد. این snapshot جای ادعای تأیید backendهای آزمایشی قدیمی P1–P15 نیست.
- کاربر ابتدا شکست اتصال whitelist و خطاهای domain cache/active overlay دید. یک تست دامنه به IPv6 روی Wi-Fi رفت؛ ناموفق‌بودن TCP443 روی CDN، اثبات بسته‌بودن ICMP یا HTTP80 نیست.
- در عمل DNS دامنهٔ `level3.blizzard.com` چند بار تغییر کرد؛ کاربر IPهای بیشتری به config افزود و سپس whitelist را متصل و نمونه‌های خارج فهرست را قطع گزارش کرد. allowlist آی‌پی معادل احراز هویت دامنه نیست؛ CDN/shared IP و DNS refresh محدودیت باقی‌اند.
- سؤال reboot: قواعد پایدار و رفتار اتصال آغازین باید جدا آزموده شوند؛ کاربر گزارش کرد با kill switch قدیمی Wi-Fi پس از restart تا Disable وصل نمی‌شود. **این مسئله حل نشده؛ کاربر ادامهٔ آن را فعلاً متوقف کرد.**
- نمونهٔ موفق content 0.1.3: ۱۹ GET بازسازی‌شدهٔ Agent به Level3 روی HTTP80، همگی `/tpr/…`، بدنه و query خالی، بدون Cookie/Authorization و بدون marker شناخته‌شدهٔ سخت‌افزار. ۱۰ درخواست به2.21.244.146 و۹ به2.21.72.210. این نتیجه فقط همین درخواست‌های کاملِ مشاهده‌شده است، نه صفر تله‌متری همهٔ سیستم.
- مرجع: [شواهد](../reports/session-20261020/level3-content-013-evidence.json). درخواست‌های دانلود هم نیاز به ارسال GET/TCP ACK دارند؛ «فقط دانلود» به معنی صفر بایت خروجی نیست.

## ۲. تفکیک لانچر و بازی
ابتدا file picker برای انتخاب EXE و ثبت مقصدها اضافه شد، سپس تمرکز به Wow.exe و فرزندان مشاهده‌شده تغییر کرد. whitelist در نمونهٔ مقصد 0.1.5 به تأیید کاربر خاموش بود. دو مقصد HTTP از مرحلهٔ موقت دانلود شروع لانچر آمدند. ۵۴ ردیف فرایند/مقصد، ۳۸ loopback و۱۶ public با۹ مقصد public یکتا ثبت شدند؛ loopback را با ارسال اینترنتی یکی نگیرید. همهٔ publicهای گزارش به Wow نسبت داده شدند، نه صرفاً Agent. [شواهد](../reports/session-20261020/game-destinations-015-evidence.json).

## ۳. تزریق ناموفق و تغییر مسیر به passive
در 0.1.6–0.1.8، Wow.exe با هویت ثابت انتخاب شد و helper/fixture گذشت، ولی attach به ProcessNotRespondingError در device_attach رسید. `hook_ready=false` و صفر event، بنابراین هیچ محتوای واقعی بازی از این روش به دست نیامد. بازی عادی به صفحهٔ ورود رسید؛ علت anti-cheat یا pinning ثابت نشده. تأخیر/manual Enter هم مسئله را حل نکرد. صرفاً تغییر timing دوباره تکرار نشود.
منبع patchهای تاریخی 0.1.3 و0.1.8 جهت تداوم حفظ شد؛ overlay هستند، نه full standalone. این sync مجوز retry injection یا دورزدن حفاظت نیست.

## ۴. passive 0.2.0 — نخستین نقشهٔ معتبر مقصد بازی
نمونه `d61e7b08-489d-496f-b4a8-c458aa51f0cc`: حدود۶۰٫۷۷ ثانیه، ۱۲ flow TCP انتخاب‌شده همگی Wow. توقف capture خودی تأیید، دو ETL parse، شمارندهٔ loss گزارش‌شده صفر؛ یک sampler error و پرچم stream-prefix/overlap وجود داشت، پس پوشش کامل ادعا نمی‌شود.
SNIهای مشاهده‌شده: `breaking-news.support.blizzard.com`، `eu.account.battle.net`، `wow.ingest.gdp.blizzard.com`، `prod.depot.battle.net` و `oauth.battle.net`. نام `eu.actual.battle.net` برای اتصال1119 تنها DNS candidate بود؛37.244.29.11:3724 دامنهٔ قطعی نداشت. دو GET Level3 به2.21.23.92 و2.21.23.7 بدنه/query/Auth/cookie/marker سخت‌افزار نداشتند. [شواهد](../reports/session-20261020/passive-020-evidence.json).

## ۵. فایل 5.bat کاربر و وضعیت پس از بلوک
کاربر با hosts blocking گزارش کرد بازی درست کار می‌کند. فایل5.bat فقط wow.ingest را تغییر نمی‌دهد: telemetry-in.battle.net، breaking-news، rum، دامنه‌های analytics/store/CDN UI و YouTube نیز در آن هستند. hosts، فایروال یا تضمین قطع directIP/customDNS/IPv6 نیست. backup آن در اجرای تکراری overwrite می‌شود. خود فایل با state زندهٔ hosts یکی نیست و در این sync به‌عنوان سیاست کامل توصیه نشده است.

## ۶. آزمایش proxy/TLS شکست خورد — بازیابی موفق بود
- کاربر با CA موقت CurrentUser موافقت کرده بود. Game-TLS-Inspector0.1.0 برای چند مقصد ساخته شد؛ تست‌ها/loopback پاس، ولی این موفقیت game login نبود.
- نمونهٔ اول چون بازی قبلاً باز بود refuse کرد. نمونهٔ دوم۳ TLS-client-established، صفر TLS-failed ثبت کرد، ولی فقط دو HTTPGET ساده به CDN دیده شد؛ بازی در login خطا داد. این counters اثبات بازرسی موفق همهٔ TLS بازی نیستند.
- پایان proxy timeout شد و cleanup نتوانست نبود root را تأیید کند. علت دقیق اختلال login مشخص نیست. pinning/anti-cheat را قطعی ننویسید؛ احتمال race در خواندن وضعیت process/cleanup و شکاف authority/SNI فقط عیب‌های محتمل/باز ابزارند.
- recovery مستقل ابتدا حذف و سپس نبود CA خودی را کنترل کرد، بعد cleanup فرایندِ مالکیت‌دار. گزارش `2cfc5ee4-6430-4d08-a315-603e27a52d97`: `root_absence_verified=true`، error null؛ certificate_removed=false یعنی هنگام این بررسی قبلاً غایب بود. نبود proxy خودی اثبات نبود همهٔ proxyهای سیستم نیست. کاربر بازگشت بازی به حالت عادی را تأیید کرد.
- کد آزمایش ناموفق فقط با هشدار DO-NOT-RUN حفظ شده؛ bin/CA/key/runstate حذف از sync. recovery مستقل در پوشهٔ جدا است. **proxy گسترده دوباره پیشنهاد/اجرا نشود.**

## ۷. آخرین بستهٔ کامل passive0.2.1 و آخرین نمونهٔ کاربر
پکیج کامل با runtime رسمی CPython3.13.12 و بدون Frida/mitmproxy تحویل شد؛ ۳۳ unit/mock پاس و یک اجرای واقعی کاربر داده تولید کرد. این مخزن فقط source subset را دارد؛ runtime باینری حذف شده و manifest اصلی فایل‌های omitted هم دارد. Start.cmd در checkout بدون بازسازی runtime، بستهٔ آمادهٔ اجرا نیست.
نمونهٔ آخر `cc64c5ac-8211-4e94-9dd7-e75b45108351`،۶۶٫۳۵ثانیه با overhead توقف، ۸flowTCP ازWow، sampler/identity errors صفر، دوETL parse، loss counters گزارش‌شده صفر:

| مقصد | شاهد نام | چه چیزی دربارهٔ محتوا می‌دانیم؟ |
| --- | --- | --- |
|2.21.23.77:80 و2.21.23.7:80|HTTP Host: level3.blizzard.com|دوGET `/tpr/…`، body/query خالی؛ marker حساس دیده نشد|
|52.29.86.120:443|SNI eu.account.battle.net|TLS؛ body نامعلوم، نام با سرویس حساب سازگار است نه اثبات نوع فیلد|
|3.125.189.135:443|SNI oauth.battle.net|TLS؛ محتوای واقعی رمزگشایی نشده|
|34.117.122.6:443|SNI prod.depot.battle.net|TLS؛ وجود نام depot اثبات صرفاً دانلود نیست|
|34.147.74.225:1119|DNS candidate eu.actual.battle.net|نام از DNS، نه اثبات binding محتوایی|
|37.244.29.93:3724|نام برنامه نامعلوم|پروتکل بازی رمزگشایی نشده|
|66.40.180.165:3724|نام برنامه نامعلوم؛ASN57976|مالکیت Blizzard، نه اثبات کارکرد/فیلد|

wow.ingest وIP قبلی35.201.91.89 در metadata flowهای انتخابی دیده نشدند؛ با بلوک سازگار است، نه تضمین عدم ارسال/عدم جایگزین. [شواهد کامل](../reports/session-20261020/passive-021-evidence.json).
مالکیتASN از RIPE: https://stat.ripe.net/data/network-info/data.json?resource=66.40.180.165 و https://stat.ripe.net/data/as-overview/data.json?resource=AS57976 . پاسخ PTR موفق نبود؛ «دامنه ندارد» نتیجه نشده است.

### حدود passive
capture در سطح NIC سیستم است، ولی گزارش shared فقط TCPهای منتخب را باPID/starttime/path/hash و فرزندان مشاهده‌شده نسبت می‌دهد؛ UDP به process نسبت داده نشده و DNS metadata سیستمی است. انتخاب frame4096، حدود60ثانیه/16MiB چندفایلی، watchdog90ثانیه و softbudget حدود96MiB پوشش کامل را تضمین نمی‌کنند. پرچم prefix/overlap و ندیدن VPN inner باقی است. شمارش بایت capture معادل upload unique نیست. TLS و پروتکل1119/3724 رمزگشایی نشده‌اند. capture خام ماشین و کلیدها عمداً منتقل نشده‌اند.

## ۸. تحلیل ایستای جدید و تفکیک شواهد تاریخی
[گزارش EXE](WOW-STATIC-2026-10-20.fa.md): descriptor واقعی ClientEngineLogV2 برای cpu_brand و فیلدهای BIOS استخراج شد. همین فایل با نمونهٔ runtime قبلی SHA یکسان دارد. هیچ باینری کاربر اجرا نشد. source اصلی/جریان دادهٔ کامل بازی بازیابی نشده است.
شاهد پیشین Agent در مخزن جدا حفظ می‌شود: CPU مدل ماشین موقت در ورودی POST `/data` به telemetry-in.battle.net پیش از رمزگذاری دیده شد؛ این نه BIOS بود، نه نمونهٔ خود Wow.exe، نه اثبات دریافت/ذخیرهٔ سرور. نبود marker در Level3 آن شاهد را باطل نمی‌کند. مرجع ثابت: https://github.com/kokononox/battle-net-agent-lab/blob/27d065c1846b0a7be16fd38980511edffe6d6d04/reports/startup-ab-api-h1-analysis.fa.md .

## گام بعد و شرط توقف
- ابتدا schema/loader و مسیرهای فراخوانی را آفلاین بررسی کنید؛ صرف رشته/نام endpoint را به ارسال runtime ارتقا ندهید. Wow .text محافظت/تبدیل‌شده به نظر می‌رسد و dataflow مستقیم فعلاً بازیابی نشده.
- passive تکراری محتوای TLS تازه نمی‌دهد؛ فقط اگر سؤال تازهٔ مقصد/مرحلهٔ بازی داریم اجرا شود.
- وضعیت login/in-world را از پیام خود کاربر بگیرید؛ صفحه login یا نتیجهٔ sample مساوی ورود موفق/جهان بازی نیست.
- هیچ repair/CASC write، نصب تازهٔ Classic، تغییر hosts/firewall، ورود حساب، غیرفعال‌کردن حفاظت یا تست reboot بدون دامنهٔ مشخص تازه انجام نشود. رفع Wi-Fi reboot هنوز backlog است.
- تضمین «صفر ارسال سخت‌افزار» یا «فقط Level3 برای همهٔ بازی کافی است» صادر نشده است.

## کد، artifact و دامنهٔ sync
منبع ابزارهای نهایی، patchهای تصمیم‌ساز تاریخی و منبع آزمایش TLS ناموفق با هشدار حفظ شدند. گزارش‌های shared فقط مشتق‌های پاک‌سازی‌شده‌اند، نه raw capture. [manifest این sync](SESSION-SYNC-2026-10-20.json) فهرست دقیق فایل‌ها/هش‌ها و artifactهای محلی را مشخص می‌کند. تاریخچهٔ مخزن، سایر شاخه‌ها و نظریات همکاران بازنویسی/merge نشده‌اند. این sync هیچ workflow جدید، runner پولی یا مجوز نصب/ورود ایجاد نمی‌کند؛ workflowهای موجود تغییری ندارند و trigger آن‌ها تابع تنظیمات قبلی مخزن است.
