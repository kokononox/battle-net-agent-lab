# G41 — قبولی یکپارچهٔ قرنطینه، گیت خروج و بازیابیِ مصنوعی

## نتیجهٔ پذیرفته‌شده
آزمون native روی GitHub-hosted Windows2025 با source `90071a495fd52fbd3b288e54ba542b194a9ba61a`، run `40240886787`، job `121312202815` موفق شد. زمان کل job در رابط گیت‌هاب 5m54s و مرحلهٔ integration برابر5m33s بود. گزارش از log کامل بازیابی شد؛ run/source تطبیق یافتند و16 hash فایل با تبدیل صریح checkout ویندوز LF→CRLF بررسی شد. hash خام runtime در accepted-evidence.json تغییر داده نشده است. پنج آزمون قرارداد کد نیز جداگانه روی لینوکس موفق بودند؛ این‌ها به تعداد اجراهای native اضافه نمی‌شوند.

| سناریو | قبل از گیت | اتصال مستقیم زیر گیت | درخواست قرنطینه | پایان کنترلر | باقی‌ماندهٔ Job قبل→بعد پایان اجباری | بازیابی fingerprint | اتصال پس از بازیابی |
| --- | --- | --- | --- | --- | --- | --- | --- |
| finish | وصل | مسدود |403، ثبت خصوصی |0 |1→0 |برابر baseline |وصل |
| cancel | وصل | مسدود |403، ثبت خصوصی |0 |2→0 |برابر baseline |وصل |
| error | وصل | مسدود |403، ثبت خصوصی |23، خروج واقعی os._exit |1→0 |برابر baseline |وصل |

در error، watchdog خروج کنترلر را با identity بومی تشخیص داد؛ کنترلر درخواست release نداد و finally پایتون اجرا نشد. بسته‌شدن stdin کنترلر می‌تواند client را خودبه‌خود خارج کند؛ عدد1 نشان‌دهندهٔ باقی‌ماندهٔ واقعی Job هنگام مداخلهٔ watchdog است، نه ادعای کشتن دو process در این سناریو. در cancel دو عضو زندهٔ Job پایان یافتند. watchdog در هر سه مورد خارج شد و fallback مشروط هم موفق بود.

در هر سه مورد، ActiveStore قبل و بعد از capture، گیت را تأیید کرد؛ فقط دو استثنای Runner.Listener/Runner.Worker برای مدیریت CI وجود داشت. target و endpoint مجوز خارجی نداشتند. client حین گیت زنده ماند، بنابراین منفی بودن probe ناشی از پایان برنامه نبود. پس از بازیابی، probe را process مورد اعتماد با همان image پایتون اجرا کرد؛ client قبلی عمداً پایان یافته بود.

درخواست ساختگی فقط به loopback رفت. شناسهٔ ساختگی در query خصوصی حفظ شد؛ credential شناخته‌شده حذف شد؛ receipt عمومی فاقد marker بود. private capture، policy backup، تنظیمات خصوصی و مسیرهای runtime به گزارش منتشرشده اضافه نشده‌اند. هیچ نصاب یا payload واقعی Battle.net اجرا یا دانلود نشد.

## علت خطای قبلی و اصلاح
محیط پالایش‌شدهٔ coordinator فاقد PATHEXT بود. آزمون Prepare-only روی Windows، با همان Gate و root خصوصی، تفاوت تک‌متغیره را نشان داد:
- بدون PATHEXT: export_exit_code=null، فایل backup موجود نبود، state ساخته نشد، backup_failed.
- فقط با PATHEXT ثابت `.COM;.EXE;.BAT;.CMD`: exit0، backup208896بایتی، state موجود، prepared=true.

مقایسه در source `0994a4d9a0f3a97428d22bcdf8ab104ff98867a3` و run `40240686811` است. export جداگانه در root خصوصی و RunnerTemp هر دو موفق بود؛ بنابراین برای رفع خطا ACL خصوصی را باز نکردیم. اصلاح تنها PATHEXT استاندارد را به محیط پالایش‌شده افزود؛ مجوز شبکه، میزبان، استثنای task یا دسترسی quarantine اضافه نشد. export/import علاوه بر بررسی فایل، اکنون exit code صحیحِ عددی و صفر را الزام می‌کنند. نبود exit code موفقیت نیست.

برای بازتولید تشخیص قدیمی، source دقیق diagnostic را استفاده کنید؛ clean_env در source پذیرفته‌شده دیگر عمداً PATHEXT را حذف نمی‌کند. probeهای diagnostic هیچ Apply/import/reset ندارند.

## تاریخچهٔ صادقانهٔ تلاش‌ها
| source | run | نتیجه |
| --- | --- | --- |
| e51c0eca69788a36d34e378b3fa4b8b656aefb73 |40238935411 |رد؛ receipt_timeout، بدون ردیف سناریو، fallback=false. شواهد اولیه برای تعیین مرحله کافی نبود؛ ادعای restore موفق ندارد. |
| f1c732b7040e149b73ff925de4c664a95c9ac2ba |40239544410 |رد؛ baseline موفق، backup_failed در prepare_gate، gate_armed=false؛ پایان Job و active0 اثبات شد، no_firewall_mutation=true. شبکه تغییر نکرد؛ این را restore موفق نمی‌نامیم. cancel/error اجرا نشدند. |
|2051027866cdcf3a75c35e33582c3d6af4c0493d |40240066185 |تشخیص read-only؛ export در root خصوصی و RunnerTemp هر دو موفق. |
|81326c27803a4eab73fb06f1eabd511af5243f17 |40240343587 |تشخیص read-only؛ export معمول موفق، Prepare در محیط پالایش‌شده با exit code=null رد شد. |
|0994a4d9a0f3a97428d22bcdf8ab104ff98867a3 |40240686811 |تشخیص read-only؛ تفاوت PATHEXT علت قابل‌بازتولید را نشان داد. |
|90071a495fd52fbd3b288e54ba542b194a9ba61a |40240886787 |قبول؛ هر سه سناریوی مصنوعی و fallback مشروط موفق. |

## مدارک
- accepted-evidence.json: گزارش خام پاک‌سازی‌شدهٔ اجرای پذیرفته‌شده.
- accepted-source-verification.json: hash runtime، hash source و تبدیل دقیق CRLF برای هر16فایل.
- initial-failure-* و pre-gate-failure-*: شکست‌های اولیه، جدا از موفقیت نهایی.
- export-diagnostic*.json، prepare-diagnostic.json و pathext-diagnostic.json: تشخیص‌های بدون تغییر فایروال.
- verify_report.py: تطبیق گزارش با source/run و assertion مستقل تمام سه سناریو.
- test_static_contract.py و static-contract-tests.txt: پنج آزمون آفلاینِ قرارداد کد، نه اثبات native.
- g40-parity.json: هفت جزء G40 فقط با namespace جدید کپی شده‌اند؛ static-safety-checks.json نیز صرفاً بررسی منبع است.

## حدود نتیجه و قدم بعد
این یک milestone پژوهشی است، نه محصول نهایی یا EXE تحویلی. پیاده‌سازی عمومی Unified Firewall Desktop0.9.10/main دست‌نخورده ماند. این قبولی اجازهٔ اجرای واقعی Battle.net یا تأیید محتوای HTTPS نیست. probe مثبت/منفی یک IPv4/پورت، پوشش همهٔ مقصدها، IPv6، UDP، transient bypass، brokerهای بیرونی یا مهاجم دارای admin را اثبات نمی‌کند. دو استثنای گستردهٔ برنامه‌ای CI نباید در محصول کاربر باقی بمانند. reboot، لغو کل worker یا مرگ هم‌زمان controller/watchdog در این سه سناریو آزمایش نشده است.

تنها canary خارجی us.version.battle.net:443 بود؛ TCP connect/close بدون HTTP یا TLS ClientHello. مقصد IP و metadata/TCP fingerprint را همچنان می‌بیند. ناشناس‌سازی یا ضد‌فینگرپرینت بودن Battle.net اثبات نشده است. classifier و recovery سخت‌گیرانهٔ نصاب واقعی با این harness جایگزین نشده و هیچ استثنای تازهٔ task به آن داده نشده است.

قدم بعدِ مرتبط با هدف: بررسی استاتیک bootstrap رسمی و استخراج منابع/manifest لازم برای broker محدود، بدون اجرای نصاب، بدون capture خصوصی منتشرشده و بدون عبور دادن HTTPS ناشناخته. تا resource معتبر با path/size/hash و بررسی محتوای لازم تأیید نشود، catalog واقعی بسته می‌ماند. امضای ناشر یا مجاز بودن نام میزبان، به‌تنهایی ثابت نمی‌کند داده‌ای برای fingerprinting ارسال نمی‌شود.
