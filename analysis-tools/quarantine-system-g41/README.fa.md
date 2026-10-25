# G41 — آزمون یکپارچهٔ مصنوعیِ گیت، قرنطینه و بازیابی

این پوشه یک harness پژوهشیِ مخصوص VM تازهٔ GitHub-hosted Windows2025 است، نه EXE نهایی یا مسیر آمادهٔ اجرای نصاب. هیچ Setup یا payload واقعی Battle.net اجرا/دریافت نمی‌کند. helper خصوصی و کنترل owner/Job/lease از G40 فقط با namespace جدید کپی شده‌اند.

## سه حالت
- finish: client ساختگی داوطلبانه خارج می‌شود؛ watchdog بقیهٔ Job، شامل endpoint، را می‌بندد و سپس سیاست فایروال را برمی‌گرداند.
- cancel: کنترلر درخواست لغو می‌دهد؛ client و endpoint زنده‌اند و watchdog آن‌ها را قبل از بازیابی پایان می‌دهد.
- error: کنترلر واقعاً با os._exit(23) خارج می‌شود، بدون درخواست release یا اجرای finally پایتون. watchdog مستقل باید خروج کنترلر را با identity بومی تشخیص دهد و همان ترتیب پایان Job سپس restore را انجام دهد.

هر مورد Root/Job جدا دارد و موفقیت مورد قبلی پیش‌شرط ادامهٔ بعدی است. این سه حالت، لغو کل GitHub job، reboot، power loss یا کشته‌شدن هم‌زمان کنترلر و watchdog نیستند.

## ورودی/خروجی شبکه
فقط یک مقصد canary ثابت از us.version.battle.net روی443 به IPv4 عمومی resolve می‌شود. پیش از تغییر firewall، IP قابل اتصال انتخاب می‌شود. probe فقط TCP connect/close است؛ هیچ HTTP، TLS ClientHello، Cookie، شناسهٔ ساختگی یا بدنه‌ای به آن مقصد ارسال نمی‌شود. سرور همچنان IP و metadata/TCP fingerprint شبکهٔ VM را می‌بیند؛ ادعای ناشناسی مطلق نداریم.

client تحت Job باید پیش از gate به همان IP وصل شود، زیر gate نتواند وصل شود و در عین حال زنده و قادر به ارسال درخواست ساختگی به loopback باشد. بعد از restore، یک process مورد اعتماد با همان image پایتون به همان IP probe می‌زند؛ client قبلی عمداً پایان یافته است.

خود درخواست HTTP ساختگی با شناسهٔ ساختگی فقط به127.0.0.1 می‌رود، در capture خصوصی pending می‌ماند و403 دریافت می‌کند. endpoint هیچ مسیر upstream ندارد. کانال‌های ارتباطی زیر gate فقط استثناهای Runner.Listener/Runner.Worker برای CI هستند؛ این استثناهای گستردهٔ برنامه‌ای باید در محصول کاربر وجود نداشته باشند. target و endpoint هیچ مجوز خارجی ندارند، حتی به دو میزبان قبلی.

## گیت فایروال
قبل از هر mutation، export به before.wfw و fingerprint سیاست PersistentStore شامل profile، rule و application/port/address/service/interface/security filterها گرفته می‌شود. قبل از apply باید watchdog-ready و handle Job موجود باشند. marker gate-armed قبل از اولین mutation نوشته می‌شود تا تغییر ناقص هم نیازمند restore باشد.

اجازه‌های فعال PersistentStore غیرفعال و فقط مجوزهای مدیریتی CI ساخته می‌شوند؛ هر سه profile روی inbound/outbound block قرار می‌گیرند. ActiveStore قبل و بعد از probe/capture باید فقط همان استثناها را نشان دهد. این بررسی لحظه‌ای است، نه اثبات پیوستهٔ نبود هر transient یا پوشش همهٔ bypassها.

## بازیابی
watchdog خارج از Job کنترل‌شده اجرا می‌شود و خودش handle همان Job را نگه می‌دارد. ورودی‌هایش policy/fixture مورد اعتمادند، نه تنظیم کلاینت. lease را releasing می‌کند، TerminateJobObject می‌زند و ActiveProcesses=0 را از API بومی می‌خواهد. تنها بعد از این proof اجازهٔ netsh import هست. سپس fingerprint سیاست بازیابی‌شده باید برابر baseline شود و watchdog خارج شود. default allow یا restore بدون پایان Job وجود ندارد.

یک lock خصوصی زیر root، اجراهای recovery/fallback را سری می‌کند. fallback همان مسیر component-first را دارد، نه آزادسازی بی‌قید شبکه. اگر proof یا fingerprint رد شود، موفقیت ادعا نمی‌شود. یک workflow always-step فقط همین fallback مشروط را دوباره فراخوانی می‌کند.

watchdog یک process مستقل است، نه سرویس یا task پایدار پس از reboot. کل worker/VM از کار بیفتد، این نمونه تضمین بازیابی ماشین دائمی کاربر نمی‌دهد. VM آزمایش دورریختنی است. برنامهٔ ساختگی کد ثابت دارد و سرویس/BITS/Task یا broker بیرونی ایجاد نمی‌کند؛ این recovery به جای classifier سخت‌گیرانهٔ production برای نصاب واقعی قرار نگرفته است و استثنای تازه‌ای به آن نداده‌ایم.

## داده و دامنهٔ اعتماد
private root با helper G40-derived و ACL محدود SYSTEM/Administrators ساخته می‌شود. فرزندان محیط پالایش‌شده با متغیرهای مسیر سیستم می‌گیرند؛ credentialهای GitHub به fixture منتقل نمی‌شوند. payload ساختگی و captureهای خصوصی، pointer، context، .wfw و snapshot سیاست به artifact/commit نمی‌روند. فقط output/g41-evidence.json برای انتشار تعیین شده است.

source/worktree، helper، root، کنترلر و admin مورد اعتماد فرض شده‌اند. دفاع علیه admin یا تزریق به Runner نداریم. pipeline یک سیاست فایروال موقت را export/import می‌کند؛ hosts، DNS configuration، route، IIS، CA یا taskهای ویندوز را عمداً تغییر نمی‌دهد. تصمیم‌ها و ثبت‌های task طبیعی OS را این نمونه به نصاب منتسب نمی‌کند.

## اجرا
workflow `battlenet-system-g41.yml` فقط با branch/message دقیق و run_attempt=1 اجرا می‌شود. Python و C# و PowerShell قبل از mutation parse/compile می‌شوند. اجرای دستی روی سیستم روزمره توصیه نمی‌شود. گزارش باید با run_id و source_commit و hashهای checkout ویندوز تطبیق داده شود؛ اختلاف CRLF با LF جداگانه ثبت می‌شود.

## خارج از پذیرش این نمونه
دانلود واقعی، صحت manifest، تشخیص معنای HTTPS، Range/resume، TCP/UDP/IPv6 همه‌جانبه، rollback همهٔ stack شبکه، ادغام UI و امنیت مقابل مهاجم privileged. probe مثبت/منفی یک مقصد، گواهِ نبود همهٔ نشت‌های شبکه نیست. حتی موفقیت همهٔ سه سناریو، اثبات ضد فینگرپرینت بودن Battle.net نیست.

## وضعیت تأییدشده
سه سناریوی مصنوعی در source90071a495fd52fbd3b288e54ba542b194a9ba61a/run40240886787 موفق شدند؛ این نتیجه فقط برای همان source است. گزارش، hashها، شکست‌های قبلی و محدودیت‌ها در reports/quarantine-system-g41/RESULT.fa.md ثبت شده‌اند. PATHEXT استاندارد به محیط محدود افزوده شده تا export/import بومی، همگام و با exit code معتبر اجرا شود؛ ACL یا مجوز شبکه باز نشده است.
