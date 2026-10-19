# S3U با استثنای محدود CI — دو دور بازگردانی و حذف قواعد موقت موفق

## نتیجهٔ فعلی
اجرای `39195750447` از منبع `d62a0e6c548515ed5bd4139eb06983b99249fd37` روی standard windows-2025، validate و publish را موفق تکمیل کرد. این بار رسید native دو دور کامل روی همان VM دارد: passed=true، stage=complete، ۱۳fixture native و دو بار تایمر مستقل SYSTEM؛ fallback کنترل‌کننده لازم نشد. در هر دور stored state، effective CIM/COM، مقدار/نوع/وجود valueهای هفت مسیر محدود registry و ویژگی‌های منتخب rules تطبیق داده شدند؛ replay بدون write، TaskResult=0 و حذف task ثبت شد. خواندن registry فقط‌خواندنی بود و هر دور حضور DefaultOutboundAction در مسیرهای بررسی‌شده ۰→۳→۰ ثبت شد.

هش هر چهار PowerShell native با منبع CRLF تطبیق داده شد و نسبت به اجرای تشخیصی قبلی تغییر نکرده است: Core، Timer، Driver و Run-CI. guard S3، baseline، زمان۷۵ثانیه تایمر native و assertionهای قبولی تغییر نکردند. این PASS محدود به provider/بازگردانی روی همین WindowsServer build26100 و PowerShell5.1.26100.33438 است؛ نه تست SSTP یا enforcement محصول و نه آزمون Windows11 کاربر. user_device_tested=false و ready_for_user_apply=false باقی ماندند.

## استثنای جداگانه و محدودِ میزبان آزمایش
دو قاعده Allow موقت برای مسیر اجرایی دقیق Runner.Listener و Runner.Worker ساخته شد، فقط TCP remote-port443 و فقط host-IPهای اتصال Established همان پردازش‌ها. مجموع IPهای یکتا۴ بود. Any مقصد/برنامه، زیرشبکه وسیع، تغییر DNS/route/VPN/hosts، غیرفعال‌کردن rules موجود یا Allow عمومی اضافه نشد. فایل‌ها و مسیرهای executable، یکتایی process، نبود reparse و hash پایدار بررسی شدند؛ اینها شناسایی runtime در image مورداعتماد hostedCI هستند، نه attestation مستقل origin/signature یا تضمین ثبات executable در برابر admin مهاجم. TCP443 و owningPID نیز به‌تنهایی attestation نام میزبان/TLS نیستند. IPها فقط محلی و در journal محافظت‌شده ماندند.

این helper عمداً جدا از چهار فایل native است: ایجاد/حذف قواعد خود fixture را انجام می‌دهد و قبل از آزمون native به‌طور صریح اجرا می‌شود. prohibitionهای native تغییر نکردند؛ نباید وجود Allowهای fixture را پنهان یا محصول را default-denyِ بدون استثنا معرفی کرد. قواعد هنگام snapshot native وجود داشتند و در پایان helper حذف شدند. هفت fixture ساده native برای فیلتر host-address و۱۴fixture محلی Python برای schema و scope رسید بررسی شدند؛ جدا از۱۳fixture recovery هستند.

## پاک‌سازی ثبت‌شده
setup_succeeded=true، cleanup_attempted=true، cleanup_succeeded=true؛ rules_created=2، rules_removed=2، remaining_rules=0. profiles_exact=true و selected_rules_exact=true نسبت به snapshot قبل از helper ثبت شد و task پاک‌سازی helper هم حذف شد. این بررسی، همه فیلترهای WFP و همه ویژگی‌های policy را پوشش نمی‌دهد.

پیش از ایجاد قواعد، journal در پوشه ACLدار Admin/SYSTEM نوشته و task SYSTEM انقضای هفت‌دقیقه‌ای با کنترل هویت آماده شد. در این اجرا پاک‌سازی مستقیم موفق شد؛ timer_fallback_used=false. بنابراین مسیر اجرای واقعیِ انقضای helper با این PASS آزموده نشده است. cleanup از قفل جلسه و compare-before-delete روی قواعد نام‌گذاری‌شده متعلق به fixture استفاده می‌کند؛ compare/delete اتمیک نیست و دفاع مقابل admin مهاجم هدف این آزمون نیست. private journal و نام/IP/pathها آپلود نشدند.

## کانال کنترل و تفسیر درست تشخیص
در دو فایل بررسی‌شده، هیچ تطبیق برای HTTP/Socket، exception تمدید job یا لغو worker ثبت نشد. همراه با موفقیت انتظار بدون تغییر شبکه و شکست‌های قبل، این نتیجه از فرضیه اختلال کانال کنترل runner در آزمایش قبلی پشتیبانی می‌کند. آزمایش‌ها هم‌زمان یا روی همان VM قبلی نبودند؛ علت ریشه‌ای دقیقِ هر شکست قبلی از این نتیجه به‌تنهایی اثبات نمی‌شود.

**نکتهٔ schema:** در رسید diagnostic قدیمی `network_exception_added=false` مقدار ثابت جمع‌کننده است؛ درباره کل workflow نباید از آن نتیجه گرفت که Allow اضافه نشده. در این اجرا واقعاً دو Allow مخصوص fixture اضافه و حذف شد؛ منبع حقیقت، رسید ci-control و کد helper است. رسید اصلی دستکاری نشد. این محدودیت نام‌گذاری برای مصرف‌کنندگان رسید مهم است.

## دامنهٔ محصول و توضیح کاربر
کاربر دوباره فایل‌های BAT۶ و۹۹ را فرستاد و پرسید چرا نمی‌توان قابلیت بستن/بازکردن مسیرهای خارج SSTP را به آن‌ها افزود. فایل‌های ارسالی فقط خوانده شدند، نه اجرا؛ BAT۶ دقیقاً با blob5149527468b78a284c4ac2ffa073fb67f9037dea برابر بود. هر دو فقط hosts را تغییر می‌دهند؛۹۹ پاک‌کردن فهرست است، نه reset کامل فایروال یا بازیابی کل تنظیمات.

قبل از ساخت نسخهٔ نهایی یک تفکیک باید با کاربر روشن شود: **A)** حفظ BAT۶ و اجازه ترافیک فقط از SSTP holand (با ارتباط‌های لازم برای برقراری خود تونل)، یا **B)** علاوه بر A، enforce کردن فقط Level3 حتی داخل تونل. حالتA همان allowlist تک‌مقصدی کل اینترنت نیست. این انتخاب هنوز تأیید نشده؛ اجرای محصول یا گسترش تست‌های مقصد تا روشن‌شدن آن متوقف است. آزمایش CI درحال‌اجرا با بررسی پاک‌سازی تکمیل شد؛ runner یا task ادامه‌دار عمداً باقی نماند.

روی دستگاه کاربر هیچ تغییر یا Apply انجام نشد. BAT۶/holand و وضعیت Pause حفظ شوند؛ دستور/BAT99/toggle/Resume تازه لازم نیست. تنها runnerهای استاندارد استفاده شدند؛ larger/paid runner فعال نشد و هزینه صفر تضمین نشده است.

## منابع
- [اجرای موفق](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39195750447)
- [منبع fixture و workflow](https://github.com/kokononox/battle-net-agent-lab/commit/d62a0e6c548515ed5bd4139eb06983b99249fd37)
- [رسید native](sstp-unset-s3u-success-39195750447.json)
- [رسید ایجاد/حذف fixture](sstp-ci-control-success-39195750447.json)
- [شمارنده‌های diagnostic](sstp-runner-signals-success-39195750447.json)
- [رسیدهای منتشرشده خودکار](https://github.com/kokononox/battle-net-agent-lab/tree/12c27ae0b34795f867bde80ae7a176eeecf18a58/reports)
- [شاهد لغو قبلی](sstp-runner-control-analysis.fa.md)
