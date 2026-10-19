# S3 — آزمایش بازیابی واقعی تغییرات محدود، فقط Windows موقت CI

**روی سیستم کاربر اجرا نشود؛ بسته/لانچر کاربری ندارد.** شرط‌های محیط github-hosted/Windows/repository فقط guard جلوگیری از اجرای اتفاقی‌اند، نه اثبات امنیتی یا attestation. SSTP/Battle.net/بازی اجرا نمی‌شوند؛ ترافیک دانلود یا telemetry در این مرحله آزمایش نمی‌شود.

## سؤال دقیق
آیا بعد از خروج ناگهانی driver آزمایش، یک Scheduled Task مستقل SYSTEM می‌تواند propertyهایی را که journal از قبل ثبت کرده به مقدار قبلی برگرداند؟ آیا یک تغییر تشخیص‌داده‌شده بیرونی و rule نامرتبط حفظ می‌شوند؟ S2 فقط export و timer receipt بود؛ S3 واقعاً Set-NetFirewallProfile و Set-NetFirewallRule را در runner موقت اجرا می‌کند.

## طراحی
- snapshot محلی PersistentStore برای مقدار واقعی تنظیم‌شده، نه فقط ActiveStore effective؛ طبق مستند Microsoft، NotConfigured برای GPO است؛ اگر مقدار محلی Allow/Block نباشد پیش از mutation توقف می‌کند، نه اینکه مقدار نامستند restore کند. مقدار effective قبل/بعد جدا سنجیده می‌شود.
- پوشه ProgramData یکتا با ACL فقط Admin/SYSTEM؛ journal قبل هر mutation با CreateNew و Flush(true) نوشته می‌شود. lock بین driver/worker مستقل از شبکه و با انتظار محدود است؛ خروج driver قفل سیستم‌عامل را آزاد می‌کند.
- سه fixture rule یکتا، محدود به IP مستندسازی198.51.100.17 و TCP9؛ هیچ درخواستی ارسال نمی‌شود. ruleهای موجود runner حذف یا disable نمی‌شوند. default outbound سه profile موقتاً Block می‌شود؛ Allowهای قبلی باقی‌اند، بنابراین این تست **اثبات default-deny/enforcement کل اینترنت نیست**.
- timer SYSTEM برای۷۵ثانیه بعد، قبل تغییرات ثبت و هویت task کنترل می‌شود. driver عمداً با Environment.Exit(73)، بدون finally/rollback خارج می‌شود. این crash تزریقی متعلق به ابزار است، نه فرایند Blizzard.
- سناریوی full: هر سه default و Enabled دو fixture تغییر می‌کنند؛ timer باید baseline را برگرداند. سناریوی partial_conflict: یک profile و fixtureها تغییر می‌کنند، مشخصات fixtureB با تغییر خارجی مصنوعی عوض می‌شود؛ timer باید بقیه را restore و B را با conflict حفظ کند. fixtureC خارج journal هم تغییر خارجی دارد و باید دست‌نخورده بماند.
- replay برای idempotence: بازگشت دوباره نباید Set تازه‌ای لازم داشته باشد. task و فقط fixtureهای همین GUID در پایان حذف می‌شوند. اگر timer تست را نگذرد، controller یک fallback بازیابی محدود دارد؛ fallback **هیچ‌وقت** به عنوان موفقیت timer محسوب نمی‌شود.

## محدودیت مهم compare-before-write
این مدل compare-before-write است، **CAS اتمیک نیست**. cmdletهای Windows برای تمام policy یک transaction/compare-and-swap اتمیک عمومی فراهم نمی‌کنند؛ بین خواندن و نوشتن race باقی می‌ماند و تغییر خارج از lock ابزار را نمی‌توان کامل منع/تشخیص داد. برابرشدن مقدار جدید با baseline یا مقدار ابزار نیز منشأ تغییر را معلوم نمی‌کند. S3 تضمین حفظ تمام تغییرات هم‌زمان نیست.

fingerprint فقط fixtureهای ساخته‌شده خود تست را پوشش می‌دهد؛ موتور عمومی برای همه ruleهای Local کاربر نیست. GPO، IPsec/WFP شخص ثالث، reconnect/IPv6/DNS/CRL/OCSP، reboot/power loss و enforcement SSTP/Level3 پوشش این gate نیستند. هیچ netsh import/reset یا snapshot سراسری overwrite نمی‌شود. journal stale/نام‌ها و enum نامعتبر رد می‌شوند؛ failure-injection همه پنجره‌ها را پوشش نمی‌دهد.

## معیار عبور
۱۷fixture تصمیم/schema، دو سناریوی زنده، مشاهده تغییر پیش از crash، receipt SYSTEM، baseline دقیق profile/Persistent+effective، برگشت fixtureA، conflict مورد انتظار B بدون overwrite، حفظ تغییر C، idempotence بدون Set تازه، حذف task/ruleهای همین آزمایش. receipt باید success و همه این شاهدها را داشته باشد؛ نداشتن receipt/پاس ناقص به معنی شکست است.

موفقیت روی runner **مجوز Apply روی دستگاه کاربر نیست**. ready-to-apply از این آزمایش استنتاج نمی‌شود. کاربر فعلاً Pause را نگه می‌دارد و S2 تکرار/BAT99/Enable/Disable انجام نمی‌دهد. backup خصوصی کاربر لازم نیست آپلود شود.

مرجع cmdlet profile و تفاوت storeها: https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2025-ps

## وضعیت آزمون
نسخه اول source40fd1b53 در run39187957739 با۱۶fixture و دو سناریو PASS شد. نسخه تکمیلی source9f7b568c برای رد مقدار NotConfigured محلی و اندازه‌گیری transition اکنون در حال آزمون است؛ هنوز receipt نسخه تکمیلی نداریم. هیچ بسته کاربری یا Apply تحویل نشده است.
