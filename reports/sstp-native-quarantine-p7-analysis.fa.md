# P7 — قرنطینه واقعی Allowهای موجود و بازیابی Enabled اصلی

## هدف و محدوده
گزارش کاربر صد Allow فعال محلی را نشان داده بود. default outbound=Block به‌تنهایی آن Allowها را خنثی نمی‌کند. این مرحله کتابخانهٔ واقعیِ ثبت snapshot، غیرفعال‌کردن و بازگرداندن دقیق Enabled را پیاده می‌کند؛ تست فقط روی fixtureهای CI است، نه صد قانون واقعی کاربر.

## تغییر نسبت به مراحل قبلی
P4 فقط مدل فایلی بود و P3/P5 هرگز قوانین را فعال نمی‌کردند. P7 واقعاً Set-NetFirewallRule را روی قوانین فعال ساختگی اجرا می‌کند و Enabled را False و سپس True اصلی برمی‌گرداند. fingerprint کامل CIM و هفت فیلتر کنترل می‌شود؛ نه فقط نام یا Enabled. snapshot اصلی محفوظ می‌ماند. برخلاف Force-Allow یا reset، Restore فقط همان قوانین ثبت‌شده را بازیابی می‌کند.

## اجرای بومی
- منبع: 5126e36144b2538c2837f384c9fd67e8e8b7da48
- اجرا: https://github.com/kokononox/battle-net-agent-lab/actions/runs/39206606322
- **نتیجه نخستین اجرا: failed، نه PASS.** هر۸۷check داخلی تکمیل شد؛۱۰termination و۱۰recovery در فرایند تازه و۲Restore مستقیم از Quarantine ناقص ثبت شدند. هر۲۹fixture پاک شد، remaining=0 و baseline منتخب پروفایل‌ها برابر بود؛ اما existing_rule_properties_unchanged=false و error=quarantine_baseline_mismatch. نبود جزئیات diff در رسید اول اجازه تعیین علت نمی‌دهد.
- SHA256 artifact اول: `732ac8511f975b185e47aa056ab5eab79f1d2ded6a1a7c4250ac4dfc69839b7d`؛ هویت source/run و هر۶hash منبع با کد مربوط، با لحاظ LF/CRLF checkout، مستقلاً تأیید شد.
- نسبت‌دادن اختلاف به background Windows، ناچیز شمردن آن، یا اعلام عدم تغییر قوانین قبلی مجاز نیست. هیچ شرط baseline از تست برداشته نشده است.

## اجرای تشخیصی دوم
- منبع: `51056e9ce0cc960e4b59cb6f2ec54405218d02d8`
- اجرا: https://github.com/kokononox/battle-net-agent-lab/actions/runs/39207924748
- تغییر: lookup الزامی یک قانون با escaped Name و require-exact-local، بدون تلقی provider/not-found به‌عنوان absence؛ همان snapshot کامل و همان معیار baseline. شمارش افزوده/حذف/اصلاح قوانین نامرتبط و فقط نام فیلدهای متفاوت اضافه شد؛ نه نام/مقدار قوانین. قالب رسید جدید نسخه۲ است. هدف کاهش queryهای کل store و ثبت منشأ اختلاف است؛ تغییر lookup به‌تنهایی درمان علت اختلاف اول اثبات نشده است.
- **نتیجه: failed.** checks=87، termination=10، fresh_process_recoveries=10، partial_restores=2، remaining=0؛ profiles_unchanged=true و existing_rule_properties_unchanged=false.
- delta قوانین نامرتبط: added=0، removed=0، modified=2؛ property_names=["Description", "DisplayGroup", "DisplayName"]. این تشخیص فقط نام فیلد و شمارش است و نام/مقدار قوانین را صادر نمی‌کند.
- error_code=quarantine_baseline_mismatch. تطبیق digest ZIP، source/run و هر۶hash منبع مستقلاً بررسی شد. تغییر query علت اختلاف اجرای اول را به‌تنهایی ثابت نمی‌کند.

## سازوکار
write-ahead قبل از هر setter، قفل کل فراخوانی و journal با ACL/flush/revision از P2؛ تطبیق کل frontier پیش/پس از تغییر و ادامه در فرایند تازه فقط با حالت قبل/بعد دقیق همان تغییر معلق. Restore از Quarantine ناقص هم مقدار اصلی هر قانون را برمی‌گرداند. journal خراب/گمشده، تداخل فیلتر خارجی یا تغییر یکی از قوانین بعدی موجب توقف پیش از mutation است. Set با InputObject از wildcard شدن نام قوانین موجود جلوگیری می‌کند.

## محدودیت‌ها و گام بعد
این کتابخانه guard ندارد و اجرای مستقلش روی قوانین واقعی دستگاه کاربر توصیه/تأیید نشده است. باید به coordinator با guard پایدار و تأییدشده، ثبت/بازگردانی stored profile defaults و مدیریت موجودی کامل effective policy متصل شود. قفل journal فقط اجرای همکار را سریالی می‌کند، نه مدیر هم‌زمان/GPO؛ check و syscall اتمیک نیستند. ظرفیت journal برای snapshot صد قانون واقعی هنوز اندازه‌گیری نشده است.

کد CI هیچ setter پیش‌فرض پروفایل یا guard کل سیستم ندارد؛ baseline منتخب پروفایل‌ها در اجرای اول برابر بود. fixtureها برنامهٔ تصادفی ناموجود، آدرس‌های رزروشدهٔ مستندسازی و TCP/65534 دارند. پاک‌سازی فقط fixtureهای همین اجرا با hash کامل است. baseline قوانین نامرتبط فقط property-level است؛ هفت فیلتر همهٔ قوانین نامرتبط جمع‌آوری نشده‌اند. فایل‌های خصوصی journal/snapshot آپلود نشده‌اند.

guard/default=Block، اعمال فیلتر SSTP و گذر واقعی بسته، DNS/IPv6/LAN، قطع‌وصل VPN، reboot و تضمین no-leak در P7 آزمایش نمی‌شوند. دستگاه کاربر تغییر نکرده است؛ هیچ فایل جدید برای اجرای کاربر یا فرمان Enable ارائه نمی‌شود. ready_for_user_apply=false. ورودی قبلی کاربر کافی است و گزارش تشخیصی تکراری لازم نیست.

## تعبیر دقیق اختلاف فعلی و شرط توقف
در اجرای دوم هیچ قانون نامرتبطی افزوده/حذف نشد و فقط **دو قانون** در فیلدهای `Description`، `DisplayGroup` و `DisplayName` متفاوت بودند. در این diff property-level تغییر `Enabled` یا `Action` گزارش نشد. این شاهد را نباید به «همهٔ فیلترهای قوانین نامرتبط دست‌نخورده‌اند» یا «حتماً Windows در پس‌زمینه این کار را کرده» تعمیم داد؛ آن فیلترها در baseline نامرتبط جمع‌آوری نشده‌اند و منشأ تغییر این سه فیلد هنوز تعیین نشده است. snapshot کامل و هفت فیلتر برای fixtureهای خودمان بررسی شدند.

این بار هم آزمون کل failed ماند، با وجود تکمیل هر۸۷check داخلی و۱۰recovery و cleanup صفر. برای سبزشدن تست، فیلدهای مزاحم از مقایسه حذف نشدند و reset یا broad Allow اضافه نشد. پیش از اجرای جهش‌دار دیگر، یک کنترل فقط‌خواندنی هم‌مدت/یا ردیابی محدود تغییر منبع لازم است تا تغییر برچسب‌های provider از اثر setter جدا شود. این کنترل هنوز اجرا نشده؛ سومین اجرای mutation بی‌فرضیه راه نیفتاد. پس از رفع این مانع آزمون، کار مستقل guard/coordinator/profile defaults و qualification فیلتر/packet هنوز باقی است.

SHA256 artifact دوم: `de981ffb4c730c46cc63d7845a790166a06cf0b8851a6e0da19a879de3fcb7d8`.
