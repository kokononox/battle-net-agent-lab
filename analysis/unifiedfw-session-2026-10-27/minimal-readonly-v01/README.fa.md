# بنیاد حداقلی خواندن پروفایل — نسخهٔ ۰٫۱

## چرا این مرحله؟

هدف نهایی همچنان ابزار کوچک اختصاصی نصاب Battle.net با ایزولاسیون و حمل SSTP است، نه dashboard یا زنجیرهٔ بی‌پایان ابزارهای تشخیص. این ماژول یک جزء کدِ آفلاین برای جداسازی reader از mutation runtime است؛ هنوز نصاب اجرایی، جایگزین controller یا مجوز Apply نیست.

## نتیجهٔ پیاده‌سازی

- `source/Ufw.ProfileReader.psm1` مستقل از همهٔ فایل‌های قدیمی است و فقط `Invoke-UfwProfilePreflightReadOnly` را export می‌کند.
- هنگام import، فقط تعریف تابع‌ها، StrictMode و Export اجرا می‌شوند؛ هیچ query بومی یا file I/O در import نیست. مسیر اجرایی، setter یا تابع تعریف‌کنندهٔ setter ندارد و runtime قدیمی را import نمی‌کند.
- دو مشاهدهٔ پیاپی از PersistentStore/ActiveStore گرفته می‌شود: در مسیر موفق مجموعاً چهار Get-NetFirewallProfile، نه query جدا برای هر profile/property. شمارندهٔ started/attempted calls در failure نیز تعداد شروع‌شده را ثبت می‌کند. این کاهش شمار query این reader است، نه benchmark سرعت کل Apply/Restore.
- نام، تعداد و یکتایی سه profile، fieldهای اجباری، encodingها و نبود interface exclusion کنترل می‌شود. null بی‌نوع برای exclusion نامعلوم است؛ فقط CIM StringArray null معتبر و array خالی یا marker NotConfigured پذیرفته می‌شوند. raw aliasها صادر نمی‌شوند و Ethernet/Wi-Fi نام یا index ثابت ندارند.
- وضعیت محلی و مؤثر جدا حفظ می‌شوند؛ Enabled محلی با مقدار مؤثر جایگزین نمی‌شود. NotConfigured بدون تبدیل به Allow گزارش می‌شود.
- Block معتبر می‌تواند «مشاهدهٔ موفق» باشد، اما normal mode یا اجرای ایزولاسیون تلقی نمی‌شود. `all_outbound_allow` فقط دربارهٔ دو مقدار outbound است؛ فایروال غیرفعال/عدم پذیرش local rules جداگانه review را ناسازگار می‌کند. حتی شواهد سازگار مجوز write نمی‌دهند.
- effective AllowLocalFirewallRules باید True باشد تا `profile_fields_compatible_for_later_review` true شود؛ False/NotConfigured یا Enabled مؤثر غیر True مانع آن‌اند. این guard محدود و سخت‌گیرانه است، نه migration سیاست سازمانی.
- اختلاف دو مشاهده failure است؛ برابری‌شان فقط برابری همین fieldهای خوانده‌شده را نشان می‌دهد، نه نبود تغییر بین آن‌ها یا پس از آن. snapshot اتمیک/locked نیست.
- هیچ فایل، ژورنال، rule، route، DNS، task یا VPN خوانده/نوشته نمی‌شود جز profile getterهای مشخص؛ منظور از «ژورنال» journal اختصاصی برنامه است. ماژول از سیستم‌عامل نمی‌خواهد audit/log جدید بسازد، اما رفتار داخلی Windows provider را نمی‌توان از روی تست mock تضمین کرد.
- `ready_for_apply`, `normal_mode_record_authorized`, `original_restore_verified`, `no_leak_certified` false هستند. موافقت کاربر، rule snapshot، active policy precedence، SSTP identity/service-tag/transport/bootstrap، migration و recovery اجرایی باید جدا ساخته/اثبات شوند؛ این جزء جای آن‌ها نیست.

## آزمون و مرز ادعا

۵۴ assertion در `tests/Test-ProfileReader.ps1` روی PowerShell Linux گذشت: Allow، Block، NotConfigured، اختلاف local/effective، disabled/unknown، missing/duplicate/invalid، exclusion، typed-null، drift، خطای بومی، redaction، چهار getter در مسیر موفق و یک getter در failure اول، platform guard واقعی Linux، export واحد، allowlist command/API و نبود query در import. Windows getterها در این suite mock هستند و **این ماژول روی Windows کاربر اجرا نشده است**.

۷۲ assertion کتابخانهٔ HF124 و ۴۷ assertion runner قبلی نیز دوباره روی Linux اجرا شدند. آزمون کامل ۴۶ PS suite/۵۳۱ Python این مرحله تکرار نشده است؛ اعداد قدیمی، نتیجهٔ milestone پیشین‌اند.

## وضعیت کاربر و ادامه

هیچ اقدامی از کاربر درخواست نمی‌شود؛ ماژول در سیستم او نصب/جایگزین نشده است. SSTP متصل و outbound فعلیِ گزارش‌شده Block باقی می‌مانند. بستهٔ قبلی و Apply/Restore/reconnect قدیمی تکرار نشوند؛ WmiPrvSE بسته نشود.

رویداد تغییر Block در 04:23:05.1253967 UTC پیش از timestamp نام گزارش runner در 04:23:51 UTC است؛ مرحلهٔ qualification/review آن اجرای مشخص پس از تغییر آغاز شده. requester اصلی WMI هنوز نامعلوم است؛ موفقیت reader یا این ترتیب زمانی علت تاریخی را حل نمی‌کند.

مرحلهٔ بعدی فنی، استفادهٔ کنترل‌شده از این قرارداد reader در preflight هستهٔ کوچک و آزمون reset-free recovery است؛ بدون import کردن mutatorهای نامرتبط. old journal NotConfigured و مجوز write را دور نزنید. **تا تأیید مسیر نوشتن/بازیابی، بستهٔ قابل Apply به کاربر تحویل داده نمی‌شود.**
