# P11 — بازگردانی بومی دقیق NotConfigured در Domain غیرفعال

## نتیجه
**PASS محدود به qualification Domain غیرفعال در runner windows-2025**، نه adapter آمادهٔ همهٔ profileها یا کیل‌سوییچ کل سیستم.

- source: `3d2119235af5d0b7018e3bd3c93d1349dd279f17`
- run: https://github.com/kokononox/battle-net-agent-lab/actions/runs/39224713268 — Success؛ job در UI: 1m50s.
- checks=191؛ profile_field_cases=132 از raw fieldهای هر شش تصویر PersistentStore/ActiveStore، با هیچ معافیت نمایشی.
- fault_cases=6؛ fresh_process_recoveries=6؛ partial_restores=2.
- native_notconfigured_noops=9؛ verified_restore_completions=8؛ observed_inactive_domain_block=True؛ توقف روی native conflict بیرونی=1.
- cleanup_exact=True؛ final_stored_notconfigured=True؛ baseline کامل rule/هفت filter/شش profile نامرتبط برابر=True؛ label drift=0.
- ZIP SHA256: `fa570b81fb52294e288d4c2aa5df0f73fcee1378b187582437510c9a5cd12c92`. digest دانلود واقعی، schema/flags/countها، source/run و hash هفت فایل منبع با encoding LF/CRLF checkout مستقلاً بررسی شدند.

## چه چیزی واقعاً اثبات شد
روی همین runner، Set-NetFirewallProfile -InputObject <PersistentStore Domain> -DefaultOutboundAction NotConfigured واقعاً پذیرفته شد. ابتدا NotConfigured→NotConfigured به‌عنوان canary native اجرا و شش تصویر کامل قبل/بعد تطبیق شد؛ تا موفقیت آن هیچ Blockی نوشته نمی‌شد. سپس تغییر واقعی Domain به Block و Restore به stored=NotConfigured با readback ذخیره و effective مشاهده شد. این نتیجهٔ تجربی روی این runner است، نه تغییر تفسیر مستند Microsoft یا تضمین همهٔ نسخه‌های Windows/دستگاه کاربر.

هشت completion بازگردانی الزاماً هشت setter Restore یا هشت roundtrip کامل نیستند: در Restore مستقیم از Block ناقصِ قبل از setter، policy هنوز original است و Restore بدون Block/Restore بی‌جهت کامل می‌شود. آزمایش اصلی و چند fault واقعاً Block را مشاهده کردند؛ cleanup بعد از corrupt journal مسیر جدا و خارج از شمارش recovery محصول است.

## محدودیت ایمنی و تغییرهای مجاز
تنها DefaultOutboundAction پروفایل Domain در PersistentStore نوشته می‌شود. Domain باید طبق COM CurrentProfileTypes و Get-NetConnectionProfile غیرفعال باشد؛ ابهام/نبود شبکه، Domain فعال، original غیر از stored=NotConfigured یا Firewall غیرفعال در Domain stored/effective توقف است. هیچ -All، Enabled، inbound، logging، merge، exclusion، rule، registry یا ActiveStore setter وجود ندارد. AST workflow پارامترهای تمام setterها را به InputObject/DefaultOutboundAction/ErrorAction محدود می‌کند.

گیت inactive قبل از خواندن/نوشتن تکرار می‌شود، اما با تغییر شبکه اتمیک نیست؛ هیچ ادعایی دربارهٔ منتفی بودن گذار لحظه‌ای category یا تأثیر active traffic مطرح نیست. هدف عمداً profile فعال نیست. این qualification روی VM موقت CI است؛ دستگاه کاربر تغییر نکرده است. این ابزار با همین قفل inactive باید محدود بماند، نه اینکه آن قفل برای deployment حذف شود.

## journal و frontier
P2 همچنان ACL/lock/flush/revision/backup را تأمین می‌کند. original هر شش تصویر کامل ذخیره می‌شود. comparison بر اساس هویت دقیق store/name و تمام RawDifferenceFields P8 است؛ نه hash serialization کل آرایه و نه صرفاً DefaultOutboundAction. pending فقط before/after دقیق همان property هدف در دو store را می‌پذیرد؛ mix موقت known-before/after فقط برای انتظار محدود readback است. mutation/ack/completion تا snapshot کامل settled انجام نمی‌شود. هر فیلد ناآشنا/تغییر دیگر موجب توقف است. محدودیت check/read/set و admin هم‌زمان باقی است؛ hash journal احراز اصالت در برابر admin مهاجم نیست.

بعد از restoring/restored، Block دوباره ممنوع است. journal گمشده/خراب یا backup recovery_required هیچ Restore حدسی، Force-Allow، reset یا adoption ندارد. negative native test فقط همان Domain غیرفعال را عمداً به Allow تغییر داد؛ موتور conflict را بدون افزایش revision رد کرد. harness فقط پس از مقایسهٔ کامل با همین تصویر شناخته‌شده، تغییر منفی خودش را undo کرد. cleanup CI نیز جداست و فقط original کامل یا Block دقیقِ معلومِ همین یک Domain را می‌پذیرد، نه تغییر ناشناخته را. در cleanup نهایی stored=NotConfigured و کل baseline با P8 برابر بودند.

## دو اجرای ناموفقِ حفظ‌شده
1. source40382327c16d679275524c3041d1c531a490401f، run39223998468: failed، checks=1، canary موفق=0، fault/recovery=0. مرحلهٔ Block شروع نشد؛ cleanup_exact=true، stored=NotConfigured و baseline کامل برابر ماند.
2. sourced03c65bb320cf9c7eec3d095f98c36e35280c576، run39224375752: failed تشخیصی، همان checks=1 و صفر canary/fault/recovery. log پیش از setter، profile_serialization_shape_mismatch را گزارش کرد، بدون نام فیلد اختلاف. cleanup_exact=true و baseline کامل برابر بود. این‌ها شکست اثبات‌شدهٔ setter NotConfigured نیستند و PASS هم نیستند؛ receipt و هر هفت hash هر دو اجرا تأیید/حفظ شدند.

نسخهٔ موفق clone را برای هر image جدا انجام داد و برابری شش profile را با هویت و تمام raw fieldها سنجید، نه serialization کل آرایه. هیچ field/type/value از comparison حذف نشد؛ ۱۳۲ مورد تغییر فیلد در حافظه همچنان رد شدند. منشأ دقیق داخلی تفاوت representation پیشین فراتر از شواهد تشخیصی بالا ادعا نمی‌شود.

## خارج از qualification و گام بعد
active_profile_targeted=false؛ whole_machine_enforcement_tested=false؛ guard_coordinator_tested=false؛ sstp_tested=false؛ reboot_tested=false؛ user_device_tested=false؛ ready_for_user_apply=false.

هنوز P9 و P10 و profile adapter در coordinator واحد ادغام نشده‌اند؛ P9 با frontier profile قدیمی نمی‌تواند تغییرهای profile را بی‌طرح جدید قبول کند. گام بعد باید frontier مشترکِ guard/quarantine/profile/allowها و شرط ممیزی تازه قبل از آزادسازی guard را تعریف و تست کند. پروفایل‌های فعال/همهٔ profileها، default متفاوت، GPO/merge، قواعد مؤثر، هویت و انحصار SSTP، قطع‌وصل، IPv6/DNS/LAN، اتصال‌های قدیمی و boot/عدم‌نشت هنوز باید qualified شوند. هیچ فایل اجرای تازه یا فرمان Enable برای کاربر تولید نشده و گزارش کاربر تکراراً خواسته نشده است.

هیچ resident/task/watchdog/expiry اضافه نشده؛ loop کوتاه readback به معنی برنامهٔ مقیم یا rollback زمان‌دار نیست.

## منابع
- قرارداد setter و محدودیت مستند NotConfigured برای GPO: https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2025-ps
- شکل CIM profile: https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netfirewallprofile
