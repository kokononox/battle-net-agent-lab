# ادامه: ثبت خصوصیِ قواعد و منشأ

کاربر پس از milestone مدل آفلاین تراکنش گفت «گام بعدی». ابزار PRIVATE-INVENTORY-01 برای inventory و storage-only ساخته شد؛ setter یا Apply به مدل وصل نشد. هیچ مشاهده یا تغییری روی Windows کاربر در این مرحله انجام نشده است.

## دامنهٔ واقعی

[راهنمای کامل](../analysis/unifiedfw-session-2026-10-27/private-inventory-v01/package/UFW-PRIVATE-INVENTORY-01/README.fa.md). با رضایت محلی صریح فقط برای ذخیره، پروفایل‌ها و تمام قواعد قابل‌مشاهده در PersistentStore/ActiveStore و هفت دستهٔ فیلتر مرتبط با هر rule خوانده می‌شوند: Application،Service،Port،Address،Interface،InterfaceType،Security. ActiveStore با TracePolicyStore خوانده می‌شود. header پروفایل و ruleها در پایان دوباره بررسی می‌شود؛ فیلترها یک دورند، بنابراین snapshot اتمیک یا پایداری فیلتر ثابت نیست.

snapshot خصوصی در ریشهٔ جدید ProgramData/UnifiedFW-PrivateInventory-01 و زیرپوشهٔ تصادفی با ACL فقط Administrators/SYSTEM، CreateNew، Flush و بازخوانی بایت/چک‌سام ذخیره می‌شود. سه ماژول helper قبلی بایت‌به‌بایت حفظ شده‌اند. به root/journal/candidate/baseline قدیمی یا Security log دست نمی‌زند و هیچ تغییر فایروال/audit/DNS/VPN یا اجرای هدف ندارد. فقط فایل‌های خود بسته Unblock و snapshot جدیدِ رضایت‌داده‌شده نوشته می‌شوند.

نوع ناشناختهٔ CIM بی‌صدا حذف یا string نمی‌شود؛ دادهٔ نوع‌دار قابل‌پشتیبانی ذخیره و در غیر این صورت امتناع می‌شود. بیش از۴۰۹۶rule/store، cardinality غیر۱ فیلتر، هویت نام مبهم، تغییر هدر یا actor، cap serialization/زمان/حجم باعث توقف است. شکست پس از تلاش ذخیره ممکن است فایل/پوشهٔ خصوصی ناقص بگذارد؛ حذف، overwrite یا تعمیر خودکار نداریم.

## گزارش و محدودیت‌ها

فایل عمومی فقط شمارش‌ها، stage/code و نام ثابت store/دستهٔ فیلتر دارد؛ نام/ID/مسیر/IP/SID/متن exception/hash خصوصی صادر نمی‌شود. source_counts فقط منشأ Allowهای فعال است. unique_local_name_candidates تنها نام یکتا با منشأ Local را نشان می‌دهد؛ تطبیق معنایی فیلترها و اختیار تغییر محسوب نمی‌شود.

این snapshot نمونهٔ خصوصیِ بازخوانی‌شده است، نه backup تأییدشده برای Restore. فعلاً reader/recovery اجرایی برای مصرف آن وجود ندارد. Get-NetFirewallRule کل WFP/WSH/AppContainer/third-party را اثبات نمی‌کند؛ همهٔ native_restore_qualified/ready_for_apply/target_execution_authorized=false می‌مانند. SSTP/bootstrap و بازیابی بومی همچنان مانع مستقل‌اند. این بسته هیچ READY ندارد و محدودیت‌های رصدگر قبلی را دور نمی‌زند.

## شواهد

۱۷۲assertion جدید در۱۹callback از جمله موفق/لغو/خطا/تغییر header/خواندن ناقص/ذخیره و readback ناموفق؛ serializer با CIM-like fixture و انواع/کران‌ها؛ Linux file IO واقعی و CreateNew collision.۱۶۱۷assertion تشخیص Allow دوباره عبور کردند. شش فایل PS، bootstrap، manifest و pin پنج وابستگی و ZIP پس از استخراج بررسی شدند. Windows5.1/CIM/فیلترهای واقعی/UI/ACL این جریان جدید هنوز اجرا نشده‌اند. native qualification از تست mock یا مدل قبلی استنتاج نشود.

## اقدام کاربر و ادامه

ZIP در پوشهٔ محلی جدید، همان حساب administrator، Run-Inventory.cmd؛ تأیید Save private inventory only پس از مطالعه. چند دقیقه زمان ممکن است لازم باشد؛ cap زمانی بین فرمان‌ها۱۵دقیقه شامل رضایت است، نه تضمین قطع cmdlet گیرکرده. در طول ثبت برنامه/نصب‌کننده/UI تغییر فایروال شروع نشود. فقط diagnostic جدید UFW-PRIVATE-INVENTORY-01-*.json برگردد؛ snapshot خصوصی، screenshot و transcript دریافت نشوند.

پس از رسید، موفقیت native capture/storage/readback و منشأهای شمارشی بررسی شود؛ همین‌ها نیز اختیار غیرفعال‌کردن۱۰۶قاعده نیستند. گام بعد، تطبیق معنایی محلی و بازبینی دقیق حمل/تغییرات و qualification recovery است؛ نه blind-disable یا اجرای نصب‌کننده. از فایل واقعی خصوصی برای GitHub یا chat ورودی نسازید.
