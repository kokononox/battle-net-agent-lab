# ثبت خصوصیِ فقط‌خواندنی قواعد — آزمایشی ۰٫۱

این بسته گام inventory/storage است، **نه Apply، غیرفعال‌سازی Allow، restore یا اجرای نصب‌کننده**. هیچ قاعده، پروفایل، audit، DNS یا VPN را تغییر نمی‌دهد. فقط پروفایل‌ها و قواعد قابل‌مشاهده در PersistentStore و ActiveStore را می‌خواند؛ برای ActiveStore منشأ policy را نیز trace می‌کند. به candidate، baselineهای قبلی، journalهای قبلی و Security log دست نمی‌زند.

## اجرا و رضایت محلی

1. ZIP را کامل در پوشهٔ محلی جدید و غیرپیوندی استخراج کنید. با همان حساب Windows، `Run-Inventory.cmd` را با **Run as administrator** اجرا کنید.
2. پنجرهٔ رضایت را بخوانید. **Save private inventory only** فقط اجازهٔ ذخیرهٔ خصوصی همین مشاهده است؛ مجوز تغییر فایروال یا اجرای هدف نیست. Cancel هیچ snapshot خصوصی نمی‌نویسد؛ diagnostic عمومی همچنان ایجاد می‌شود.
3. پس از رضایت، هر دو store و برای هر rule هفت دستهٔ فیلتر Application،Service،Port،Address،Interface،InterfaceType،Security خوانده می‌شوند. قواعد Block، inbound و disabled هم برای inventory خوانده می‌شوند، نه تغییر. خواندن چندین دقیقه ممکن است طول بکشد؛ پیشرفت فقط شمارش نشان می‌دهد. در این مدت برنامه‌ها، نصب‌کننده یا UIهای تغییر فایروال را شروع نکنید. هیچ تست سرعت Windows برای این نسخه انجام نشده است.
4. قواعد/پروفایل‌ها در پایان دوباره خوانده می‌شوند؛ تغییر header باعث توقف بدون ذخیرهٔ snapshot می‌شود. فیلترها فقط یک دور خوانده می‌شوند؛ recheck هدر **اثبات پایداری فیلتر یا snapshot اتمیک نیست**. محدودیت زمانی۱۵دقیقه بین فرمان‌ها بررسی می‌شود و توقف اجباری یک cmdlet گیرکرده نیست؛ زمان پنجرهٔ رضایت نیز جزو آن است.
5. فقط فایل تازهٔ `UFW-PRIVATE-INVENTORY-01-*.json` کنار ابزار را برگردانید، حتی در لغو/خطا. **private-policy-snapshot.json را ارسال نکنید.** screenshot، transcript یا خروجی raw قواعد لازم نیست.

## چه چیزی کجا ذخیره می‌شود؟

خروجی عمومی فقط شمارش، stage/code، نام ثابت store/دستهٔ فیلتر و وضعیت‌هاست؛ نام/ID قواعد، SID، مسیر، IP، منبع policy، hash خصوصی و متن exception صادر نمی‌شود.

فقط پس از رضایت و تکمیل خواندن‌ها، snapshot شامل نام/ID و تمام CimInstanceProperties قابل‌سریال‌سازیِ قواعد، پروفایل‌ها و فیلترهای مرتبط، منشأ policy و SID عامل، زیر ProgramData/UnifiedFW-PrivateInventory-01/inventory-<random>/private-policy-snapshot.json ذخیره می‌شود. owner/DACL با helper بدونتغییر قبلی برای Administrators/SYSTEM، inheritance محافظت‌شده، کنترل reparse، CreateNew، Flush و بازخوانی بایت/چک‌سام اعمال می‌شود. امنیت در برابر مدیر مخرب، امضای محتوا، anti-rollback یا دوام قطعی قطع برق ادعا نمی‌شود. بسته مالک فایل‌های قبلی نیست و آنها را نمی‌خواند/تعمیر/حذف نمی‌کند.

snapshot بزرگ‌تر از۶۴MiB، بیش از۴۰۹۶ruleدرهرstore، نوع مقدار ناشناخته، بیش ازیک/صفر فیلتر در هر دسته، یا هویت rule مبهم باعث امتناع است؛ دادهٔ ناشناخته بی‌صدا حذف یا به string تبدیل نمی‌شود. شکست ذخیره ممکن است پوشه/فایل خصوصی ناقص بگذارد؛ آنها را حذف یا بازنویسی نکنید. فعلاً recovery/reader اجرایی برای مصرف این snapshot وجود ندارد.

## تفسیر منشأ

source_counts فقط تعداد Allow خروجی فعال در Local،GroupPolicy،Dynamic،Generated،Hardcoded یا Unknown است. unique_local_name_candidates صرفاً تطبیق نام یکتا در PersistentStore برای منشأ Local است؛ **تطبیق معنایی تمام فیلترها، مالکیت تغییر یا مجوز غیرفعال‌کردن نیست**. rule با منبع مدیریت‌شده یا ناشناخته در این بسته تغییر نمی‌کند. snapshot نمونهٔ خصوصیِ قابل‌بازخوانی است؛ نه backup تأییدشده برای Restore و نه جایگزین مشاهدهٔ تازهٔ قبل از تغییر.

Get-NetFirewallRule همهٔ WFP/AppContainer/third-party را پوشش نمی‌دهد؛ این ابزار full WFP inventory یا نبود ترافیک را ثابت نمی‌کند. هیچ READY یا مجوز نصب‌کننده در این بسته وجود ندارد. همهٔ ready_for_apply/native_restore_qualified/target_execution_authorized false می‌مانند. وضعیت Block فعلی به Allow تبدیل نمی‌شود و SSTP آزمایش/قطع‌وصل نمی‌شود.

## شواهد و حدود

callbackهای موفق/لغو/خطا، header drift، عدم انتشار اطلاعات خصوصی، نوع‌محوربودن serializer و file IO واقعی روی Linux آزموده شده‌اند؛ counts در evidence/model-tests.json هستند. helperهای storage/core/reader قبلی بایت‌به‌بایت حفظ شده‌اند. **Windows PowerShell5.1/CIM/فیلترهای واقعی، پنجرهٔ رضایت و ACL بومی این جریان جدید هنوز اجرا نشده‌اند**. bootstrap فقط شش اسکریپت/ماژول خود بسته را بعد از hash verification، Unblock می‌کند؛ RemoteSigned فقط در process فعلی، بدون Bypass یا تغییر دائمی policy. تغییرات فایل محدود به بستهٔ استخراج‌شده و snapshot خصوصیِ رضایت‌داده‌شده است، نه تنظیمات سیستم.
