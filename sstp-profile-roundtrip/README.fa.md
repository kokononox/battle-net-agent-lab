# P11 — راستی‌آزمایی بازگردانی دقیق NotConfigured در Domain غیرفعال
ابزار qualification داخلی و محدود به آزمایش؛ نه adapter نهایی همهٔ profileها، نه فرمان Enable/Disable کاربر.

## چرا
مقدار stored=NotConfigured با effective=Allow یکسان نیست. بازگردانی باید همان stored value را بنویسد، نه Force-Allow. مستند Microsoft مقدار NotConfigured را فقط برای GPO معتبر توصیف می‌کند؛ بنابراین هیچ اتکایی به پذیرش آن در PersistentStore بدون آزمون بومی نمی‌شود.

## دامنه و ایمنی CI
تنها هدف، DefaultOutboundAction پروفایل **Domain در PersistentStore** است؛ باید Domain غیرفعال و original stored=NotConfigured باشد، و Domain stored/effective Firewall enabled باشند. COM CurrentProfileTypes و Get-NetConnectionProfile هر دو باید Domain را غیرفعال نشان دهند؛ نبود/ابهام شبکه موجب توقف است. این گیت قبل از عملیات و نمونه‌برداری تکرار می‌شود، اما تغییر دستهٔ شبکه و setter اتمیک نیست و گذار لحظه‌ای اثباتاً منتفی نشده است. محیط disposable CI است، نه دستگاه کاربر. هیچ profile فعال عمداً هدف نیست؛ اگر شرایط برقرار نباشد آزمون failed می‌شود، نه اینکه profile دیگری تصادفی انتخاب شود.

اول از شش profile تصویر کامل خوانده و journal P2 نوشته می‌شود؛ سپس setter واقعی NotConfigured→NotConfigured اجرا و کل شش تصویر عیناً تطبیق داده می‌شود. **تا موفقیت این canary، Block نوشته نمی‌شود.** بعد فقط همین property به Block و سپس NotConfigured اصلی می‌رود. Enabled، inbound، logging، merge، interface exclusions یا ruleها نوشته نمی‌شوند. به ActiveStore هیچ setterی داده نمی‌شود.

## دوام و مقایسه
state مستقل در journal با write-ahead/pending/revision/lock نگه داشته می‌شود. مقایسه همهٔ propertyهای هر شش تصویر را شامل است؛ فقط DefaultOutboundAction هدف در دو store تغییرِ مورد انتظار دارد. pending تنها before/after دقیق را می‌پذیرد. ترکیب موقت دو store فقط با مقادیر شناخته‌شدهٔ همان property در انتظار محدود readback پذیرفته می‌شود، نه برای mutation یا completion؛ نیاز به snapshot کامل settled هست. دادهٔ ناآشنا/تغییر field دیگر توقف است. گم‌شدن/خرابی journal هیچ Force-Allow یا reset ایجاد نمی‌کند. وضعیت restoring/restored مانع Block دوباره است.

## آزمون
- NotConfigured no-op واقعی و Block→NotConfigured با readback stored و effective.
- شش termination/fresh recovery در هر دو سمت setter و Restore مستقیم از دو Block ناقص.
- idempotency، هر raw field شش profile در حافظه، native conflict با تغییر عمدی همان property Domain به Allow در تست، journal گمشده/خراب.
- negative-test Allow به‌عنوان تغییر بیرونی شناخته‌شده و با full-image تطبیق undo می‌شود؛ هیچ اختلاف ناشناخته‌ای adopt نمی‌شود.
- cleanup CI جدا از recovery محصول است؛ فقط تصویر کامل اصلی یا Block دقیقِ همین یک Domain شناخته‌شده را می‌پذیرد و NotConfigured اصلی را برمی‌گرداند؛ نه baseline نامعتبر، نه Force-Allow.
- P8 همهٔ ruleهای PersistentStore و هفت filter و هر شش profile را پیش/پس کامل مقایسه می‌کند. تنها receipt محدود و hashها upload می‌شوند؛ raw inventory/journal/نام شبکه/شناسه‌ها upload نمی‌شوند.

پذیرش setter در یک windows-2025 runner اثبات پذیرش در همهٔ Windowsها یا دستگاه کاربر نیست. این ابزار باید غیرفعال بودن Domain را الزام کند؛ گیت آن برای فعال‌کردن محصول حذف نشده است. هیچ گارد سراسری فعال نمی‌شود، coordinator/P9/P10 در یک transaction ادغام نمی‌شوند، و packet/SSTP/reconnect/IPv6/LAN/DNS/boot آزموده نمی‌شود. حلقهٔ کوتاه readback، resident/watchdog/expiry یا rollback زمان‌دار نیست. ready_for_user_apply=false.

## منابع
- https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netfirewallprofile
