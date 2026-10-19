# بازیابی محدود Prepare غیرفعال — ۰.۱.۲ آزمایشی

کاربر صریحاً فقط Prepare disabled را زده، نه Enable. گزارش او نشان می‌دهد staging/pending=create index2 false؛ guard/v4 با original و واقعاً غیرفعال، v6 بدون original و واقعاً غایب است. این خرابی آماده‌سازی ابزار است، نه خطای فعال‌سازی کاربر.

## تغییر محدود
Resume-Prepare.cmd → Launcher -Action Resume → تأیید دستی → ResumeOverlayPreparation. فقط journal معتبر با scope RemoteAccess و دو قاعدهٔ قبلی دقیقاً مطابق و غیرفعال پذیرفته می‌شود. v6 ثبت‌نشده باید واقعاً غایب باشد؛ موجودبودن آن موجب توقف بدون adoption/removal می‌شود. مجموعهٔ مقصدهای همان snapshot بدون DNS جدید حفظ و نمایش IPv6 به CIDR هم‌ارز تبدیل می‌شود. سقف۲۰۴۸، برابری interval signature، pending durable، ایجاد Enabled=False، capture، readback و final audit الزامی‌اند. existing prepared دقیق، idempotent است. هیچ reset، Allow، تغییر پروفایل، DNS، route، VPN، سرویس یا rule نامرتبطی وجود ندارد. خطای ساخت، فقط کلاس و کدهای عددی را گزارش می‌کند.

علت شکست بومی دستگاه کاربر هنوز ثابت نشده است. نمایش جایگزین به‌تنهایی اثبات علت نیست. این بسته هیچ تضمین نبود نشتی یا قطع‌وصل واقعی SSTP/IPv6 packet/reboot ارائه نمی‌کند. محافظت بیرون تونل همان کیل‌سوییچ قبلیِ تأییدنشده است؛ scope روی همهٔ RemoteAccessهاست، نه پروفایل خاص.

## تاریخچهٔ واقعی آزمون
- 74dec2a / run39316767749: overall FAILED؛ recovery در check3 متوقف شد؛ اندازه‌گیری باقی‌مانده/برابری سیاست recovery انجام نشد (-1/false). native regression موفق بود. PASS فرض نشده است.
- b9a1d42 / run39317053901: overall FAILED؛ گزارش محدود فرایند تازه خطای overlay_interval را نشان داد. دادهٔ fixture برخلاف شکل واقعی journal آرایهٔ تو‌در‌تو ایجاد می‌کرد. فقط harness اصلاح شد؛ قواعد امنیتی محصول شل نشدند.
- 8bcdca8 / run39317865720: recovery46 و native40 و UI موفق؛ overall FAILED چون رسید CIDR موجود نبود. LASTEXITCODE اولیهٔ null موجب خروج زودهنگام step با exit-null/0 شده بود. نتیجهٔ ناقص منتشر نشد؛ هر دو pure suite در فرایند مستقل WindowsPS اجرا شدند.
- 2c64029 / run39318914571: overall SUCCESS. pure257، CIDR28، recovery46 در پنج مجموعه، دو fresh-process fault recovery، رد existing-uncaptured و drift، idempotent prepared. native40، workers12، fault recoveries2، TCPv4 probe pairs6؛ هر دو مجموعه cleanup0 و unrelated policy equal/display0. UI construct/dispose موفق. IPv6 arithmetic/rule creation != IPv6 packet proof؛ UAC تعاملی و دستگاه کاربر آزموده نشده‌اند.

رسید ZIP نهایی c5ef757cf89b0596068a04328d3abb4b662304b7dd723a580c2218ae509f94f4 با digest صفحه تطبیق داده شد؛ هش هر ۲۲ فایل کد/تست/receipt.py با payload دقیق، LF/CRLF، بررسی شد. چهار receipt با نتیجهٔ واقعی حفظ شده‌اند.

https://github.com/kokononox/battle-net-agent-lab/actions/runs/39318914571

## تحویل برای آزمون کاربر
بستهٔ کامل، پوشهٔ جدید، نسخهٔ قبلی بسته؛ فقط Resume-Prepare.cmd و تأیید آن. فعلاً Prepare مجدد یا Enable اجرا نشود. نتیجهٔ resume-result.json یا کد startup-error.json درخواست می‌شود، نه journal خصوصی. allowlist.json قبلی خودکار کپی نمی‌شود؛ مرحلهٔ فعال‌سازی بعدی نیازمند بررسی/حفظ سازگاری hash همان فهرست است. journal موجود ProgramData نباید حذف یا reset شود.

## بسته

```json
{
  "version": "0.1.2-test",
  "source_commit": "2c64029eccd0ee91da5f3db5e521110ea6d4b0ff",
  "run_id": "39318914571",
  "zip_sha256": "5e774c6f40f1c6bb67a14b24eab1a1207550f3d2598ac4e2fabf184c3de50234",
  "zip_bytes": 35994,
  "file_count": 18,
  "ready_for_production": false
}
```
