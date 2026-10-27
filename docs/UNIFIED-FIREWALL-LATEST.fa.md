# ادامهٔ فعلی Unified Firewall

[تحویل جامع](SESSION-UNIFIED-FIREWALL-2026-10-27.fa.md)، [اصلاح مشاهده‌گر ۰٫۳٫۱](../analysis/unifiedfw-session-2026-10-27/endpoint-v031/README.fa.md) و [وضعیت ماشین‌خوان](UNIFIED-FIREWALL-CURRENT.json) مرجع ادامه‌اند.

v0.3 روی Windows دو بار پیش از endpoint متوقف شد: disconnected و سپس unknown. wrapper علت lifecycle را پنهان کرده بود؛ unknown را قطع‌بودن VPN تلقی نکنید. v0.3.1 علت پالایش‌شده را حفظ می‌کند و هیچ guard یا native reader را تغییر نمی‌دهد؛ ۶۱ assertion جدید و ۸۴ lifecycle محلی گذشتند، هنوز receipt اجرای اصلاح نداریم. SplitTunneling=True بعد از بازسازی قبلاً دیده شده، اما علت آخرین شکست با دادهٔ موجود قطعی نیست.

گام بعد فقط اجرای بستهٔ جداگانهٔ v0.3.1 با وضعیت فعلی VPN و دریافت JSON است. Apply/Restore/قطع‌و‌وصل یا تغییر حدسی تنظیمات درخواست نشود. مشکل LAN به‌گفتهٔ کاربر فعلاً رفع شده، علت نامعلوم؛ این اثبات reconnect تحت ایزولاسیون نیست. هدف ابزار اختصاصی Battle.net، no-leak و bootstrap تأییدنشده باقی است.
