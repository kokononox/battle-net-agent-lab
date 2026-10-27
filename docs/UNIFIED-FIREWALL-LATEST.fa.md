# ادامهٔ فعلی Unified Firewall

مرجع: [تحویل جامع](SESSION-UNIFIED-FIREWALL-2026-10-27.fa.md)، [گزارش‌گیری بازبینی محلی v0.1.1](../analysis/unifiedfw-session-2026-10-27/local-review-v011/README.fa.md) و [وضعیت ماشین‌خوان](UNIFIED-FIREWALL-CURRENT.json).

v0.1 واقعی Windows پیش از prompt در شرط unique stable endpoint متوقف شد. علت دقیق (cache سرد/تطبیق صفر/چند flow/تغییر اتصال) از گزارش قدیمی معلوم نیست. v0.1.1 فقط شمارنده‌های پالایش‌شده را اضافه کرده؛ همهٔ شروط، readerها، عدم DNS query و عدم مجوز Apply بدون تغییرند. ۶۸ assertion بازبینی و ۶۱+۸۴+۸۶ رگرسیون گذشتند؛ اجرای Windows نسخهٔ اصلاح هنوز نداریم.

کاربر فقط بستهٔ جداگانهٔ جدید را با VPN/فایروال بدون تغییر اجرا و JSON را برگرداند. اگر prompt رسید، raw مشخصات محلی ارسال نشود؛ acknowledge draft یا لغو مجاز است. Apply/Restore/قطع‌و‌وصل/تغییر DNS درخواست نشود. هنوز persistent approval، bootstrap DNS/TLS، executor/guardian و no-leak نداریم؛ هدف ابزار کوچک نصاب Battle.net است.
