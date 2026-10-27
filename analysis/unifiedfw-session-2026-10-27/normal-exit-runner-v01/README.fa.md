# راه‌انداز کنترل‌شدهٔ ثبت خروج عادی — ۰٫۱

[راهنمای اجرا](package/NORMAL-EXIT-REVIEW-01/README-FA.md) و [مشخصات ZIP](PACKAGE-SUMMARY.json).

این milestone بعد از کتابخانهٔ HF1.2.4 است، نه ارتقای برنامهٔ فعال. پنج dependency بدون تغییر بایت بسته‌بندی شده‌اند. ابتدا روی Windows یک fixture جدا در ProgramData، ACL metadata و عملیات واقعی فایل، CreateNew، قفل و cleanup محدود را می‌سنجد؛ هیچ تستی ژورنال اصلی را هدف نوشتن قرار نمی‌دهد. سپس فقط وضعیت فعلی را می‌خواند و با رضایت دستی تصادفی، رکورد normal-mode جداگانه را می‌سازد یا با شواهد تازه بازتأیید می‌کند. لغو بدون درخواست Record ممکن است. در failure بعد از درخواست نوشتن، ممکن است فایل ایجاد شده باشد؛ گزارش باید بررسی شود و نباید وعدهٔ no-write یا retry خودکار داد.

۴۷ assertion راه‌انداز با mock prompt/ACL metadata، ۷۲ assertion کتابخانه و parse هفت PS1/کد CMD و pin/hash payload گذشتند. guard Linux قبل از native/storage اجرا شد. **Windows این بسته هنوز اجرا نشده و هیچ رکورد واقعی روی سیستم کاربر ساخته نشده است.** آزمون‌های کامل HF124 سابق ۴۶ PS suite و ۵۳۱ Python pass+۲skip بودند؛ در این milestone فقط ۴۷+۷۲ اختصاصی rerun شدند، نه همهٔ regressionها.

اقدام تازه فقط اجرای اختیاری این بسته در پوشهٔ جدا با admin و همان حساب است؛ اینترنت/VPN را تغییر ندهید. خروجی قابل ارسال فقط NORMAL-EXIT-REVIEW-01-*.json است، نه فایل‌های محافظت‌شده. فقط بعد از موفقیت fixture و live review، prompt رضایت ظاهر می‌شود؛ Enter لغو می‌کند.

فایروال/VPN/rules/route/DNS/task/controller یا legacy journal تغییر نمی‌کنند؛ فایل fixture/قفل/report و رکورد جداگانهٔ consented مرز نوشتن‌اند. snapshot اتمیک نیست، قفل cooperative و ACL test نه impersonation تمام کاربران است نه دفاع در برابر admin مخرب. Apply/Restore قدیمی، local-review قبلی و live isolation reconnect همچنان متوقف‌اند. این خروج عادی نه exact original Restore است نه رفع قطعی علت reboot Block. رکورد مجوز Apply/migration/no-leak/fingerprint prevention نیست. هدف نهایی همچنان بنیاد کوچک اختصاصی نصاب Battle.net با حمل SSTP و سازگاری LAN/Wi-Fi است.
