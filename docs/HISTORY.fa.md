# مسیر تصمیم‌ها و نسخه‌ها

این تاریخچه مرحله‌ای است، نه فهرست کامل تمام پیام‌ها یا ادعای بازسازی تمام باینری‌های قدیمی.

1. بررسی تله‌متری/مقصدهای WoW و loader؛ مشاهدهٔ استاتیک و شبکه از body واقعی جدا شد. مخزن قدیمی `kokononox/check-spy-app` فقط مرجع تاریخی است؛ در این کار تغییر داده نشده است.
2. تست چهارشنبه به realm/in-world نرسید. به‌روزرسانی بازی پیش‌نیاز شد و مسیر downloader آغاز گردید.
3. v0.24 تا supply/download/metadata/offline diagnostics: محدودسازی دریافت و شواهد read-only. VPN/شبکه و اجرای از فلش به‌عنوان عوامل محیطی مطرح شدند؛ علت همهٔ شکست‌ها قطعی نیست.
4. حدود ۴۲MB دریافت محدود گزارش شد؛ subset completion و decoded staging v0.30 رسید. manifest خصوصی و root همان اجرا باید با هم بمانند.
5. v0.31 readiness ابتدا `source_missing_or_oversized` داشت، سپس گزارش تولید شد. v0.32 record diagnostic: ۹ staged، ۱۶ checksum idx، ۱۹۸۴ bucket mismatch؛ شکل cross-reference تمام mismatchها را توضیح نداد. condition/reference geometry probeهای بعدی صادر شدند؛ این سابقه مجوز نصب ایجاد نکرد.
6. پس از اعتراض درست کاربر به طولانی‌شدن نسخه‌های تشخیصی، مسیر به هستهٔ قابل‌آزمون و پیشرفت کاربردی منتقل شد: ۶۹ آزمون repair، ۱۲۱ metadata، ۱۶۶ content planning، ۲۲۷ local CASC، ۳۱۷ Windows preview، ۳۴۸ offline continuation، ۳۹۳ installed metadata delta، ۴۲۹ scope، ۴۴۶ TagFix. عدد تست، متر پیشرفت نصب نهایی نیست.
7. metadata کامل ۲٬۸۸۱٬۶۱۹ هدف به encoding/index route متصل شد؛ در آزمون مربوط ۱٬۴۰۷ index کامل بررسی و تطبیق مستقل بدون اختلاف بود. archive-group در CDN موجود نبود و مسیر archives واقعی استفاده شد؛ fallback ناامن نشد. تلاش نمونهٔ asset در یک مرحله HTTP403 داشت؛ آن مرحله دریافت asset موفق اعلام نشد.
8. کاربر Windows preview را با Lab جدا، Data/data و staging/manifest v0.30 اجرا کرد. prepare ابتدا مشکل شبکه داشت و سپس تمام شد؛ پوشه حدود ۳٫۸۸GB، نه اندازهٔ قطعی آپدیت.
9. ادامهٔ محلی اضافه شد تا از checkpoint به‌جای metadata/scan از ابتدا ادامه دهد. مرور ۱٬۵۳۱٬۱۶۷ نامزد کامل و صف offline تازه شد. intermediate checkpointهای بی‌ارجاع ساخته‌شدهٔ همان قابلیت کنترل‌شده prune شدند؛ دادهٔ بازی/metadata اولیه پاک نشد.
10. installed metadata تفاوت old/new را مشخص کرد؛ اختلاف منطقی عمومی ۴۴٬۲۱۹ افزوده/۳۵٬۶۲۱ حذف روی همهٔ tagها، جایگزین scope پروفایل نیست.
11. scope نخست با `update_scope_unknown_installed_tag_no_guess` متوقف شد. TagFix، optional suffix و auxiliary acct/geoip را بدون حدس/انتشار مقادیر پشتیبانی کرد؛ token ناشناختهٔ دیگر همچنان متوقف می‌کند. گزارش Windows کاربر scope نهایی را موفق ثبت کرد.
12. با درخواست کاربر برای بررسی Battle.net در GitHub و ادامهٔ موازی تست‌های محلی، مخزن خصوصی `battle-net-agent-lab` ساخته شد. اولین baselineها timeout ابزار داشتند، native snapshot جایگزین WMI شد. Setup رسمی و امضای آن واقعاً اجرا/بررسی شد ولی Agent مشاهده نشد.
13. درخواست جدید: sync جامع context و منبع معتبر، همراه probe فقط‌خواندنی GUI برای یک علت مشخص؛ بدون تکرار تست سنگین کاربر و بدون ادعای نصب کامل.

## شناسه‌های انتشار و شواهد

- بستهٔ منبع syncشده: `WoW-Update-Scope-Preview-TagFix.zip`؛ SHA256 `c26e5f9416e7aadef0f9f7dc36c06c2e8975ae65f8f1ac3bfca0abd67fa81001`؛ ۲۰۱٬۳۹۶ بایت. خود ZIP در GitHub کپی نشده؛ محتوای متنی و manifest معتبر آن در `downloader/` است.
- Agent initial source: `ced7acfd476ef7003ab030b1df4d80059daf10d8`.
- Native/stdin source پیش از probe GUI: `f9a91c0825bcb3b9606ea8bb8b2726eb0e6885a2`.
- گزارش bootstrap: `9b2f3b3700b1a4619eda3db710f443185aa63ad7`؛ run `38827529003` attempt 1.
- SHA256 Setup مشاهده‌شده: `de5d32d4ea5eed5a9e120027fb68b370976dbfecc8f2a8f91305977f0b87fcaf`، باینری منتشر نشده است.
