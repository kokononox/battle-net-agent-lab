# ادامهٔ جلسه — قواعد انتخاب ۰٫۱۶

منبع جاری updater-core/ است؛ [وضعیت پیشین ۰٫۱۵](UPDATER-SESSION-0.15.fa.md) برای سابقه نگه داشته شد. معماری همچنان نسخه‌مستقل است؛ target آزمایش تاریخی 12.1.5.70448 است، نه ادعای آخرین انتشار.

## انجام‌شده
- تبدیل پروفایل نوع‌دار به عبارت انتخاب بدون optional بودن ابعاد اصلی؛ speech/text و localeهایشان جدا نگه داشته می‌شوند.
- توقف در بعد مفقود، تغییر kind، schema ناسازگار دو manifest، ورودی اضافی/نامعتبر و قالب ناشناخته.
- اجرای واقعی فقط‌خواندنی روی کش موجود: bitmap دقیقاً برابر برنامهٔ قبلی، ۳۹ Install و ۱۵۷۸۰۲۲ Download؛ دانلود یا حذف هیچ شیئی انجام نشد.
- ۱۰۰۲۸ عضو Alternate و یک عضو Talebound در نامزدهای Download دیده شد؛ معنای انتخاب آن‌ها هنوز تأیید نشده. هیچ فرض لازم/اضافی یا برآورد دانلود از این اعداد تولید نشده.
- ۴۱۱ تست Linux (۴۰۶ مصنوعی + پنج fixture متادیتای عمومی)؛ تست دوبارهٔ بستهٔ استخراج‌شده موفق. نه qualification بومی Windows.

## چه چیزی کامل نشده
این «بازبینی نامزد» است، نه تکمیل سیاست رسمی Agent. independent_vendor_selection_policy، ترجیحات زنده، dependency/variant/patch و معنای featureها بازند. promotion_to_required_set_permitted=false، installation_ready=false، apply_authorized=false و required_network_download_bytes=null باقی‌اند.

هیچ اقدام Windows یا permission تازه‌ای از کاربر درخواست نشده؛ برای رفع ابهام‌ها کار مهندسی آفلاین ادامه دارد. نوشتن آزمایشی بعداً فقط روی کپی مستقل و با دامنهٔ روشن مجاز خواهد بود، نه نصب اصلی.

## منابع
- [کد قواعد](../updater-core/selection_policy.py)
- [گزارش واقعی این مرحله](../updater-core/reports/SELECTION-POLICY-to-share.json)
- [تست‌ها و وضعیت](../updater-core/QA.json)
- [اقدامات باقی‌مانده به‌ترتیب](UPDATER-REMAINING.fa.md)
- شواهد عمومی قالب tag، نه oracle سیاست: https://wowdev.wiki/TACT#Install_manifest و https://wowdev.wiki/TACT#Tags
