# تحویل staging بومی Windows — ۰٫۱۸

ادامهٔ [۰٫۱۷](UPDATER-SESSION-0.17.fa.md). سورس فعلی: updater-core/. هدف محصول همچنان به‌روزرسانی نسخهٔ موجود به مقصد سازگار جاری در انتشارهای بعدی است؛ هدف 12.1.5.70448 فقط snapshot پژوهشی pinned است.

## انجام‌شده
- WindowsStore و WindowsStreamStage برای scratch جدید برنامه، با handle بومی، guard والدها، رد reparse/hardlink، reader بدون share write/delete، writer.lock انحصاری، flush segment و انتشار journal پیاده شدند. هیچ enumeration، شبکه یا دسترسی به نصب بازی اضافه نشد.
- نخستین Windows CI: از ۱۱۱ تست، یک تست rename ریشه fail شد. FILE_READ_ATTRIBUTES به‌تنهایی share checking لازم را نمی‌داد؛ FILE_LIST_DIRECTORY نیز درخواست شد، بدون فهرست‌خوانی. رسید شکست حفظ شده و failure مخفی نشده است.
- پس از اصلاح: ۱۱۱ تست واقعی Windows/Python 3.12.10، صفر failure/error/skip. ۳۸ تست native scratch و ۷۳ portable parser/selection هستند. source: 531f95f8ccae807d078efd2876c00f86fd54d0dd؛ receipt: 4f29b55f7aecdfa4d370cf594b9b236aa5e32ed1.
- ۴۷۹ تست Linux پاس شدند؛ native-onlyها در Linux اجرا/skip نشده‌اند. شمار پلتفرم‌ها قابل جمع به‌عنوان آزمون مستقل نیست. ZIP بعد از تولید دوباره استخراج، hash/CRC و regression آن کنترل می‌شود.
- کاربر وجود Windows و فضای کپی آزمایشی را تأیید کرد؛ فعلاً درخواست کپی یا اجرای probe بازی نشده است.

## ادامهٔ اجرایی
1. اتصال محدود WindowsStreamStage به gate تازه‌اعتبارسنجی candidate با رد نوع نامطمئن و آزمون بومی جدید. gate فعلی دقیقاً POSIX StreamStage را می‌پذیرد؛ این اتصال هنوز انجام نشده است.
2. کنترلر بودجه‌دار انتقال چندشیء/بزرگ با Range/ETag/resume و journal؛ append فعلی فقط پاسخ تأمین‌شدهٔ caller را مصرف می‌کند. مجوز شبکهٔ قدیمی دوباره باز نشده است.
3. qualification مستقل انتخاب feature/variant/patch، ترجیحات تازه و نسل فعال؛ reuse کامل و محاسبهٔ حجم‌ها پس از حل unknownها.
4. نویسندهٔ تراکنشی CASC، rollback/activation و crash recovery؛ بعد از آماده‌شدن آزمون محدود، فقط در کپی بازی Windows. سپس آزمون end-to-end و UI/انتشار.

## مرزهای صریح
native_windows_stage_synthetic_tests_passed=true، اما native_windows_staging_backend_qualified=false، native_CASC_writer_qualified=false، installation_ready=false و apply_authorized=false. flush/write-through اثبات دوام سخت‌افزار/قطع برق نیست. orphan یا lock رهاشده خودکار پاک/پذیرفته نمی‌شود. مدل محافظت cooperative است، نه تضمین در برابر پردازش مهاجم. حجم دانلود ضروری null و reuse نصب زنده اثبات‌نشده‌اند.

متادیتای موجود و بانک‌های پروژه حفظ شده‌اند؛ دوباره دانلود نشوند. فایل بازی، decoded بزرگ، SQLite، raw transcript و credential وارد مخزن/ZIP نشده‌اند. workflow مستقل Agent اجرا/تغییر داده نشد.

## شواهد
- [رسید موفق Windows](../updater-core/reports/WINDOWS-STAGE-CI-to-share.json)
- [رسید شکست اولیه](../updater-core/reports/WINDOWS-STAGE-FIRST-FAILURE-to-share.json)
- [QA و وضعیت مرزها](../updater-core/QA.json)
- [README فنی](../updater-core/README-fa.md)
- [اقدامات باقی‌مانده](UPDATER-REMAINING.fa.md)
