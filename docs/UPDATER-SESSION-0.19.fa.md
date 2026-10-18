# تحویل پذیرش staging بومی Windows — ۰٫۱۹

ادامهٔ [۰٫۱۸](UPDATER-SESSION-0.18.fa.md). کد در updater-core/ است؛ نسخه‌ها در منطق محصول به یک مهاجرت ثابت محدود نشده‌اند. 12.1.5.70448 فقط snapshot پژوهشی تاریخی است، نه ادعای آخرین نسخه.

## انجام‌شدهٔ این مرحله
- اتصال WindowsStreamStage به reverify_stream_candidate، فقط با نوع دقیق در کنار StreamStage. object جعلی و subclass قبل از خواندن receipt رد می‌شوند.
- URI واقعی فایل Windows برای بانک read-only با Path.as_uri؛ هویت بانک/target، full EKey/CKey و اندازه‌ها به‌اضافهٔ verify تازهٔ segmentها/BLTE کنترل می‌شوند. restore metadata جای proof نیست.
- خطای fixture در نخستین admission CI (فیلد name اضافی در تبدیل spec) محلی بازتولید و با نگاشت صریح چهار فیلد اصلاح شد؛ تست قرارداد مستقل Linux اضافه و رسید شکست اولیه نگه داشته شد.
- ده آزمون مستقل native admission با بانک کوچک synthetic: سالم/restore، فساد payload، target/catalogue تغییرکرده، انتخاب‌نشده، ادعای apply در receipt، guard بسته، subclass و CKey متفاوت با hash receipt به‌روز.
- ۱۲۱ تست در اجرای واقعی Windows/Python 3.12.10 با صفر failure/error/skip: ۷۳ portable + ۳۸ native stage + ۱۰ native admission. source commit: 0da8bfdbec54f742f53f627e364997efd99b67cd.
- ۴۸۳ تست Linux، hash/CRC بسته و تست مجدد در ZIP استخراج‌شده. عدد Windows با Linux جمع نشود؛ بخشی از منطق روی پلتفرم دیگر تکرار می‌شود.

## هنوز انجام نشده
کنترلر شبکهٔ چندشیء/بزرگ با budget/Range/ETag/resume، qualification مستقل policy/feature/variant/patch، پروفایل تازه و نسل فعال نصب، reuse کامل و محاسبهٔ حجم، CASC writer/rollback/activation، end-to-end در کپی Windows و UI/انتشار. نتیجهٔ تازه فقط verified staging input است، نه required set یا اعتبار محتوای نصب کاربر. حجم ضروری دانلود null و installation_ready=false/apply_authorized=false باقی‌اند. native_windows_staging_backend_qualified=false یعنی qualification تولیدی/قطع برق هنوز انجام نشده، نه شکست تست‌های مصنوعی.

کاربر Windows و فضای کپی آزمایشی دارد؛ هنوز کپی بازی یا probe روی نصب درخواست نشده است. نه game access، نه CDN بازی تازه، نه admin/ACL/repair. workflow مستقل Agent دست‌نخورده است؛ متادیتای موجود دوباره دانلود نشود. decoded بزرگ، SQLite، payload بازی، transcript و credential به مخزن/ZIP نمی‌روند.

[رسید Windows](../updater-core/reports/WINDOWS-ADMISSION-CI-to-share.json) · [QA](../updater-core/QA.json) · [سورس و تست](../updater-core/GITHUB-SOURCE.md) · [اقدامات باقی‌مانده به ترتیب](UPDATER-REMAINING.fa.md)
