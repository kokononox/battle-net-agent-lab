# پیشرفت عملی: جداکردن هویت محتوا از وضعیت نسل

[معماری و محدودیت‌ها](../updater-core/research/CONTENT-IDENTITY-NOT-GENERATION.md) · [باقی‌مانده](UPDATER-REMAINING.fa.md)

نتیجهٔ اصلی صرفاً افزایش تعداد تست نیست: در آزمایش native، فرض اولیهٔ عبور writable mapping تأیید نشد؛ capture با اشتراک ناسازگار رد شد و تنها پس از unmap موفق شد. این شاهد محدود تقویت‌کنندهٔ guard است، نه تضمین سکون همهٔ پردازش‌ها یا اتصال به نصب واقعی. مستقل از این نتیجه، برای reuse اصل محتوای خوانده‌شده در کپی موقت مستقل نگه داشته و همان کپی با کلیدهای کامل هدف، اندازه‌ها و checksumها اثبات می‌شود. اگر منبع بعداً تغییر کند کپی عوض نمی‌شود؛ اگر حین خواندن دادهٔ ناسازگار بدهد اعتبارسنجی رد می‌کند. این اثبات محتوای کپی است، نه تشخیص سلامت/نسل نصب یا ایمنی نوشتن آن.

local_content_capture.py و local_capture_admission.py ساخته شدند. خواندن source فقط تا encoded_size و در بلوک‌های حداکثر ۶۴ KiB است؛ حتی sentinel از source خارج از span نمی‌خواند. cap واردکردن ۲۵۶ MiB است و permission نیست. کپی موقت تا close زنده و سپس حذف می‌شود؛ cache دائمی/rollback/power-loss هنوز وجود ندارد. MD5 هویت پروتکلی CASC و SHA256 کپی، امضای ناشر یا تضمین ضد برخورد عمدی نیستند.

## نتیجهٔ تأییدشده
دور اول Windows با 14 error ناموفق بود؛ receipt آن در reports/WINDOWS-LOCAL-CAPTURE-FIRST-FAILURE-to-share.json حفظ شد. fixture پذیرش به backend بومی Windows وصل و unmap پیش از حذف پوشهٔ موقت انجام شد؛ هیچ معیار اعتبارسنجی تولید ضعیف نشد. دور دوم تنها 2 error اشتراک در آزمایش mapping داشت؛ این مشاهده حفظ و فرض آزمون از «باید عبور کند» به بررسی صریح share-refusal/unmap تغییر کرد. گزارش دوم WINDOWS-LOCAL-CAPTURE-MAPPING-OBSERVATION-to-share.json حفظ شده است. نتیجهٔ موفق زیر مربوط به commit آخر با assertions رفتار مشاهده‌شده است، نه موفقیت فرض bypass.
- Linux: 792 پاس، بدون failure/error/skip.
- Windows/Python 3.12.10: 476 پاس، بدون failure/error/skip؛ شامل 36 تست تازه و 2 آزمایش kernel mapping واقعی روی fixture مصنوعی.
- Source commit: e29fa4466e544b392c2e2235e1473ecb0a84aca0
- CI receipt commit: b0bc825e942cca81f8f7839d47a56581920785b2
- [گزارش Windows](../updater-core/reports/WINDOWS-LOCAL-CAPTURE-CI-to-share.json)
- [اجرای مسیر تازه با کپی 52 بایتی موجود](../updater-core/reports/LOCAL-CAPTURE-EXISTING-OBJECT-to-share.json). این receipt تازه است اما target تاریخی 12.1.5.70448 و payload قبلاً stage‌شده است؛ هیچ دانلود تازه یا خواندن نصب امروز نیست.

# اقدامات باقی‌مانده — پس از مسیر مستقل اعتبار محتوا

## پیشرفت و نتیجهٔ تعیین‌کننده
- واردکردن یک stream محدود به کپی موقت مستقل و اعتبارسنجی کامل EKey/CKey، اندازه و BLTE پیاده شد؛ سپس کپی دوباره بررسی و به candidate/catalogue همان هدف bind می‌شود. این مسیر locator و نسل را مدرک محتوا نمی‌داند و هیچ HTTP/ETag ساختگی برای ورود محلی نمی‌سازد.
- آزمایش بومی Windows روی فایل‌های کاملاً مصنوعی برخلاف فرض bypass، خطای اشتراک 32 داد: capture با وجود writable mapping قبلی رد می‌شود؛ برگرداندن بایت کافی نیست ولی unmap امکان capture می‌دهد. این شاهد exclusion برای همین حالت است، نه snapshot یا تضمین همهٔ mappingها. عبور موفق A→B→A نشان داده نشد.
- ۳۶ تست تازهٔ capture/admission و ۲ آزمایش native فوق پاس شدند. مجموع Linux=792 و Windows=476 با صفر شکست/خطا/skip؛ شمار دو پلتفرم هم‌پوشانی دارد.
- همان کپی ۵۲ بایتی موجودِ قبلاً stage‌شده، از مسیر تازه وارد و با candidate/catalogue هدف تاریخی تطبیق داده شد. این اجرای تازه روی کش موجود است، نه اثبات reuse از نصب امروز. کپی موقت پس از پایان حذف شد.

## ترتیب باقی‌مانده
1. ساخت و qualification خوانندهٔ بومیِ دقیقاً محدودِ یک شیء آرشیو محلی برای تغذیهٔ همین capture؛ header/offset/archive/byte budget صریح، full key و checksum، توقف امن و بدون scan یا fallback خودکار. API فعلی stream می‌گیرد، خودش بازی را باز نمی‌کند. اجرای زنده scope و تأیید مستقل می‌خواهد؛ فعلاً هیچ درخواست اقدام کاربر وجود ندارد.
2. qualification قواعد feature/variant/dependency و ترجیحات تازه برای required set. candidate تاریخی همچنان required set معتبر تولید نیست؛ کش معتبر این مشکل را حل نمی‌کند.
3. reuse معتبر از کپی‌های مستقل و محاسبهٔ دقیق حجم لازم برای همان required set؛ unknown صفر نیست. انتقال واقعی و resume/recovery نیز qualification جدا دارند.
4. writer تراکنشی CASC با journal، rollback و activation روی کپی مستقل؛ در این مرحله اتصال معنایی store/control به نصب و سکون نویسنده‌ها همچنان لازم است. آن‌ها برای صرفِ هویت محتوای کپی شرط نیستند، ولی برای ادعای نسل فعال یا write حذف نشده‌اند.
5. آزمون چندنسخه/نسخهٔ آینده با discovery تازه و fail-closed قالب ناشناخته، سپس UI و انتشار.

active_generation_proven، installed_content_reuse_authorized، required_set_selected، installation_ready و apply_authorized=false؛ required_network_download_bytes=null. این مسیر کش دائمی یا ابزار کاربر نهایی نیست. فایل جدیدی از بازی کاربر یا CDN خوانده نشد، mutex حدسی باز/ساخته نشد و هیچ game write/repair/admin/ACL رخ نداد. ZIP تازه ساخته نشد.

نسخهٔ ZIP قبلی ۰٫۲۷ تغییر نکرده است؛ این کد افزودهٔ پس از آن است و ZIP تازه ندارد.
