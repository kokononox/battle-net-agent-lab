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
