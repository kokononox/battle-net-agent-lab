# تحویل مرحلهٔ جریانی — ۰٫۱۷

این سند ادامهٔ [۰٫۱۶](UPDATER-SESSION-0.16.fa.md) است؛ کد فعلی در updater-core/ است. نسخه‌های مبدأ/مقصد در منطق محصول hardcode نشده‌اند. snapshot تاریخی هدف هنوز 12.1.5.70448 است، نه ادعای آخرین انتشار امروز.

## انجام‌شده
1. اعتبارسنج جریانی N/Z: بلوک خواندن حداکثر ۶۴ KiB، EKey و checksum chunk و CKey، بدون خروجی decoded یا نگه‌داری کل payload در RAM؛ کلاس‌های قدیمی و دامنهٔ مجوزشان بزرگ نشده‌اند.
2. staging فایل‌محور POSIX: immutable segment تا ۱ MiB، journal فاقد payload، pin هویت source/target/baseline و entity، توقف در تغییر یا lock رهاشده، بدون پذیرش orphan.
3. restore صرفاً metadata/geometry است، نه proof. verify همهٔ segment SHA و محتوای BLTE را از نو کنترل می‌کند. ورودی staging معتبر فقط پس از اتصال کامل به catalogue و candidate پذیرفته می‌شود؛ apply مجاز نشده است.
4. تست واقعی روی فایل‌های موجود: سه متادیتا، مجموع encoded برابر 251510113 بایت، بزرگ‌ترین 188062372؛ decoded digest مطابق رسید قبلی. نمونهٔ ۵۲ بایتی کش قبلی هم در staging جدید بازپخش شد؛ بدون CDN یا بازی.
5. فایل مصنوعی encoded بیش از ۶ MiB با process جدا restore/verify شد. decoded مصنوعی ۲۰ MiB با peak تخصیص verifier زیر ۲ MiB آزموده شد؛ fixture از پیش ساخته‌شده در این سنجش نیست، RSS کل نیست.
6. ۴۷۶ تست Linux، سپس تست دوبارهٔ ZIP استخراج‌شده. ۷۳ تست مصنوعی parser/انتخاب واقعاً روی Windows/Python 3.12.10 بدون failure/error/skip پاس شد. این ۷۳ زیرمجموعه‌ای روی پلتفرم دیگر است، نه ۷۳ تست مستقل قابل‌جمع.

مرجع CI: source f8eed3f8f25aefded34143fc1aa48fea5193ee54، receipt commit 71a0f0b1e37919697402ed646c951e6bb154b637. workflow جدا فقط تست synthetic است، هیچ نصب‌کننده/بازی اجرا نکرد. workflow قبلی Agent تغییری نکرد و با این push trigger نشد؛ انتشار receipt هم loop ایجاد نمی‌کند.

## باقی‌مانده و مرز توقف
- سیاست مستقل feature/variant/patch و ترجیحات زنده هنوز qualify نشده؛ gate انتخاب ۰٫۱۶ همچنان false است.
- تشخیص نسل فعال و reuse معتبر نصب زنده هنوز نداریم؛ حجم دانلود لازم null است.
- کنترلر شبکهٔ فایل بزرگ/چندشیء با journal و بودجه یکپارچه نشده؛ append از پاسخ caller تأمین می‌شود. هیچ درخواست یا retry تازه‌ای مجاز نشده.
- staging فعلی POSIX/trusted scratch است؛ backend بومی Windows، CASC writer تراکنشی، rollback، activation، قطع برق واقعی و UI نهایی qualify نشده‌اند.
- برای مرحلهٔ نصب/فعال‌سازی واقعی، محیط Windows آزمایشی مستقل و کپی بازی لازم است. فعلاً درخواست کپی بزرگ، اجرای probe تازه، اسکن کامل یا دستکاری نصب اصلی داده نشده؛ ابتدا فقط موجودبودن محیط/فضای آزمایش مشخص شود.

installation_ready=false و apply_authorized=false باقی‌اند. فایل decoded بزرگ، SQLite، payload staging/بازی، transcript و اطلاعات ورود در مخزن نیستند. cache موجود پروژه نگه داشته شده؛ متادیتا دوباره دانلود نشود.

## منابع
- [README فنی](../updater-core/README-fa.md)
- [گزارش متادیتای جریانی](../updater-core/reports/STREAM-METADATA-to-share.json)
- [گزارش staging](../updater-core/reports/STREAM-STAGED-CACHE-to-share.json)
- [رسید Windows](../updater-core/reports/WINDOWS-PORTABLE-CI-to-share.json)
- [اقدامات باقی‌مانده](UPDATER-REMAINING.fa.md)
