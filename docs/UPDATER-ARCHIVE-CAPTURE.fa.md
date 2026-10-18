# گام جدید: آرشیو محدود ← کپی مستقل ← پذیرش هدف

## دستاورد عملکردی
local_archive_capture.py یک بازهٔ دقیق از stream بدون بافر را به LocalContentCapture می‌رساند؛ windows_archive_capture.py همان مسیر را برای دقیقاً یک فایل صریح data.NNN با handleهای بومی Windows اجرا می‌کند. تست یکپارچه تا admit_capture و candidate/catalogue همان هدف ادامه می‌یابد، نه اینکه فقط header را parse کند. بدون source write، شبکه، اسکن directory یا انتخاب خودکار فایل جایگزین.

## محدودیت خواندن
- ArchiveReadRequest به target/spec تایپ‌شده، archive_id، offset، layout و budget دقیق bind است. شمارهٔ فایل 000..999، اندازهٔ آرشیو/پایان span حداکثر 1 GiB و payload حداکثر 256 MiB است؛ این‌ها مرز پشتیبانی و مصرف‌اند، نه مجوز.
- layout فقط direct-blte یا prefix30-agent9824 است؛ layout ناشناخته/auto و ناسازگاری header بدون fallback رد می‌شوند. برای prefix30، EKey کاملِ معکوس، span size، flags و دو checksum بررسی می‌شوند. این profile پژوهشی Agent9824 است، نه specification عمومی همهٔ نسل‌ها.
- BufferedReader.read می‌تواند خارج از span کوچک prefetch کند؛ آداپتور تازه از FileIO خام و بدون بافرِ همان handle استفاده می‌کند. حساب بایت‌ها مربوط به application reads است، نه sector read/prefetch فیزیکی سیستم‌عامل.
- stat bounds پیش از payload خوانده می‌شود؛ virtual EOF مانع sentinel خارج از span می‌شود. capture دوبار هویت محتوا را بررسی و admission بار دیگر کپی را تطبیق می‌دهد.
- فایل منبع READ/shareREAD باز و ancestorها تا close برای حذف/rename نگه داشته می‌شوند؛ writable handle عادی، hardlink، reparse/offline و مسیر نامعتبر رد می‌شوند. این universal snapshot یا تضمین همهٔ mapped writerها نیست.
- کپی مستقل بعد از بستن منبع زنده می‌ماند، ولی با close حذف می‌شود؛ هنوز cache دائمی، power-loss recovery یا installer نیست. API کنترل approval بیرونی را دور نمی‌زند و خودش approval ایجاد نمی‌کند.

## نتیجهٔ آزمون تأییدشده
Linux: 813 تست پاس، شامل 807 مصنوعی و 6 fixture موجود؛ Windows/Python 3.12.10: 514 پاس، صفر failure/error/skip. تعداد دو پلتفرم هم‌پوشانی دارد. افزودهٔ این گام: 20 تست portable بازه/header/budget، 17 تست native فقط روی فایل‌های مصنوعی، و یک تست integration با مسیر native روی Windows. آزمون‌ها نصب بازی کاربر را باز نکرده‌اند.

- Source commit: d37c2d7aedf486a5fb06e2c10bed2d45ed3ae88f
- CI receipt commit: 293f32927d6b72fe59ac8901291624c4936226d2
- [گزارش Windows این گام](../updater-core/reports/WINDOWS-ARCHIVE-CAPTURE-CI-to-share.json)
- خطاهای checksum/key/size/layout، کوتاهی فایل، توقف پیش از خواندن، cleanup، write/delete/rename عادی، hardlink، existing writer، single use، source-close استقلال کپی و admission هدف پوشش داده شده‌اند.

## نتیجه‌ای که نباید ادعا کنیم
این موفقیت مصنوعی اثبات live local reuse یا required set کامل، نسل فعال، سلامت نصب، حجم دانلود یا آمادگی نصب نیست. هیچ game/CDN access، admin/ACL/repair، اسکن نصب، mutex حدسی یا ZIP تازه انجام نشد. نسخهٔ ZIP قبلی 0.27 دست‌نخورده است و با این source جدید یکی نیست.

[ترتیب اقدامات باقی‌مانده](UPDATER-REMAINING.fa.md). مرحلهٔ بعد qualification انتخاب فایل‌ها و بستن ابهام feature/variant/dependency است؛ هم‌زمان مسیر اجرای محدود کاربر به دامنهٔ مستقل نیاز دارد. اکنون هیچ اقدام یا اجازهٔ کلی از کاربر لازم نیست.
