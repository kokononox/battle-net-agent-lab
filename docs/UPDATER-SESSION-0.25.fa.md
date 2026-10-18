# ترجیحات نصب و مشاهدهٔ محدود متادیتا — ۰٫۲۵

منطق خواندن تگ‌های نصب اکنون بندهای جداشده با colon، نشانگر optional و رابطهٔ دقیق زبان با text/speech را حفظ می‌کند؛ از union تگ‌ها یا ساختن ترکیب‌های دلخواه پرهیز می‌شود. بند مبهم، ناسازگار یا ناشناخته رد می‌شود. هویت Retail و MD5 پیکربندی پیش از تحلیل کنترل می‌شود؛ چهار qualifier خصوصی کپی تاریخی حذف شده‌اند و فقط تعدادشان گزارش می‌شود.

روی کپی فایل‌های ارسالی قبلی اجرا شد: baseline تاریخی 12.1.0.69933، Windows/x86_64/EU، متن enUS و صدا enUS. این‌ها ترجیحات فعلی launcher یا نسل فعال امروز را اثبات نمی‌کنند. گزارش خروجی مسیر نصب یا تگ خصوصی ندارد. ادغام با ProductConfig تغییر alias را به‌صورت نیاز به بازبینی/replan نشان می‌دهد، نه تغییر بی‌خبر ترجیحات.

کتابخانهٔ جداگانهٔ WindowsMetadataPair فقط دو فایل .build.info و BuildConfig مشتق از کلید معتبر آن را می‌خواند. هر دو handle تا پایان بررسی باز می‌مانند و نوشتن/حذف عادی را نمی‌پذیرند؛ ancestorها نیز در برابر rename/delete عادی نگه داشته می‌شوند. اندازه‌ها محدود، فایل reparse/offline/recall یا hardlink رد، و bytes دوباره بررسی می‌شوند. این ابزار CLI آمادهٔ استفادهٔ کاربر ندارد و مجوز دسترسی به نصب زنده نیست. shmem/LRU/index/archive خوانده نمی‌شود، enumeration یا شبکه/نوشتن ندارد؛ OS snapshot یا اثبات نسل فعال هم نیست. root دلخواه به‌عنوان متعلق به ما فرض نمی‌شود (game_access=null). خطای خام native ممکن است مسیر داشته باشد و نباید بدون پاک‌سازی منتشر شود.

۲۶ تست pure جدید و ۲۰ تست native جدید: مجموع ۶۷۴ Linux و ۳۳۲ Windows/Python 3.12.10، صفر failure/error/skip. تست ویندوز فقط روی پوشه‌های موقت مصنوعی انجام شد، نه نصب بازی. شمار پلتفرم‌ها هم‌پوشانی دارد. source/receipt در QA.json و گزارش WINDOWS-METADATA-PAIR-CI ثبت شده‌اند.

**مرحلهٔ اول هنوز باز است:** انتخاب کامل feature/variant/dependency، ترجیحات واقعاً تازه و نسل فعال همساز باید ثابت شوند. حدس offset از کتابخانهٔ ثالث یا انتخاب بزرگ‌ترین نام idx جای اثبات نیست. required_set_selected/active_generation_proven/installation_ready/apply_authorized=false و required_network_download_bytes=null. فعلاً فایل، اجرای ابزار یا اجازهٔ تازه‌ای از کاربر لازم نیست.

[شواهد، منابع و ادامه](research/INSTALLED-PREFERENCES-AND-GENERATION.md) · [گزارش کپی تاریخی](reports/INSTALLED-PREFERENCE-COPY-to-share.json) · [تست ویندوز](reports/WINDOWS-METADATA-PAIR-CI-to-share.json)

## ترتیب ادامه

۱. قواعد کامل انتخاب و ترجیحات تازه/نسل فعال همساز؛ هر سه هنوز در milestone اول هستند.
۲. reuse معتبر و required set/حجم دقیق.
۳. انتقال واقعی محدود، resume/recovery و یکپارچگی.
۴. writer تراکنشی CASC، rollback و activation، ابتدا روی کپی مستقل.
۵. رابط کاربری، آزمون نسخه‌های آینده و انتشار.

مجوز نوشتن روی بازی، admin/ACL، repair یا دانلود تازه داده نشده است. workflow مستقل Agent دست‌نخورده بماند. کش‌ها دوباره دانلود نشوند. هیچ ادعای latest آنلاین دربارهٔ هدف تاریخی 12.1.5.70448 وجود ندارد.
