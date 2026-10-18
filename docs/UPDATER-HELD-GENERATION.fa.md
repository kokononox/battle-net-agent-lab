# پیشرفت عملی — خواندن نسل با handleهای نگه‌داشته‌شده

[شرح پیاده‌سازی و شاهد محدود](../updater-core/research/HELD-GENERATION-VIEW.md) · [باقی‌مانده](UPDATER-REMAINING.fa.md)

ماژول WindowsGenerationView به‌صورت کتابخانه و بدون CLI اضافه شد. ۱۹ فایل در یک context باز نگه داشته می‌شوند. پس از باز شدن همهٔ ایندکس‌های ارجاع‌شده، محتوای دو دور اعتبارسنجی و در پایان control و metadata دوباره بررسی می‌شود. هر شکست همهٔ handleها را آزاد می‌کند؛ انتخاب بزرگ‌ترین filename یا repair ندارد. ضمانت sharing پس از خروج context پایان می‌یابد.

به‌جای افزودن یک بستهٔ پژوهشی دیگر، کمبود عملی capture رفع شد. البته گرفتن handle عادی معادل snapshot یا اثبات سکون client نیست. مسیر یکسان نیز معنای نام داخلی store را ثابت نمی‌کند. این دو، همراه selection کامل، مانع بعدی‌اند؛ کل milestone اول بسته نشده است.

در شاهد pinned Agent9824، cache پیش از bind تغییر می‌کند و raw return=0 دلیل کافی برای موفقیت bind نیست. این دور ۳۵۴ بایت از اسمبلی موجود بازسازی و SHA با رسید تاریخی تطبیق داده شد؛ اصل Agent یا fragment native دوباره اجرا نشد. آزمایش‌های تاریخی helper-mocked با آزمایش نصب واقعی اشتباه نشوند.

## آزمون قابل بازبینی
- Linux: 756 پاس، صفر failure/error/skip؛ شامل 10 تست تازهٔ memory-only. دادهٔ عمومی موجود و fixture؛ بدون دانلود تازه.
- Windows/Python 3.12.10: 438 پاس، صفر failure/error/skip؛ شامل 24 تست تازهٔ native روی درخت‌های موقت کاملاً مصنوعی و همان 10 تست حافظه‌ای.
- Source commit: f8685b73ee302c84dca80360a723606b13bd084a
- Receipt commit: bd29f3a205a0aa320459a084dbdd575063a52496
- Receipt: [گزارش minimal](../updater-core/reports/WINDOWS-HELD-GENERATION-CI-to-share.json)
- شمار پلتفرم‌ها جمع‌پذیر نیست. تست sharing روی فایل مصنوعی، qualification نصب واقعی/atomicity نیست.

# اقدامات باقی‌مانده — پس از پیاده‌سازی held read view

## کار انجام‌شده
جای خالی capture بومی ۱۹ فایل پر شد: metadata pair + control + دقیقاً ۱۶ ایندکس ارجاع‌شده، همگی در یک context با read handles نگه‌داشته‌شده. ۲۴ آزمون تازهٔ واقعی Windows روی فایل‌های کاملاً ساختگی پاس شده‌اند. ۱۰ آزمون حافظه‌ای جدا ترتیب/تغییرات را بررسی می‌کنند. مجموع رگرسیون Linux=756 و مجموعهٔ Windows=438، با صفر خطا/شکست/skip؛ این دو مجموع هم‌پوشانی دارند. [جزئیات](../updater-core/research/HELD-GENERATION-VIEW.md).

## ترتیب باقی‌مانده
1. **مرحلهٔ اول همچنان باز:** اتصال معنایی store/control به نصب و qualification حالت نگهداری آفلاین؛ گرفتن read handle به‌تنهایی snapshot یا منع همهٔ mapped writerها نیست. ارجاع منتشرشده در control با استفادهٔ موفق client یکی نیست. معنای extension و V8 location نیز هنوز کامل نیست. دیگر نباید capture را «پیاده‌سازی‌نشده» بنامیم؛ آنچه باقی است qualification همین پیاده‌سازی برای نصب واقعی است.
2. کامل‌کردن و اعتبارسنجی feature/variant/dependency selection و اتصال ترجیحات تازه به required set. candidate تاریخی هنوز required set معتبر تولید نیست؛ شمارش آزمون بیشتر این فاصله را پر نمی‌کند.
3. اثبات reuse محلی از همان read view معتبر و full content identity؛ سپس حجم دقیق دانلود. required_network_download_bytes=null؛ unknown به معنی صفر نیست.
4. qualification انتقال واقعی محدود، resume/recovery و budget؛ شبکهٔ تازه فقط با scope مستقل مجاز.
5. writer تراکنشی CASC، journal/rollback/activation و آزمون شکست/قطع روی کپی مستقل؛ سپس آزمون چندنسخه، کشف تازهٔ نسخه، UI و انتشار. writer نصب واقعی هنوز وجود ندارد.

فعلاً اقدام کاربر لازم نیست. این دور فایل تازه‌ای از نصب کاربر، archive، LRU یا CDN بازی نخواند؛ هیچ نصب/repair، admin/ACL یا بازی‌نویسی انجام نشد. ZIP تازه ساخته نشد. active_generation_proven/local_reuse_authorized/installation_ready/apply_authorized=false. workflow مستقل Agent دست‌نخورده ماند.
