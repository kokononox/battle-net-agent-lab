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
