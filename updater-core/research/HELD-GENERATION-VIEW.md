# رفع مانع خواندن هم‌زمان و اصلاح تعریف نسل

## تصمیم مبتنی بر شاهد موجود
شماره‌های control «ارجاع منتشرشده» هستند؛ استفادهٔ موفق تمام readerهای بازی/Agent از همان نسل را ثابت نمی‌کنند. در قطعهٔ pinned Agent9824، cache قبل از bind عوض می‌شود و مقدار برگشتی bind لزوماً نتیجهٔ برگشتی تابع نیست. آزمایش تاریخی با helperهای mock حالت bind error سپس skip در خواندن دوم را ثبت کرده است. این دور باینری Agent یا قطعهٔ native اجرا نشد؛ ۳۵۴ بایت از اسمبلی قبلی بازسازی و SHA با رسید قبلی تطبیق داده شد. نتیجه به تمام نسخه‌ها یا مسیرهای تولید تعمیم داده نمی‌شود.

شواهد immutable:
- https://github.com/kokononox/battle-net-agent-lab/blob/7916903f5378f72a28f745fd30fe3ae11670451a/downloader/patch_audit_lab/research/sequence-visibility-9824/reader-refresh.asm
- https://github.com/kokononox/battle-net-agent-lab/blob/7916903f5378f72a28f745fd30fe3ae11670451a/downloader/patch_audit_lab/research/sequence-visibility-9824/EXPERIMENT-RESULTS.json
- https://github.com/kokononox/battle-net-agent-lab/blob/7916903f5378f72a28f745fd30fe3ae11670451a/downloader/patch_audit_lab/research/sequence-visibility-9824/FRAGMENT-BUILD-RECEIPT.json

## پیاده‌سازی واقعی تازه
windows_generation_view.py جای خالی capture را با API بومی Windows پر می‌کند: .build.info، build config متصل به آن، Data/data/shmem و دقیقاً ۱۶ ایندکسِ ارجاع‌شده. هر ۱۹ فایل با دسترسی خواندن و share READ هم‌زمان نگه داشته می‌شوند؛ مسیرهای والد نیز علیه rename/delete معمولی نگه داشته می‌شوند. هیچ انتخاب بر اساس بزرگ‌ترین نام، جست‌وجوی نصب، enumerating پوشه، خواندن LRU/آرشیو، شبکه، CLI یا writer ندارد.

ایندکس‌ها پیش از اولین خواندن محتوای ایندکس همگی باز می‌شوند. دو دور bytes/checksum/bucket بررسی و پس از دور دوم همهٔ ایندکس‌ها، control و metadata دوباره بررسی می‌شوند. خطا، فقدان، قالب ناشناخته، pending/reset، hardlink یا اشتراک ناسازگار توقف و آزادسازی همهٔ handleها می‌دهد؛ repair اجرا نمی‌شود. ضمانت handle فقط تا close/خروج از context اعتبار دارد؛ خروجی بعداً lock زنده نیست.

## چیزی که هنوز حل نشده
این API shared mapping قدیمی یا تغییر A→B→A را منتفی نمی‌کند و snapshot نیست. از همان root بازکردن با اثبات معنای نام داخلی control برای محصول/نصب یکسان نیست. معنای extension و V8 location هنوز qualification نشده؛ تمام نشانه‌های نصب، reuse و apply false می‌مانند. این کار «capture بومی پیاده‌سازی نشده» را رفع می‌کند، نه کل مرحلهٔ اول را.

برای مسیر نگهداری آفلاین باید closed-client/quiescence و اتصال معنایی store به نصب جداگانه qualification شوند؛ شرط غیرممکنِ اثبات وضعیت حافظهٔ همهٔ readerها را با ادعای بی‌پشتوانه دور نمی‌زنیم. کامل بودن feature/variant/dependency selection نیز مستقل و باز است.

## آزمون و حریم خصوصی
۱۰ آزمون حافظه‌ای ترتیب خواندن و تغییرات را در Linux پوشش می‌دهند؛ این‌ها شاهد Windows نیستند. ۲۴ آزمون بومی Windows روی درخت‌های موقت **کاملاً مصنوعی تازه** برای deny write/delete، writer قبلی، فقدان/خرابی، آزادسازی و سقف حجم اضافه شده‌اند. نتیجهٔ Windows تنها از receipt همان source commit پذیرفته می‌شود. این مرحله دادهٔ تازه‌ای از نصب کاربر نخواند. بستهٔ ZIP یا probe تازه برای کاربر ساخته نشده است.
