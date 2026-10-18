# قرارداد بررسی کپی‌های نسل نصب — ۰٫۲۷

## پیشرفت این مرحله
ماژول generation_copy_contract.py ساخته شد؛ فقط bytes دو دور کپیِ از پیش فراهم‌شده را می‌گیرد و هیچ فایل یا شبکه‌ای باز نمی‌کند. هر دور شامل build info، build config، control، فهرست صریح نام‌ها و دقیقاً ۱۶ ایندکس است. نام هر ایندکس باید از همان control پژوهشی آمده باشد؛ بزرگ‌ترین نام فایل یا نسل جدیدتر جایگزین نمی‌شود. هویت baseline/config، برابری هر دو دور، checksum/header/bucket و هندسهٔ پشتیبانی‌شدهٔ همهٔ ایندکس‌ها بررسی می‌شود. قالب ناشناخته، ترکیب خانوادهٔ V7/V8، دنبالهٔ پشتیبانی‌نشده، فقدان فایل و حالت reset/pending باعث توقف می‌شوند؛ نه repair یا تشخیص قطعی خرابی.

خروجی یک bundle hash متصل به همهٔ هویت‌ها می‌سازد و تگ خصوصی، نام داخلی control، مسیر نصب یا دادهٔ آرشیو منتشر نمی‌کند. V8 همچنان qwordهای مکان آرشیو را opaque نگه می‌دارد. extension کنترل نیز معنای کامل اثبات‌شده ندارد. سقف ورودی دو دور تعریف شده، اما این سقف «مجوز خواندن بازی» نیست.

## مرز ادعا
حتی دو کپی کاملاً برابر، OS snapshot نیستند: تغییر A→B→A ممکن است بین دو مشاهده پنهان بماند. root/time/file-ID و اینکه خود client کدام نسل را مصرف می‌کند هنوز bind نشده است. پس active_generation_proven/coherent_live_snapshot_proven/local_reuse_authorized=false می‌مانند. ماژول live reader یا ابزار آمادهٔ اجرا برای کاربر نیست و هیچ مجوز اضافه‌ای از نتیجهٔ موفق تولید نمی‌کند.

در این مرحله فقط fixture مصنوعی اجرا شد. محتوای تازهٔ control/index کاربر، shmem/LRU یا آرشیو خوانده نشد؛ فقط گزارش قدیمیِ پاک‌سازی‌شده برای تعیین محدودیت‌ها مرور شد، نه برای اثبات وضعیت امروز. هیچ CDN، Agent، update/repair، game write یا تغییر permission اجرا نشد.

## تست
۴۰ تست تازه؛ مجموع ۷۴۶ Linux و ۴۰۴ Windows/Python 3.12.10 با صفر failure/error/skip. تست ویندوز روی fixture و پوشهٔ موقت مصنوعی است، نه نصب بازی. شمار دو پلتفرم هم‌پوشانی دارد. source/receipt در QA.json و گزارش WINDOWS-GENERATION-CONTRACT-CI ثبت شده‌اند.

## ادامه
باید معنای control و extensionها، اتصال store/root و هویت فایل‌ها، روش capture محدود بومی و شاهد مستقلِ مصرف نسل توسط client مشخص و اعتبارسنجی شوند. قبل از این‌ها نباید ابزار «تشخیص قطعی نسل فعال» به کاربر بدهیم. قواعد کامل انتخاب و ترجیحات واقعاً تازه نیز هنوز در مرحلهٔ اول بازند. فعلاً اقدام یا فایل تازه‌ای از کاربر لازم نیست.

[قرارداد و محدودیت‌ها](research/GENERATION-COPY-CONTRACT.md) · [معیارهای اثبات زنده](research/GENERATION-LIVE-PROOF-REQUIREMENTS.json) · [گزارش صرفاً مصنوعی](reports/GENERATION-COPY-CONTRACT-SYNTHETIC-to-share.json)

## ترتیب ادامه

# اقدامات باقی‌مانده پس از ۰٫۲۷

## پیشرفت ثبت‌شده
قرارداد pure برای دو دور copied metadata/control و دقیقاً ۱۶ ایندکس ارجاع‌شده ساخته شد؛ header/checksum/هندسهٔ شناخته‌شده بررسی و fallback بزرگ‌ترین نام رد می‌شود. اختلاف دورها، pending/reset یا قالب ناشناخته توقف می‌دهد. دادهٔ fixture کاملاً مصنوعی است. ۷۴۶ Linux و ۴۰۴ Windows پاس‌اند. [تحویل](UPDATER-SESSION-0.27.fa.md).

## ترتیب باقی‌مانده
1. **مرحلهٔ اول هنوز باز است:** انتخاب کامل feature/variant/dependency، ترجیحات واقعاً تازه و نسل فعال همساز. برای نسل فعال اکنون قرارداد منفی و معیارهای مشخص داریم، نه detector زنده: معنای control/extension، اتصال store/root/file-ID، capture محدود بومی و شاهد مستقل استفادهٔ client باید اعتبارسنجی شوند. برابری دو دور snapshot یا محافظت ABA نیست؛ offset حدسی یا بیشترین filename کافی نیست. [معیارها](../updater-core/research/GENERATION-LIVE-PROOF-REQUIREMENTS.json).
2. اثبات reuse محلی، required set معتبر و حجم دقیق دانلود؛ unknown صفر نیست.
3. qualification انتقال واقعی محدود، resume/recovery با budget و approval مستقل.
4. writer تراکنشی CASC، rollback و activation؛ ابتدا کپی مستقل و آزمون قطع عملیات/شکست. writer نصب واقعی هنوز پیاده نشده است.
5. آزمون چندنسخه و نسخهٔ آینده با discovery تازه و stop برای قالب ناشناخته؛ سپس UI، بسته‌بندی و انتشار.

فعلاً اقدام کاربر لازم نیست. این مرحله هیچ فایل تازه‌ای از کنترل یا ایندکس کاربر نخواند؛ سقف API قرارداد مجوز بازی زنده نیست. نه admin/ACL، نه update/repair رسمی، نه broad upload و نه game write تقاضا شود. required_set_selected=false، active_generation_proven=false، required_network_download_bytes=null، installation_ready=false و apply_authorized=false. تست Windows qualification تولید/نصب واقعی نیست. کش‌ها حفظ و workflow مستقل Agent دست‌نخورده بماند.
