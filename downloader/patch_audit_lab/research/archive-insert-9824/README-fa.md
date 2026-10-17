# سازنده و درج اصلی cache — Agent 9824

## نتیجهٔ این checkpoint

زنجیرهٔ اصلی خواندن، مدیر بازکردن، constructor در `0x72d89d`، object initialization، درج جدول hash در `0x72d52f` و append در `0x72dbfb` در harness جدا اجرا شدند. ورودی cache از پیش کاشته نشده است: **خواندن اول فایل را باز می‌کند و entry می‌سازد؛ خواندن‌های بعدی همان entry را استفاده می‌کنند.** برای دو آرشیو متناوب، دو open/دو allocation کافی بود و خواندن‌های سوم و چهارم هیچ open یا allocation دیگری نداشتند. برخورد hash و حرکت فهرست نیز با entryهای ساخته‌شده در همین اجرا آزمایش شدند.

این checkpoint ادامهٔ `98892e105010d92db8863bbc76d118d94860cba7` است، نه بازیابی فایل‌های منتشرنشدهٔ آخر جلسهٔ قبل. محیط تازه از روی کد همان commit و نمونهٔ رسمی با SHA256 ثابت ساخته شد:

`b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5`

۳۱ قطعهٔ کد اصلی، مجموعاً ۳۳۵۶ بایت، بدون تغییر در ELF قرار گرفتند و بایت‌های آن‌ها با نمونهٔ پین‌شده کنترل شدند. این عدد شمار قطعاتِ نگاشت‌شده است، نه ادعای پوشش همهٔ branchهای آن‌ها. بازسازی دوم همان SHA256 باینری را تولید کرد. اجرای کامل Agent.exe صورت نگرفت.

## مرزها — دقیق و مهم

- allocator عمومی Agent اجرا نمی‌شود: virtual allocator به arena ثابت حداکثر چهار object متصل است. **object initializer و درج hash اصلی‌اند؛ تخصیص حافظهٔ عمومی شبیه‌سازی‌شده است.**
- هشت bucket و هشت slot از پیش تخصیص یافته‌اند، ولی هیچ entry از پیش درج نشده است. رشد جدول، eviction و mapping غیرتهی به trap می‌روند؛ این مسیرها پشتیبانی یا اثبات نشده‌اند.
- formatter و تبدیل ASCII/UTF-16، frame عادی به‌جای SEH و lock تک‌ریسمانی همچنان adapter هستند.
- CreateFileW به openat فقط‌خواندنی و ReadFile به pread64 لینوکس متصل است. درخواست write/create **رد می‌شود، نه اینکه به read-only تبدیل شود**.
- انتقال handle به object توسط تابع اصلی انجام می‌شود؛ cleanup handle و mapping غایب adapter محدود دارد. destructor واقعی object و چرخهٔ تخلیهٔ cache اجرا نشده‌اند. پایان فرایند descriptorهای باقی‌مانده را می‌بندد؛ این اثبات destructor نیست.
- تمام فایل‌های این checkpoint دادهٔ ساختگیِ قطعی‌اند. **ZIP خصوصی Retail، Encoding کامل، EKey/CKey نمونهٔ واقعی و چرخهٔ publication/recovery در این جلسه دوباره آزمایش نشدند.**
- مجموعهٔ تاریخی ۸۱۴ آزمون دوباره اجرا نشده است. عدد این checkpoint را نباید با آن جمع کرد و «۸۴۵ آزمون کامل» نامید.

## نتیجه‌های آزمایش

- ۳۱ آزمون جدید: صفر failure/error/skip.
- ۱۰۲۴ سناریوی native/model، مجموعاً ۴۰۹۶ درخواست خواندن. تمام مقایسه‌ها مطابق بودند.
- ۳۰۲۰ خواندن موفق با تعداد دقیق بایت؛ ۱۸۰ وضعیت صفر ولی خواندن کوتاه/EOF؛ ۸۹۶ وضعیت غیرصفر.
- gate جداگانهٔ `require_exact` موارد status=0 با تعداد ناکافی را رد می‌کند. صرف status صفر معیار موفقیت نیست.
- خطای open شمارهٔ ۲ به ۲، شمارهٔ ۵ به ۸ و شمارهٔ ۳۲ به ۲۴ تبدیل شد؛ retry پس از خطای تزریقی entry موفق ساخت و سپس آن را reuse کرد.
- خطای خواندن entry موجود را از بین نبرد؛ reference هنگام خواندن ۲ و پس از release برابر ۱ بود، حتی در خطای خواندن.
- ۱۲۸ مورد native/model روی checkpoint قدیمی نیز گذشت؛ این جای مجموعهٔ تاریخی را نمی‌گیرد.
- fixtureهای ساختگی بایت‌به‌بایت و از نظر هویت فایل ثابت ماندند. فایل‌های بازی، Lab و Portable اصلی در این محیط موجود نبودند و به آن‌ها دسترسی داده نشد.

## بازتولید

از ریشهٔ `downloader/patch_audit_lab`، Linux با binutils و پشتیبانی ELF i386؛ مسیرها باید واقعی و بدون symlink باشند. نمونهٔ پین‌شده را فقط برای استخراج قطعات به builder بدهید، نه اجرای مستقیم:

```bash
export PYTHONPATH=.
python -B research/archive-insert-9824/native/build.py \
  --agent "$PINNED_AGENT" --out-new "$WORK/native"
export ARCHIVE_INSERT_ORACLE="$WORK/native/archive_insert_oracle"
python -B -m unittest discover -s tests -p test_agent_archive_insert.py -v
python -B research/archive-insert-9824/run_experiments.py \
  --oracle "$ARCHIVE_INSERT_ORACLE" --out-new "$WORK/matrix"
```

runner فقط پوشهٔ تازه می‌سازد و برای مصرف فایل‌ها marker پژوهشی صریح لازم دارد. oracle هویت، digest، ELF بدون RWX و stack غیرقابل‌اجرا دارد. receipt کنترل یکپارچگی محلی است، نه امضای دیجیتال ناشر. ادعاهای agent identity مربوط به همین نسخهٔ پین‌شده‌اند، نه Agent نصب‌شدهٔ کاربر.

`EXPERIMENT-RESULTS.json` خلاصه است. `MATRIX-SAMPLE.json` نمونه‌ای از ماتریس است؛ ماتریس کامل با runner تولید می‌شود و SHA256 آن در خلاصه آمده است. Agent، ELF و archive باینری در Git منتشر نشده‌اند.

## ادامهٔ مستقیم

۱. در صورت بازیابی دادهٔ Portable و وابستگی‌های تاریخی، این oracle به بازخوانی نمونهٔ Retail و gate انتشار/بازیابی قبلی وصل شود؛ نتیجهٔ آن هنوز در این checkpoint وجود ندارد.
۲. caller سطح بالای object و مسیرهای refresh/mapping بررسی شوند؛ اندازه/ظرفیت، eviction، destructor و هم‌زمانی همچنان مرزهای باز هستند.
۳. سپس ترتیب قبلی: writer/locking/publication/recovery روی کپی Windows؛ full-build و multiarchive/rollover؛ در پایان هویت نصب، `.build.info`، فعال‌سازی و اجرای بازی روی کپی.

**مرحلهٔ اول کامل و updater آمادهٔ نصب اعلام نمی‌شود.**
