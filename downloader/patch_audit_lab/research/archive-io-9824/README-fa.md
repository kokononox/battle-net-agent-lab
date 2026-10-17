# مسیر اصلی خواندن آرشیو Agent 9824، با مرزهای تطبیق‌داده‌شده

> مرحلهٔ بعد، مدیر/cache اصلی: [archive-cache-9824](../archive-cache-9824/README-fa.md) جای open-manager adapter این checkpoint را با تابع اصلی و cache/hash/equality/list/retain/release اصلی پر کرده و مسیر اصلی تا CreateFileW را اجرا کرده است؛ constructor allocation/درج و OS/formatter/lock هنوز adapter هستند. ۸۱۴ آزمون/صفر skip؛ این گزارش ۷۵۳تایی تاریخی حفظ شده است.

## نتیجه و مرز ادعا

هفت تابع دست‌نخوردهٔ Agent 9824، **۷۷۳ بایت کد اصلی**، در ELF پژوهشی i386 اجرا شدند. مسیر اجرا اکنون انتخاب شمارهٔ آرشیو، کنترل بازه، ماسک offset، فراخوانی خواندن و انتشار خطای خواندن را در بر دارد؛ فقط getter یا مدل Python نیست. هویت Agent همان SHA256 پین‌شدهٔ `b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5` است.

اما **کل Agent، open/cache manager اصلی، Windows SEH و Windows I/O اجرا نشده‌اند**. مدیر بازکردن اصلی `0x71d1f3` با adapter صریح جایگزین شده که descriptor فقط‌خواندنی فایل مشخص‌شدهٔ caller را تحویل می‌دهد. `ReadFile` در مرز API به **Linux pread64 واقعی** تطبیق داده شده است. قفل/مدیریت cache و ownership اصلی اثبات نشده‌اند؛ release/logging و frame عادی adapter هستند؛ مسیر alignment و membership غیرتهی trap می‌شود. BLTE و CKey با Python مستقل بررسی می‌شوند. receipt محلی کنترل یکپارچگی است، نه امضای دیجیتال یا مرز اعتماد خصمانه.

## کدهای اصلی اجراشده

| نام پژوهشی | بازهٔ اصلی، انتها غیرشامل | نقش |
| --- | --- | --- |
| range_gate | `0x70da91..0x70db04` | شمارهٔ آرشیو و نبود عبور از مرز |
| membership | `0x70db89..0x70dba7` | شاخهٔ membership تهی |
| archive_read | `0x70dbd5..0x70dcf3` | orchestrator همگام خواندن، routing و خطا |
| buffer_read | `0x70bcad..0x70bd7c` | مسیر خواندن با alignment object تهی |
| read_file_wrapper | `0x86516f..0x8651d1` | OVERLAPPED offset، ReadFile، count و error |
| last_error_jump | `0x86deb1..0x86deb7` | انتقال به GetLastError تطبیق‌داده‌شده |
| shift64 | `0x876d30..0x876d4f` | شیفت منطقی اصلی ۶۴ بیتی |

ثابت success چهار بایت فقط‌خواندنی است. build، hash بایت‌های اصلی را در ELF کنترل می‌کند، graph مستقیم بسته است، دو indirect call از import table پین‌شده به `ReadFile` و `GetLastError` تأیید شده‌اند؛ stack غیرقابل‌اجرا و هیچ segment از نوع RWX نیست. کد استخراجی باینری و فایل اجرایی Agent در مخزن منتشر نشده‌اند.

## یافته‌هایی که قرارداد را دقیق‌تر کردند

1. **در این تابع و پروفایل shift=30، شمارهٔ ۱۰۲۳ رد می‌شود**؛ شماره‌های ۰ تا ۱۰۲۲ مجازند. بازهٔ عبوری از مرز ۱GiB هم پیش از بازکردن رد می‌شود و نتیجهٔ بالایی ۱۰ است. دریافت شمارهٔ ۱۰۲۳ از getter خالص در مرحلهٔ قبل، به معنی پذیرش آن توسط کل خواننده نبود؛ آن نتیجهٔ تاریخی درست اما محدودتر بود. adapter جدید این محدودیت را اعمال می‌کند.
2. طول صفر پس از کنترل بازه، success و count صفر می‌دهد و open/read انجام نمی‌دهد.
3. mode=0 با membership تهی، آرگومان ۱ به مدیر open می‌دهد؛ mode=1 آرگومان ۴ می‌دهد. این‌ها **آرگومان داخلی مدیر** هستند، نه استنتاجی از Windows CreateFile flags.
4. offset فایل از address با mask `0x3fffffff` گرفته می‌شود. archive انتخابی و offset/count در receipt ابزار ثبت می‌شوند؛ open adapter براساس این شماره مسیر پیدا نمی‌کند، بلکه فقط فایل صریح caller را می‌گیرد. تطابق filename با شماره در policy مستقل بررسی می‌شود.
5. **success به‌تنهایی به معنی خواندن کامل نیست**: از نمونهٔ ۱۰۲۴ بایتی، درخواست ۲۰ بایت از offset=1020، success و count=4 داد؛ در EOF، success/count=0. بنابراین گیت object علاوه بر status، برابری count با span مورد انتظار را الزام می‌کند.
6. خطای تزریقی ۵ در مرز ReadFile به status=8 اصلی در `buffer_read/archive_read` رسید؛ open error=7 بدون خواندن به همان ۷ منتقل شد. ReadFile=false/GetLastError=38 در این adapter با count اولیهٔ صفر، success/count=0 می‌دهد؛ ادعایی دربارهٔ تمام رفتارهای واقعی ویندوز یا count همهٔ موارد خطای ۳۸ نیست.
7. در primitive کنترل بازه، نتیجهٔ شیفت ۶۴ بیتی به DWORD پایین محدود می‌شود؛ address با افزایش `1<<62` می‌تواند شمارهٔ پایین یکسان بدهد. **policy مستقل این آدرس‌ها را پیش از اجرا رد می‌کند**. کنترل‌های callerهای بالاتر و قرارداد محصول کامل بررسی نشده‌اند؛ این نتیجه ادعای آسیب‌پذیری نیست.

## شواهد آزمایش

- **۱۷۳۵ بردار native/model مطابق**: ۴۵۸ status موفق، ۸۳۵ رد بازه، ۲۴۰ خطای open و ۲۰۲ خطای خواندن. ۳۵۹ مورد success کوتاه شامل EOF و تزریق مشخص خطای ۳۸ است؛ success کوتاه به‌عنوان object معتبر پذیرفته نمی‌شود.
- **۸ بازخوانی source/target واقعی** از چهار کپی کوچک `data.000`، `data.003`، `data.004`، `data.1022`. lookup اصلی V8 بازه را می‌دهد، مسیر اصلی جدید بایت‌ها را می‌خواند، parser/getter اصلی قبلی هدر و آدرس را کنترل می‌کند و Python مستقل BLTE/CKey را بررسی می‌کند. فایل‌ها ۸۵۶ بایت، با prefix صفر و فقط fixture هدر/داده‌اند؛ storage چندآرشیوی کامل نیستند.
- target CKey مستقل از Encoding: `3d42bf2e42127f313b0ec64cb440cde9`؛ CKey source مشتق‌شده است، نه شاهد مستقل. هر object پس از decode، ۳۳۹۴۰ بایت است.
- `retail_io_cycle.py` گیت bind و lookup موجود را نگه می‌دارد و خواندن اصلی + exact count + parser/header + BLTE/CKey را زیر قفل پایه پیش/پس publication و در no-op الزام می‌کند.
- **۹ توقف سخت با exit=91، resume و no-op بدون نوشتن موفق**. source/prefix و همهٔ indexهای اولیه حفظ شدند.
- تزریق خطای ۵ **فقط در adapter ReadFile برای target** واقعاً از توابع اصلی عبور کرد و به ۸ رسید؛ caller پژوهشی انتشار control را متوقف کرد و control قدیمی/journal prepared را نگه داشت. حذف تزریق، recovery را موفق کرد. فایل واقعی خراب نشده بود. خرابی هدر در مرز parser هم جداگانه همین توقف امن را نشان داد.
- **۷۵۳ آزمون، صفر failure/error/skip؛ ۵۷ آزمون تازه**. همهٔ وابستگی‌های native قدیمی و fixtureها برای full suite فراهم بودند.

رسیدها: `FRAGMENT-BUILD-RECEIPT.json`، `EXPERIMENT-RESULTS.json`، `CYCLE-EXPERIMENT.json`، `TEST-RESULTS.json` و `ALL-TESTS.log`.

## بازتولید

در Linux با Python، binutils، قابلیت اجرای ELF i386 و Agent دقیقاً پین‌شده؛ از package root و خروجی تازه و خارج از پوشهٔ بازی:

```bash
export PYTHONPATH=.
python -B research/archive-io-9824/native/build.py \
  --agent "$PINNED_AGENT" --out-new "$WORK/native"
export ARCHIVE_IO_ORACLE="$WORK/native/archive_io_oracle"
python -B research/archive-io-9824/run_experiments.py \
  --io-oracle "$ARCHIVE_IO_ORACLE" --span-oracle "$SPAN_READER_ORACLE" \
  --lookup-oracle "$LOOKUP_MERGE_ORACLE" \
  --prior-owned-store "$SPAN_PRIOR_STORE" --out-new "$WORK/matrix"
python -B research/archive-io-9824/run_cycle_experiments.py \
  --io-oracle "$ARCHIVE_IO_ORACLE" --span-oracle "$SPAN_READER_ORACLE" \
  --lookup-oracle "$LOOKUP_MERGE_ORACLE" --bind-oracle "$BIND_CONTRACT_ORACLE" \
  --prior-owned-cycle "$V8_PRIOR_CYCLE" --out-new "$WORK/cycle"
python -B -m unittest discover -s tests -v
```

برای suite بدون skip، متغیرهای native تاریخی همان checkpoint قبلی هم لازم‌اند. `SPAN_PRIOR_STORE` همان completed lookup store معتبر است؛ `V8_PRIOR_CYCLE` کپی پژوهشی پیشین است، نه نصب اصلی. هیچ مسیر fallback یا discovery بازی وجود ندارد. API raw حداکثر ۴۰۹۶ بایت می‌خواند؛ reader سخت‌گیر فقط archive<1023، offset>=480، span>30 و <=4096 و عدم عبور از segment را می‌پذیرد. پشتیبانی از objectهای بزرگ یا فایل‌های واقعی چندگیگابایتی نتیجهٔ این milestone نیست.

## ترتیب ادامه و gate خروج از مرحلهٔ اول

این milestone **مرحلهٔ اول را کامل اعلام نمی‌کند**. باقی‌ماندهٔ همین مرحله: اجرای واقعی مسیر open/cache manager و انتخاب فایل، و اتصال caller سطح بالای object-read؛ آزمایش mmap/refresh index کامل با آن caller نیز هنوز باقی است. مسیرهای alignment غیرتهی، SEH، cache eviction و concurrency اصلی خارج از محدوده‌اند.

سپس به همان ترتیب توافق‌شده: Windows writer/locking/publication/recovery روی کپی مجزا؛ بعد full-build planning/multiarchive/rollover/consecutive cycles/root/install/download؛ و در پایان installation binding/activation/`.build.info` و launch روی کپی. در محیط فعلی Wine و cross-compiler ویندوز یافت نشدند و هیچ آزمون ویندوز انجام نشده است؛ نتیجهٔ Linux جای آن را نمی‌گیرد. publication همچنان Linux سفارشی است و proof قطع برق نیست. بازی، Lab، Portable اصلی و Release تاریخی تغییر نکردند. **نصب اصلی آمادهٔ نوشتن نیست.**
