# نام رایانه + نام canonical ذخیره‌سازی → seed کلیدهای آرشیو

## نتیجهٔ اصلی

شکاف مرحلهٔ قبل تا حد **ورودی‌های صریح و مصنوعی ASCII** کوچک‌تر شد: seed تنها تابع مسیر نیست. مسیر بررسی‌شده ابتدا نام رایانه را از `GetComputerNameW` می‌گیرد و در حالت موفق ASCII، نتیجه چنین است:

```text
seed = MD5(computer_name_bytes || canonical_storage_name_bytes)
```

نه delimiter اضافه می‌شود، نه NUL پایان رشته و نه lowercase سراسری. سپس همان مولد مرحلهٔ قبل ۱۶ full key رزروشده را از seed می‌سازد. ورودیِ دوم **نام canonical ذخیره‌سازی در کلاس بررسی‌شده** است؛ نباید بدون شاهد آن را root نصب WoW یا مسیر `Data` کاربر فرض کرد.

برای ورودی کاملاً مصنوعی زیر:

```text
computer = LAB-PC
raw path = C:\Games\World of Warcraft\Data
canonical = c:/Games/World of Warcraft/Data
seed = 13c12f1aaed0ac3d869b3fc98e77f84d
```

مدل Python و اجرای جداگانهٔ توابع خالص استخراج‌شده دقیقاً در canonical path، seed و تمام ۱۶ کلید برابر شدند. این مثال نشانی یا نام رایانهٔ کاربر نیست.

همین seed به fixture **جدید** متصل شد؛ prefix شانزده‌رکوردی و indexهای آن با harness native/CascLib بررسی و شیء واقعی Retail دوباره با EKey `faedca88d0a0ab30dae5519239582d31` و CKey `3d42bf2e42127f313b0ec64cb440cde9` بازخوانی شد. خروجی جدید placeholder ندارد، ولی نصب قابل‌اجرا یا activation واقعی نیست.

## نوع آزمایش — نه اجرای Agent روی Windows

این مرحله نسبت به قبلی یک تفاوت مهم دارد: **دستورهای ماشینی ۷ تابع خالص Agent واقعاً اجرا شدند**؛ فقط static audit نیست. آن‌ها با hash کامل باینری ثابت استخراج و در executable کوچک **Linux ELF i386** قرار گرفتند:

- lexical normalizer؛
- MD5 init، update، final و transform؛
- reserved-key generator و bucket.

توابع در نشانی‌های اصلی نگه داشته شدند تا relative callها عوض نشوند. فقط memcpy و memset با helperهای سادهٔ harness جایگزین شدند. بایت‌های همهٔ fragmentها در ELF نهایی دوباره با بایت‌های استخراج‌شده تطبیق داده شدند.

**Agent.exe به‌صورت برنامه اجرا یا بارگذاری نشد، PE loader یا API ویندوز در کار نیست.** نام رایانه و مسیر در argv از مثال‌های مصنوعی داده می‌شوند؛ نه hostname و cwd میزبان خوانده می‌شود، نه فایل بازی. harness فقط syscall خروجی استاندارد و خروج دارد؛ timeout subprocess پنج ثانیه است. ELF به dynamic linker/import نیاز ندارد، load segment قابل‌نوشتن+اجرایی ندارد و stack غیرقابل‌اجرا است. این‌ها یک harness محدودند، نه ادعای sandbox امنیتی عمومی.

فایل Agent، قطعات binary استخراج‌شده و executable harness در Git منتشر نمی‌شوند. فقط source سازنده، assembly wrapper، hashها و گزارش‌های پالایش‌شده ثبت شده‌اند. کد `build.py` از ورودی محلی با SHA ثابت استفاده می‌کند؛ دانلودی ندارد.

## رفتار مسیر که با کد اصلی تطبیق داده شد

- slashها به `/` تبدیل می‌شوند؛ `.` و `..` پردازش می‌شوند؛ case نام پوشه‌ها حفظ می‌شود.
- فقط حرف drive در شکل `C:/...` به lowercase تبدیل می‌شود، نه همهٔ رشته.
- جفت slash ابتدایی UNC و slash انتهایی در حالت‌های بررسی‌شده حفظ می‌شوند.
- رفتار تابع با `ntpath.normpath` یکسان فرض نشده است. مثال مهم: تابع خام `C:/../x` را به `x` تبدیل می‌کند و از root محافظت نمی‌کند؛ wrapper پژوهشی ما چنین خروجی‌ای را **رد** می‌کند، نه اینکه آن را مسیر مجاز نصب تلقی کند.
- مسیر relative ساده فقط با cwd صریح و مطلقِ مصنوعی پذیرفته می‌شود. join ورودی‌ها در wrapper یک **سیاست محدود ما** است؛ اجرای `GetCurrentDirectoryW` یا اثبات سازگاری تمام حالت‌های relative ویندوز نیست.

### دامنه و رد صریح

مدل عمومی فقط printable ASCII، نام رایانهٔ صریح حداکثر ۱۵ کاراکتر و مسیر خام حداکثر ۷۷۵ کاراکتر را پوشش می‌دهد. حالت‌های drive-absolute و UNC و relative ساده با cwd صریح آزمایش شدند. device path، root-relative، drive-relative، ADS، کاراکترهای ویژهٔ خارج از دامنه و root نامعتبر رد می‌شوند. این ردها سیاست احتیاطی ما هستند، نه فهرست خطاهای Agent.

تبدیل کامل Unicode، خطای API نام رایانه، نام واقعی دستگاه، cwd واقعی Windows، reparse point/symlink و هویت نصب کاربر هنوز اثبات نشده‌اند. با اینکه API ورودی wide است، این checkpoint ادعای سازگاری همهٔ Unicode ندارد. هش MD5 نیز شناسهٔ بررسی‌شدهٔ این ساختار است، نه امضای ناشر یا مکانیزم امنیتی پیشنهادی.

## شواهد استاتیک

Agent ثابت `2.41.1.9824`:
`b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5`.

- `0x711452` نام ورودی storage را به canonicalizer بررسی‌شدهٔ `0x712bc9` می‌دهد؛ `0x710b83` seed را برای ساخت کلیدها درخواست می‌کند.
- `0x712b22 → 0x70ee15 → 0x86cfed` به IAT `0x8fb55c` می‌رسد که دقیقاً `KERNEL32!GetComputerNameW` است؛ buffer داخلی ۱۶ wide character ظرفیت دارد.
- `0x712b55` نخست نام رایانه و طول بدون NUL آن را MD5-update می‌کند؛ `0x712b70` سپس نام canonical و طول آن را اضافه می‌کند؛ final در `0x712b82` است.
- ثابت‌های init، padding و bit length و ذخیرهٔ چهار DWORD digest بررسی شدند؛ عملکرد هم با کد اصلیِ استخراج‌شده سنجیده شد، نه فقط تشخیص چهار ثابت.
- مسیر خروجی ASCII در helper تبدیل، byte مقدار کاراکتر را بدون lowercase می‌نویسد.
- **۱۷ byte anchor، ۱۳ direct call و یک import call** در verifier جدید، علاوه بر prerequisiteهای checkpointهای قبلی، تأیید شدند.

## آزمون‌ها

**۴۵۳ آزمون؛ صفر failure/error/skip**، شامل ۲۹ روش تازه نسبت به ۴۲۴ قبلی. برخی روش‌ها بردارهای متعدد دارند؛ تعداد بردار را به‌جای تعداد تست جمع نزده‌ایم.

اجرای بازتولیدپذیر جدا:

- ۹ مورد سطح wrapper، شامل تغییر case نام رایانه/پوشه، drive، UNC، relative و مرز طول؛
- ۱٬۰۲۴ بردار deterministic خام برای normalizer/MD5/تمام ۱۶ کلید؛ همه برابر با fragmentهای اصلی؛ برخی عمداً خارج از سیاست wrapper نصب هستند؛
- ۱۵ بردار MD5 در مرزهای padding/block؛
- ۱۰ ورودی خارج از سیاست مدل و ۴ ورودی نامعتبر مستقیم harness، همگی ردشده؛
- زنجیرهٔ metadata/source/patch واقعی → seed مشتق‌شده از مثال مصنوعی → prefix/index → native EKey/CKey، موفق.

این اعداد اثبات تمام مسیرهای Windows، همهٔ ظرفیت‌ها/شماره‌های archive یا آپدیت کامل پروفایل نیستند. اجرای keygen این harness مشخصاً archive=0 و capacity=1024 است.

## بازتولید

از ریشهٔ `downloader/patch_audit_lab`، روی Linux x86 با قابلیت اجرای ELF i386 و ابزارهای GNU `as`/`ld`:

```sh
PYTHONPATH=. python -B research/name-seed-9824/native/build.py \
  --agent /path/to/hash-pinned/Agent.9824.exe \
  --out-new ./NEW-SEED-NATIVE

PYTHONPATH=. python -B research/name-seed-9824/run_experiments.py \
  --fixture /path/to/original-extracted-portable \
  --agent /path/to/hash-pinned/Agent.9824.exe \
  --isolated-oracle ./NEW-SEED-NATIVE/name_seed_oracle \
  --prefix-native-dir /path/to/archive-prefix-native-build \
  --report-new ./NEW-NAME-SEED-EXPERIMENT
```

nativeهای prefix/CascLib از [checkpoint قبلی](../archive-prefix-9824/README-fa.md) لازم‌اند. اجرای metadata محلی با manifest اصلی است، نه اسکن payloadهای نصب یا دانلود تازه. خروجی باید جدید و خارج از مسیر بازی باشد.

```sh
NAME_SEED_ORACLE=./NEW-SEED-NATIVE/name_seed_oracle \
PREFIX_NATIVE_DIR=/path/to/archive-prefix-native-build \
RETAIL_POC_NATIVE=/path/to/archive-prefix-native-build/storage_oracle \
RETAIL_POC_FIXTURE=/path/to/original-extracted-portable \
SYNTHETIC_NATIVE_DIR=/path/to/prior-synthetic-native \
python -B -m unittest discover -s tests -v
```

حذف ورودی‌های اختیاری می‌تواند skip ایجاد کند؛ عدد ۴۵۳/صفر skip مربوط به اجرای مستند با همهٔ ورودی‌ها است.

## مدارک و گام بعد

`AGENT-NAME-SEED-STATIC.json`، `PURE-FRAGMENT-BUILD-RECEIPT.json`، `EXPERIMENT-RESULTS.json`، `DERIVED-SEED-REAL-READBACK.json`، `TEST-RESULTS.json` و `ALL-TESTS.log` مرجع این checkpoint هستند. تمام ورودی‌های هویتی مثال‌های مصنوعی‌اند.

بازی، Lab، fixture اصلی، فایل‌های Release، صف/checkpoint دانلود و `.build.info` تغییر نکردند. upstream name/seed برای **حالت محدود ASCII** اکنون مدل و با توابع اصلی مقایسه شده است؛ اتصال به نصب زندهٔ کاربر همچنان انجام نشده. گام بعد می‌تواند تکمیل Unicode/API-error باشد یا تکمیل قرارداد publication/control در fixture جدا؛ هیچ‌کدام مجوز نوشتن در نصب واقعی نیست.
