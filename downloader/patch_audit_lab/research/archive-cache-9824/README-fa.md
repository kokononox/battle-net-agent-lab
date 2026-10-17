# مدیر اصلی بازکردن/cache آرشیو و مسیر CreateFile — Agent 9824

## نتیجه و مرز ادعا

این مرحله جایگزین کامل open-manager مرحلهٔ قبلی را حذف کرد: **۲۳ تابع دست‌نخوردهٔ اصلی، ۲۴۲۳ بایت کد**، شامل مسیر خواندن قبلی، مدیر `0x71d1f3`، hash و زنجیرهٔ cache، مقایسهٔ کلید، retain، جابه‌جایی فهرست، release و مسیرهای اصلی بازکردن فایل تا `CreateFileW` اجرا شدند. Agent پین‌شده همان SHA256 زیر است:

`b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5`

**این اجرای کامل Agent یا Windows نیست.** مرز باقی‌مانده اکنون constructor `0x72d89d` است: allocation/درج cache اصلی هنوز adapter است؛ adapter به‌طور صریح مسیر اصلی `0x72dd0a` و `0x864f87` را برای بازکردن فراخوانی می‌کند، object کوچک پژوهشی می‌سازد و reference متعلق به driver را نگه می‌دارد. cache-hitها از دو object پیش‌کاشته و یک hash bucket استفاده می‌کنند. cache miss باعث درج واقعی در cache نمی‌شود و reuse ناشی از یک miss قبلی اثبات نشده است.

`CreateFileW` به Linux `openat(O_RDONLY|O_NOFOLLOW|O_CLOEXEC)` و `ReadFile` به `pread64` واقعی تطبیق داده شده‌اند. formatter، تبدیل ASCII/UTF-16، frame عادی، cookie check و lock/unlock تک‌ریسمانی adapter هستند؛ BLTE/CKey مستقل Python است. این‌ها قفل ویندوز، SEH، مدیریت حافظه/ظرفیت، eviction، destructor، رفتار چندریسمانی یا protocol نصب کامل را اثبات نمی‌کنند. receipt محلی صرفاً کنترل یکپارچگی است، نه امضای دیجیتال.

## یافته‌های جدید

### cache hit واقعاً مسیر بازکردن دیسک را دور می‌زند

مدیر اصلی و `0x72db39` کلید archive-64bit و یک variant byte را به lookup می‌دهند. `0x72d843`/`0x68165e` hash اصلی، `0x72d655`/`0x72d6b4` جست‌وجوی زنجیره و `0x72d81c` تطبیق دقیق را اجرا می‌کنند. high DWORD در hash شرکت ندارد ولی **در برابری کلید کنترل می‌شود**؛ برابر بودن hash به معنی hit نیست. variant byte با open-mode یکی نیست؛ top-level reader در این پروفایل variant=0 می‌دهد.

- archive نادرست، high DWORD نادرست یا variant نادرست به miss می‌رسند.
- fixture برخورد، entry اولِ نامنطبق را رد می‌کند و entry دومِ دقیق را انتخاب می‌کند.
- فایل cache اول با بایت `A`، فایل دوم با `B` و فایل دیسک با الگوی مستقل ساخته شدند؛ بایت‌های واقعاً برگشتی انتخاب فایل را تأیید کردند، نه فقط trace درایور.
- hit باعث formatter، constructor یا CreateFile نمی‌شود و open-error تزریقی در مرز API را لمس نمی‌کند.
- hit دوم، با `0x72dbcb` و `0x687fb0` به ابتدای فهرست منتقل می‌شود؛ این یک فهرست کوچک معتبر است، نه اثبات همهٔ سیاست‌های LRU/capacity محصول.

### reference اکنون اصلی است

`0x681aec` شمارندهٔ object کش‌شده را از ۱ به ۲ می‌برد. در مرز ReadFile، ۲ مشاهده می‌شود؛ `0x67b495` و `0x67a5ee` آن را پس از خواندن موفق **یا خطای خواندن** به ۱ برمی‌گردانند. destructor عمداً خارج از محدوده است و vtable fixture به trap متصل است. object تازهٔ constructor adapter از ابتدا دو reference دارد (یکی متعلق به driver)، تا release اصلی فقط reference موقت caller را بردارد؛ این جای allocation/cache ownership اصلی را نمی‌گیرد.

### آرگومان‌های واقعی بازکردن و منع دسترسی نوشتن

مسیر اصلی `0x72dd0a`/`0x864f87` تا آرگومان‌های `CreateFileW` اجرا شد:

| حالت کنترل‌شده | desired access | disposition | share | نتیجه در adapter |
| --- | --- | --- | --- | --- |
| open-mode=4، fast=0 | `0x80000000` | `3` | `7` | openat فقط‌خواندنی واقعی |
| open-mode=4، fast=1 | `0x80000000` | `3` | `1` | شاخهٔ اصلی fast؛ openat فقط‌خواندنی |
| open-mode=1، cache miss | `0xc0000000` | `4` | `7` | رد با ۵؛ هیچ open/create انجام نمی‌شود |

حالت آخر درخواست read/write و OPEN_ALWAYS اصلی را دارد. **آن را پنهانی به read-only تبدیل نکردیم**؛ API adapter پیش از syscall رد می‌کند. فایل غایب در حالت فقط‌خواندنی نیز ساخته نمی‌شود. از این نتیجه مجوز اجرای modeهای نوشتن روی نصب اصلی حاصل نمی‌شود؛ معنی این جدول فقط همین پروفایل و مسیر اجراست.

خطای open تزریقی یا خطای فایل غایب از constructor adapter عبور می‌کند؛ نگاشت خطاهای کامل constructor اصلی `0x72d89d` هنوز اجرا نشده است. در مقابل، تبدیل خطای ReadFile=5 به status=8 در reader همچنان توسط توابع اصلی انجام می‌شود.

### guard و قفل

بازگشت مقدار ۷۸۰ از formatter adapter عمداً تزریق شد: guard اصلی مدیر، پیش از constructor با خطای ۱۰ برمی‌گردد و unlock انجام می‌شود. این **تزریق مقدار بازگشتی formatter** است، نه آزمایش واقعی یک مسیر ۷۸۰ کاراکتری یا اثبات formatter اصلی. در مسیر hit، miss، خطای open و guard، فراخوانی‌های lock/unlock adapter متوازن بودند؛ هم‌زمانی یا قفل سیستم‌عامل اثبات نشده است.

## شواهد

- **۱۵۴۱ بردار native/model مطابق**: ۴۶۷ status موفق، ۱۰۷۴ رد؛ ۵۲۱ cache hit همراه خواندن، ۴۰۶ فراخوانی مرز CreateFile، ۱۹۷ منع درخواست write/create و ۲۷۹ guard formatter. این counters هم‌پوشان‌اند؛ مثلاً cache hit می‌تواند خطای خواندن داشته باشد.
- **۳۲ بازخوانی source/target واقعی**: دو object در چهار fixture آرشیو ۰، ۳، ۴ و ۱۰۲۲؛ برای هر کدام miss خالی، hit، miss بر اثر high DWORD و collision-hit اجرا شد. lookup اصلی V8 → manager/cache/read اصلی → parser/getter اصلی قبلی → BLTE/CKey مستقل Python. هر object پس از decode، ۳۳۹۴۰ بایت.
- fixtureها ۸۵۶ بایت با prefix صفرند، نه storage چندآرشیوی کامل. CKey source مشتق‌شده است؛ target CKey `3d42bf2e42127f313b0ec64cb440cde9` از Encoding مستقل است.
- `retail_cache_cycle.py` گیت bind/lookup را نگه می‌دارد و manager/open/read/count/header/decode را پیش/پس انتشار و در no-op الزام می‌کند؛ mode پژوهشی برای miss همان open-mode=4 فقط‌خواندنی است.
- **۹ توقف سخت exit=91، resume و no-op بدون نوشتن موفق**؛ source/prefix و همهٔ indexهای اولیه حفظ شدند. خطای خواندن تزریقی که توسط reader اصلی به ۸ تبدیل شد، و خرابی هدر در مرز parser، هر دو control قدیمی و journal prepared را نگه داشتند؛ پس از حذف تزریق recovery موفق بود. فایل واقعی برای این دو تزریق خراب نشد.
- **۸۱۴ آزمون، صفر failure/error/skip؛ ۶۱ آزمون تازه**. full suite همهٔ وابستگی‌های native و fixture تاریخی را داشت.

گزارش‌های قابل‌بازتولید: `FRAGMENT-BUILD-RECEIPT.json`، `EXPERIMENT-RESULTS.json`، `CYCLE-EXPERIMENT.json`، `TEST-RESULTS.json` و `ALL-TESTS.log`. assemblyها فقط متن‌اند؛ Agent/ELF/فایل archive باینری منتشر نشده است.

## بازتولید

از package root در Linux با binutils و قابلیت اجرای ELF i386؛ Agent پین‌شده و خروجی تازه خارج از نصب بازی:

```bash
export PYTHONPATH=.
python -B research/archive-cache-9824/native/build.py \
  --agent "$PINNED_AGENT" --out-new "$WORK/native"
export ARCHIVE_CACHE_ORACLE="$WORK/native/archive_cache_oracle"
python -B research/archive-cache-9824/run_experiments.py \
  --cache-oracle "$ARCHIVE_CACHE_ORACLE" --span-oracle "$SPAN_READER_ORACLE" \
  --lookup-oracle "$LOOKUP_MERGE_ORACLE" \
  --prior-owned-store "$SPAN_PRIOR_STORE" --out-new "$WORK/matrix"
python -B research/archive-cache-9824/run_cycle_experiments.py \
  --cache-oracle "$ARCHIVE_CACHE_ORACLE" --span-oracle "$SPAN_READER_ORACLE" \
  --lookup-oracle "$LOOKUP_MERGE_ORACLE" --bind-oracle "$BIND_CONTRACT_ORACLE" \
  --prior-owned-cycle "$V8_PRIOR_CYCLE" --out-new "$WORK/cycle"
python -B -m unittest discover -s tests -v
```

برای full suite بدون skip، متغیرهای native همهٔ checkpointهای قبلی، از جمله `ARCHIVE_IO_ORACLE` هم لازم‌اند. API خواندن سخت‌گیر همان محدودیت قبلی را دارد: archive<1023، offset>=480، span>30 و <=4096 و عدم عبور از segment. کشف خودکار نصب، اسکن archive، شبکه، تغییر fixture اصلی و نوشتن بازی وجود ندارد. بستهٔ کامل Windows Agent اجرا نشده است.

## باقی‌ماندهٔ مرحلهٔ اول

۱. حذف adapter constructor: allocation، درج واقعی hash/cache، ownership و capacity/eviction؛ آن‌وقت reuse پس از miss را واقعاً می‌توان آزمود.
۲. اتصال caller سطح بالای object-read و مسیر mapping/refresh به همین زنجیره؛ alignment غیرتهی و SEH جداگانه باید محدود و آزموده شوند.
۳. سپس طبق ترتیب توافق‌شده Windows writer/locking/publication/recovery روی کپی مجزا، full-build/multiarchive/rollover، و در پایان installation binding/`.build.info`/activation/launch روی کپی.

publication فعلی همچنان Linux سفارشی است، نه protocol ویندوز و نه proof قطع برق. بازی، Lab، Portable اصلی و Release تاریخی دست‌نخورده‌اند. **مرحلهٔ اول هنوز کامل و نصب اصلی آمادهٔ نوشتن نیست.**
