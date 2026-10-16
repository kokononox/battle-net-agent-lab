# prefix آرشیو Agent 9824: از placeholder به ۱۶ رکورد قابل بازخوانی

## نتیجهٔ جدید

نمونهٔ واقعی Retail در **پوشهٔ جدید پژوهشی** با prefix بازسازی‌شده ذخیره و بازخوانی شد: ۱۶ هدر ۳۰بایتی، ۱۶ رکورد رزروشده و یک رکورد واقعی در ۱۶ فایل index v7؛ اندازهٔ `data.000` همچنان ۶۶۸ بایت است. هدرهای ویژه BLTE ندارند و طول خودشان ۳۰ است. span واقعی از offset=480 شروع می‌شود: ۱۸۸ بایت شامل encoded ۱۵۸بایتی.

- EKey واقعی: `faedca88d0a0ab30dae5519239582d31`
- CKey واقعی decoded: `3d42bf2e42127f313b0ec64cb440cde9`
- SHA256 encoded: `73bb9f2ec6c3dba2dbe61d5aa7e5bd4560f0d96c53972adb7472894d4f69b364`
- **۴۲۴ آزمون موفق، صفر failure/error/skip**؛ ۲۹ روش آزمون جدید نسبت به checkpoint ۳۹۵تایی.
- آزمایش جدا: ۱۶ seed مثبت، هرکدام با دو خوانندهٔ native؛ **۵۰۲ ورودی منفی رد شدند**: ۴۸۰ flip تک‌بایتی prefix، ۱۶ خرابی index و ۶ خطای معنایی/هویت.
- نمونهٔ baseline قبلی، fixture اصلی، Lab، نصب بازی، صف و checkpointهای دانلود تغییر نکردند. فایل‌های Release تعویض نشدند. فایل دادهٔ تولیدشده یا Agent.exe داخل Git منتشر نمی‌شود.

## مرز شواهد — updater آماده نیست

**seed شانزده‌بایتی ورودی صریح پژوهشی است، نه هویت استخراج‌شده از نصب واقعی Windows.** مولد کلیدها نسبت به این seed بازسازی شده؛ اتصال upstream مسیر/نام نصب به seed هنوز port و تأیید نشده است. capacity ورودی نیز در آزمایش ۱۰۲۴ انتخاب شده، نه اینکه ظرفیت نصب کاربر کشف شده باشد. موفقیت این نمونه به معنی پذیرش توسط Agent نیست.

هیچ Agent یا بازی اجرا نشد؛ `CascOpenStorage` هم اجرا نشده است. توابع واقعی CascLib برای capture ایندکس و parse هدر BLTE به کار رفته‌اند؛ کنترل سختگیرانهٔ checksumهای span و هدرهای ویژه، سیاست مستقل harness ما است و نباید به CascLib نسبت داده شود. BLTE بازخوانی native از zlib استفاده می‌کند؛ این استقلال پیاده‌سازی کنترل‌ها است، نه استقلال الگوریتم codec.

generated shmem فقط کنترل همان fixture است، نه activation واقعی. هیچ `.build.info` یا `active.json` نوشته نشد. هنوز closure کل پروفایل/نصب، اتصال Windows، publication/دوام و recovery واقعی Agent، و writer نهایی نصب اثبات نشده‌اند.

## شواهد استاتیک دقیق

باینری ثابت Agent `2.41.1.9824`، SHA256:
`b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5`؛ فقط خوانده و disassemble شد.

- callback صحیح نویسنده **`0x7014aa`** است. `0x701453` تابع گزارش خطا است، نه نویسنده؛ نشانی میانی را نباید از روی یک call نام‌گذاری کرد.
- init در `0x70112d` همین callback را می‌دهد؛ `0x711477` آن را در شیء `+0x38` ذخیره می‌کند و `0x711b88` با context، شمارهٔ archive و آرایهٔ full keyها فراخوانی می‌کند. این شیء با callback کلاس دیگری در `0x71cae3` یکی فرض نشده است.
- نویسنده: archive×1GiB، slot×30، flag=1، size=30؛ call سازندهٔ هدر `0x713d2a` در `0x70152f`؛ ۱۶ دور؛ write ۴۸۰بایتی در `0x701571`.
- مولد `0x712a6d`: seed شانزده‌بایتی را برای هر slot کپی می‌کند؛ byte1 شمارهٔ archive پایین است. فقط اگر capacity>256 باشد byte2 با شمارهٔ archive بالا جایگزین می‌شود؛ در capacity≤256، byte2 seed حفظ می‌شود. byte0 از صفر تا اولین bucket مناسب جست‌وجو می‌شود. ۷ بایت suffix از seed باقی می‌مانند؛ صفر فرض نشده‌اند.
- bucket در `0x712b9f`: XOR نخستین ۹ بایت، fold دو nibble، افزودن mode و mask15. **کلید رزروشده mode=1 دارد**؛ bucket آن `(ordinary_bucket+1)&15` است، نه bucket عادی. ثبت `0x71252a` هر slot را در همان شمارهٔ slot وارد می‌کند. این تفاوت با index ساز معمول BLTE یکسان‌سازی نشده است.
- helper `0x710b6a` full keyهای ۱۶بایتی را به prefixهای ۹بایتی برای index تبدیل می‌کند. reader `0x713c8c` flag صفر یا یک را قبول می‌کند.
- ۲۵ byte anchor و ۹ call در گزارش جدید، علاوه بر verifierهای پیشین، با SHA ثابت بررسی شدند. این شمارش، اثبات مسیرهای اجرا‌نشده یا همهٔ branchها نیست.

## بازتولید آفلاین

از ریشهٔ `downloader/patch_audit_lab`؛ منبع محلی و پاک CascLib باید روی commit زیر باشد:
`38a34665624b8775bb875274b36191b21c38d97b`.

```sh
mkdir ./NEW-NATIVE
sh research/archive-prefix-9824/native/build.sh /path/to/CascLib ./NEW-NATIVE
PYTHONPATH=. python -B research/archive-prefix-9824/run_experiments.py \
  --fixture /path/to/extracted-original-portable \
  --native-dir ./NEW-NATIVE \
  --agent /path/to/pinned/Agent.9824.exe \
  --report-new ./NEW-PREFIX-EXPERIMENT
```

این runner شبکه ندارد. fixture اولیه با manifest و metadata کامل قبلی دوباره خوانده می‌شود؛ اسکن payloadهای نصب یا دانلود تازه نیست. `baseline` تاریخی و `prefix-fixture` جدید در output پژوهشی ساخته می‌شوند. خروجی موجود و مسیرهای game-like رد می‌شوند. برای آزمون‌های کامل سه native مسیر لازم است:

```sh
SYNTHETIC_NATIVE_DIR=/path/to/prior-synthetic-native \
RETAIL_POC_FIXTURE=/path/to/extracted-original-portable \
RETAIL_POC_NATIVE=./NEW-NATIVE/storage_oracle \
PREFIX_NATIVE_DIR=./NEW-NATIVE \
python -B -m unittest discover -s tests -v
```

نبود ورودی‌های اختیاری باعث skip می‌شود؛ ادعای ۴۲۴/صفر skip فقط مربوط به اجرای ثبت‌شده با همهٔ ورودی‌ها است. ساخت native به compiler، OpenSSL و zlib نصب‌شده نیاز دارد؛ build script چیزی دریافت نمی‌کند.

## مدارک

- `AGENT-PREFIX-STATIC.json` و `asm/`: byte/call و قطعه‌های محدود disassembly.
- `REAL-PREFIX-READBACK.json`: نتیجهٔ prefix و فایل واقعی؛ seed و عدم اثبات نصب آشکارند.
- `BASELINE-REAL-READBACK.json`: زنجیرهٔ source → patch → metadata/ESpec → target، حفظ‌شده با placeholder تاریخی.
- `EXPERIMENT-RESULTS.json`: بردارهای مثبت و خطاهای ردشده؛ در پایان fixture به حالت درست بازگردانده و verify شد.
- `TEST-RESULTS.json`، `ALL-TESTS.log` و `NATIVE-BUILD-RECEIPT.json`: suite، hash کد و منبع native.

checkpoint قبلی [retail-storage-poc](../retail-storage-poc/README-fa.md) عمداً با داده و ادعای تاریخی placeholder باقی می‌ماند؛ خروجی قبلی به‌صورت پنهانی اصلاح نشده است.

## گام بعد

مسیر seed از نام/مسیر canonical نصب را با شواهد upstream کامل کنیم و برای حالت‌های مسیر Windows آزمون مستقل بسازیم؛ سپس قرارداد index/control publication و closure پروفایل را به نصب جدا و قابل‌بازگشت متصل کنیم. تا آن زمان writer نصب واقعی و تغییر build.info ممنوع می‌مانند.
