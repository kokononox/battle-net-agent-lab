# milestone عملی: patch واقعی Retail → data/index → بازخوانی native

> checkpoint تاریخی ۳۹۵تایی با placeholder؛ مرحلهٔ بعد در [archive-prefix-9824](../archive-prefix-9824/README-fa.md) prefix خروجی تازه را بازسازی و suite را به ۴۲۴ رسانده است. کد، receipt و نمونهٔ این checkpoint عمداً تغییر نکرده‌اند.

## نتیجهٔ اصلی

**نمونهٔ واقعی Retail دیگر فقط فایل decoded یا BLTE جداگانه نیست:** از source و patch اصلی بازسازی، با ESpec متادیتای هدف بازرمزگذاری، در یک span داخل `data.000` و index محلی آزمایشی ذخیره و سپس توسط خوانندهٔ native جداگانه با EKey و CKey کامل بازخوانی شد. تمام این کار در پوشهٔ کاملاً جدید پژوهشی انجام شد؛ نصب بازی، Lab و fixture اصلی تغییر نکردند.

این **updater آمادهٔ WoW یا نصب قابل‌اجرا نیست**. ۴۸۰ بایت ابتدایی archive فعلاً placeholder صریح پژوهشی است؛ `shmem` تولیدشده نیز کنترلِ ساختگی همان آزمایش است، نه activation نصب واقعی. هیچ `.build.info` یا اشاره‌گر `active.json` ساخته یا تغییر داده نشد. Agent.exe و بازی اجرا نشدند.

## سه پیشرفت به‌هم‌پیوسته

### ۱. اتصال آرایه‌های payload به تخصیص فضای data

مسیر `0x7229e3`، آرایهٔ A در `payload+0x20` را برای اولین طول کافی جست‌وجو و نشانی متناظر را از آرایهٔ B در `+0x156a` می‌خواند. در مسیر مصرف عادی، طول را به اندازهٔ درخواست کم و نشانی را همان اندازه زیاد می‌کند؛ update از مسیر ذخیره/rollback مرحلهٔ قبل می‌رود. ترتیب انتخاب **اولین رکورد مناسب در ترتیب موجود** است، نه انتخاب خودکار بزرگ‌ترین حفره.

- بدون رکورد مناسب، کد `14` مشاهده شد؛ درخواست صفر در state مناسب خروجی صفر می‌دهد.
- اگر نشانی روی مرز `1<<30` و طول دست‌کم `0x1e0=480` باشد، مسیر بررسی‌شده کد `16` می‌دهد، نه مصرف عادی.
- caller در `0x71004c/0x710067/0x71007c` این کد را به ایجاد/آماده‌سازی archive و تلاش دوباره وصل می‌کند.
- `0x722b05` بازهٔ `archive*(1<<30) .. +480` را رزرو و باقی‌مانده را از انتهای این prefix نگه می‌دارد.

[agent_allocator_model.py](../../agent_allocator_model.py) فقط مدل محدود **در حافظه** است. محدودیت‌های اضافهٔ اندازه، عدم هم‌پوشانی، عدم عبور از segment و ظرفیت، سیاست محافظه‌کارانهٔ fixture هستند، نه ادعای اینکه خود Agent همین خطاها را رد می‌کند. این مدل allocator کامل یا ابزار آزادسازی/rebuild عمومی نیست.

### ۲. بستن شکاف نسخهٔ checksum پیش‌هدر

پیش‌تر checksum-B فقط از دستورالعمل جامعه برای نسخهٔ قدیمی استفاده می‌شد. اکنون writer `0x713b90`، reader/checker `0x713c27/0x713c8c` و constructor `0x713d2a` در **خود Agent 2.41.1.9824 ثابت** ردیابی شدند:

- EKey به ترتیب معکوس در ۱۶ بایت اول؛ اندازهٔ span به صورت little-endian در +16.
- variant تولیدشده در PoC: دو بایت flag صفر در +20/+21؛ پشتیبانی عمومی همهٔ variantها ادعا نمی‌شود.
- hash روی ۲۲ بایت اول با seed `0x3d6be971`، خروجی little-endian در +22.
- checksum-B روی ۲۶ بایت قبلی با alignment نشانی و جدول ۱۶تایی در `0x9bd650`؛ هر ۱۶ DWORD با جدول کد ما برابر بود. checker خود Agent از fold همهٔ ۳۰ بایت و مقایسه با offset+30 استفاده می‌کند.
- caller ساخت header نیز در `0x712de5` بررسی شد.

۲۵ anchor، ۱۲ call، ۶ branch و جدول ۶۴بایتی روی PE با SHA256 ثابت زیر تطبیق یافتند:
`b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5`.

[رسید استاتیک](AGENT-STORAGE-STATIC.json)، [حدود و hash قطعات disassembly](DISASSEMBLY-MANIFEST.json). این تطبیق استاتیک است، نه اجرای واقعی تابع‌های Agent یا اثبات تمام قرارداد writer. سازگاری index v7 جداگانه با CascLib آزمایش شد؛ مشخصات کامل نویسندهٔ index خود Agent از این نتیجه استنتاج نشده است.

### ۳. ذخیره‌سازی و بازخوانی مستقل نمونهٔ واقعی

زنجیرهٔ اصلی:

```text
source.blte + sample.zbsdiff
→ decoded هدف 33,940 بایتی
→ ESpec رسمی b:{256K*=z}
→ encoded هدف 158 بایتی
→ span با پیش‌هدر 30 بایتی: 188 بایت
→ data.000: offset=480، کل فایل=668 بایت
→ index v7 تک‌ورودی: 58 بایت
→ بازخوانی native → EKey و CKey کامل هدف
```

- CKey هدف: `3d42bf2e42127f313b0ec64cb440cde9`
- EKey هدف: `faedca88d0a0ab30dae5519239582d31`
- SHA256 encoded: `73bb9f2ec6c3dba2dbe61d5aa7e5bd4560f0d96c53972adb7472894d4f69b364`
- پس از رزرو prefix و مصرف span، مدل فضای آزاد یک رکورد با نشانی `668` و طول `(1<<30)-668` داشت؛ این **ظرفیت مفهومی مدل** است، نه فایل ۱GiB واقعاً تخصیص‌یافته.
- manifest اصلی fixture و فایل Encoding ثابت بررسی شدند؛ کد از fixture import نشد. هویت فایل‌های اصلی در طول ساخت خروجی کنترل شد. نه اسکن نصب، نه دانلود مجدد و نه دست‌کاری manifest لازم شد.

[REAL-RETAIL-READBACK.json](REAL-RETAIL-READBACK.json) رسید زنجیرهٔ source/patch/Encoding، هویت هدف و پذیرش native را نگه می‌دارد. فایل‌های باینری تولیدشده عمداً در commit نیستند؛ از همان fixture اصلی Release بازتولید می‌شوند.

## استقلال خواننده دقیقاً تا کجاست؟

خوانندهٔ C++ هیچ helper پایتونی را import یا اجرا نمی‌کند. از source ثابت CascLib در commit `38a34665624b8775bb875274b36191b21c38d97b` این توابع را واقعاً فراخوانی می‌کند:

- `CaptureIndexHeader_V2`
- `CaptureGuardedBlock2`
- `ParseBlteHeader`

سپس harness خودمان checksumهای سخت‌گیرانهٔ span، EKey کامل، MD5 chunk، مرزهای decoding و CKey decoded را بررسی می‌کند. **CascLib در این مسیر release، checksumهای span را سخت‌گیرانه بررسی نمی‌کند؛ آن بخش را نباید به CascLib نسبت داد.** `CascOpenStorage` یا اجرای کامل کلاینت انجام نشده است. Python و native هر دو از zlib استفاده می‌کنند؛ این دو موتور فشرده‌سازی مستقل محسوب نمی‌شوند. [رسید build و hash منبع/باینری](NATIVE-BUILD-RECEIPT.json).

## آزمون موفق کافی نبود؛ موارد منفی هم آزمایش شدند

**۳۹۵ آزمون، صفر failure/error/skip**؛ ۳۵ test method تازه نسبت به مرحلهٔ ۳۶۰تایی. شمار بردارهای داخل loop را متد آزمون جداگانه حساب نکرده‌ایم. [رسید تست و hash کد](TEST-RESULTS.json)، [لاگ کامل](ALL-TESTS.log).

[رسید آزمایش جداگانه از unittest](EXPERIMENT-RESULTS.json):

- **۶۴ بردار مثبت native:** تمام ۱۶ alignment نشانی برای archiveهای ۰، ۳، ۴ و ۱۰۲۳؛ شامل نشانی‌های بالاتر از ۳۲ بیت.
- **۱۱ مورد منفی ردشده:** EKey کامل، size، hash-A، checksum-B، امضای BLTE، داده/tail chunk، truncation، checksum index، EKey اشتباه با prefix یکسان و CKey اشتباه.
- **۴ نقطهٔ خروج ناگهانی subprocess:** پس از data، index، control و receipt. سه مورد اول به‌عنوان fixture ناقص رد شدند؛ پس از receipt، fixture کامل بود و native آن را خواند. فایل‌های ناقص حفظ شدند و overwrite خودکار رد شد. این **آزمون قطع سازندهٔ fixture** است، نه crash recovery یا activation واقعی بازی؛ قطع وسط write یا هنگام قطع برق پوشش داده نشده است.
- **۶ snapshot حافظه‌ای update/rollback:** قبل و بعد از ذخیرهٔ مقادیر، state=2، نوشتن A/B و state=1. قبل از commit آرایهٔ قدیمی حفظ/بازگردانده شد و بعد از commit آرایهٔ جدید باقی ماند؛ recovery تکراری پایدار بود. این شبیه‌سازی حافظه‌ای است، نه اجرای Agent یا آزمون shared-memory سیستم‌عامل.

## بازتولید برای توسعه‌دهنده

از کد فعلی شاخه و **fixture اصلی دست‌نخورده** استفاده کنید؛ companion ZIP قدیمی Release ماژول‌های تازه را ندارد. source ثابت CascLib باید قبلاً در دسترس باشد. build script شبکه، clone و تغییر tracked source ندارد؛ compiler، OpenSSL و zlib development headers لازم‌اند.

از ریشهٔ `downloader/patch_audit_lab`:

```bash
mkdir -p /PATH/TO/NEW_NATIVE_BUILD_DIR
sh research/retail-storage-poc/native/build.sh /PATH/TO/PINNED_CASCLIB /PATH/TO/NEW_NATIVE_BUILD_DIR
python -B retail_storage_poc.py --fixture /PATH/TO/ORIGINAL_FIXTURE --out-new /PATH/TO/NEW_RESEARCH_FOLDER --native-oracle /PATH/TO/NEW_NATIVE_BUILD_DIR/storage_oracle
python -B retail_storage_poc.py --verify /PATH/TO/NEW_RESEARCH_FOLDER --native-oracle /PATH/TO/NEW_NATIVE_BUILD_DIR/storage_oracle
python -B research/retail-storage-poc/run_experiments.py --fixture /PATH/TO/ORIGINAL_FIXTURE --native-oracle /PATH/TO/NEW_NATIVE_BUILD_DIR/storage_oracle --report-new /PATH/TO/NEW_REPORT_FOLDER
```

خروجی باید مسیر کاملاً جدید باشد؛ پوشهٔ موجود، مسیر داخل fixture و مسیرهای شناخته‌شدهٔ نصب رد می‌شوند. این حفاظت برای پژوهش و ابزارهای همکار است، نه sandbox امنیتی کامل مقابل تغییر هم‌زمان مسیرها توسط پردازش متخاصم. ابزار را روی نصب زنده اجرا نکنید.

برای suite کامل، oracleهای مرحلهٔ قبلی نیز لازم‌اند:

```bash
SYNTHETIC_NATIVE_DIR=/PATH/TO/PREVIOUS_NATIVE_ORACLES RETAIL_POC_FIXTURE=/PATH/TO/ORIGINAL_FIXTURE RETAIL_POC_NATIVE=/PATH/TO/NEW_NATIVE_BUILD_DIR/storage_oracle python -B -m unittest discover -s tests -v
python -B agent_storage_paths_audit.py --agent /PATH/TO/PINNED_AGENT
```

نبود fixture/native باعث skip آزمون‌های مخصوص آن‌ها می‌شود؛ در اجرای گزارش‌شده همه حاضر بودند و skip صفر بود. مسیر CLI خصوصی `--test-exit-after` فقط برای subprocess آزمایش است و عمداً پردازش را با کد ۹۱ متوقف می‌کند؛ اجرای عادی به آن نیاز ندارد.

## چه چیز هنوز آماده نیست؟

۱. محتوای واقعی prefix رزروشدهٔ archive و رکوردهای مرتبط آن؛ placeholder نباید وارد نصب واقعی شود.
۲. قرارداد کامل نوشتن/انتشار index و activation واقعی و نام/قفل نصب روی Windows؛ generated shmem این‌ها را ثابت نمی‌کند.
۳. writer `.build.info`، closure کامل build هدف و همهٔ patch/BLTE/encryption variantها.
۴. آزمایش Windows، قطع برق و دوام دیسک؛ fsync/rename یا خروج subprocess جانشین آن‌ها نیست.

نتیجهٔ اساسی این مرحله، **اثبات عملی یک شیء واقعی تا ذخیره‌سازی و بازخوانی کنترل‌شده** است؛ نه وعدهٔ ساخت updater کامل در تعداد گام نامعلوم. قدم بعدی باید prefix/رکوردهای رزروشده و publication واقعی را ببندد، نه اینکه همین نمونه دوباره اسکن یا دانلود شود.
