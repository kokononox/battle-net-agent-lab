# نسخه 0.1 پژوهشی: CLI سرتاسری آفلاین برای یک جفت واقعی Retail

این برنامه یک vertical slice اجرایی است، نه اپدیتر کامل بازی و نه فایل اجرایی Windows. ورودی آن Portable-Retail-Sample تأییدشده است و فقط در workspace جدید خودش کار می‌کند. هیچ کشف نصب، اسکن بازی یا نوشتن روی Lab، `.build.info` یا نصب اصلی ندارد.

## چه کاری واقعاً انجام می‌دهد؟

`retail_sample_updater.py` پنج فرمان دارد:

1. `init`: کل manifest بسته، source/patch/target و Encoding ذخیره‌شده را با کد بازبینی‌شده کنترل می‌کند؛ سپس یک workspace تازه source-only می‌سازد. اسکریپت‌های داخل ZIP اجرا نمی‌شوند.
2. `plan`: برای همین رابطه پین‌شده PA، source و patch و target مورد نیاز را گزارش می‌کند. این **تشخیص نسخه بازی یا برنامه کامل یک build نیست**.
3. `update`: patch واقعی ذخیره‌شده را اعمال، target را دقیقاً re-encode و از مسیر gateهای bind/lookup/cache/span تأیید می‌کند؛ سپس journal و انتشار سفارشی Linux را پیش می‌برد. اگر قبلاً نیمه‌تمام باشد resume می‌کند.
4. `status`: وضعیت فعلی را دوباره با gateهای مستقیم و identityهای پین‌شده بررسی می‌کند؛ صرفاً خواندن یک flag ذخیره‌شده نیست.
5. `export`: فقط پس از committed شدن، target را از همان آرشیو زنده، با آدرس lookup و read اصلی، می‌خواند و decode می‌کند؛ فایل decoded جدید و مستقل با rename بدون overwrite منتشر می‌شود.

در تمام پاسخ‌های برنامه `installation_ready=false` است. ورودی از بسته محلی می‌آید؛ download شبکه‌ای در برنامه وجود ندارد. هیچ فایل واقعی بازی با خروجی export جایگزین نمی‌شود.

## نتیجه واقعی

خروجی decoded برابر 33940 بایت است:

- CKey: `3d42bf2e42127f313b0ec64cb440cde9`
- SHA-256: `3818ed3b407ad07a407fb104a65c03ab39f8a89e86937ea4e261e26b99c71bd9`
- EKey هدف encoded: `faedca88d0a0ab30dae5519239582d31`

target از patch بازسازی می‌شود؛ export فایل `target.decoded` موجود در Portable را کپی نمی‌کند. مسیر cache چهار خواندن را در یک child انجام می‌دهد؛ CreateFileW با dup descriptor زنده و فقط‌خواندنی تطبیق داده شده، نه اجرای واقعی Windows API.

## شکل workspace

- `SAMPLE-UPDATER-RESEARCH.json`: شناسه workspace و اتصال هش origin/tools به آن.
- `origin.json`: proof بسته و PA/Encoding در init، seed پژوهشی و هش manifest.
- `tools.json`: مسیر و SHA-256 چهار oracle محلی؛ فایل‌ها و receiptهایشان در هر فرمان کنترل می‌شوند.
- `LOCK`: قفل همکاری‌کننده سطح برنامه.
- `cycle/`: چرخه strict V8 با lock جدا و بدون marker اضافی reader.

مسیر oracleها در config محلی‌اند؛ جابه‌جایی این workspace به ماشین دیگر بدون آماده‌کردن oracleهای معتبر، یک بسته قابل اجرای خودکفا ایجاد نمی‌کند. markerها و receiptها امضای امنیتی علیه مهاجم نیستند.

## اجرا

Linux دارای Python، binutils و پشتیبانی اجرای ELF i386 لازم است. چهار oracle را طبق READMEهای پژوهشی از Agent 9824 پین‌شده بسازید. برای re-encode دقیق، runtime zlib آزمایش‌شده 1.2.11 بود؛ runtime ناسازگار ممکن است ایمن متوقف شود.

از ریشه `downloader/patch_audit_lab`، با مسیرهای فیزیکی بدون symlink و workspace موجودنباشد:

```bash
PYTHONPATH=. python -B retail_sample_updater.py init \
  --portable /absolute/Portable-Retail-Sample \
  --workspace /absolute/new-sample-workspace \
  --bind-oracle /absolute/bind-native/bind_contract_oracle \
  --lookup-oracle /absolute/lookup-native/lookup_merge_oracle \
  --span-oracle /absolute/span-native/span_reader_oracle \
  --direct-oracle /absolute/direct-native/archive_direct_oracle
PYTHONPATH=. python -B retail_sample_updater.py plan \
  --workspace /absolute/new-sample-workspace
PYTHONPATH=. python -B retail_sample_updater.py update \
  --workspace /absolute/new-sample-workspace
PYTHONPATH=. python -B retail_sample_updater.py status \
  --workspace /absolute/new-sample-workspace
PYTHONPATH=. python -B retail_sample_updater.py export \
  --workspace /absolute/new-sample-workspace \
  --out-new /absolute/new-target.decoded
```

تکرار `update` پس از commit، no-op بدون تغییر فایل است. `export` درون workspace یا Portable، روی فایل موجود یا روی symlink رد می‌شود. رقابت برای ساخت همان خروجی نیز overwrite نمی‌کند. خطای عادی export فایل موقت خودش را پاک می‌کند؛ crash سخت حین export ممکن است فایل موقت با نام مجزا باقی بگذارد، نه یک خروجی نهایی موفق.

ساخت workspace (`init`) transaction resumable نیست: marker سطح بالا آخر نوشته می‌شود و init ناقص fail-closed است؛ برای شروع مجدد باید مسیر جدید داد. تضمین‌های resume در این مرحله مربوط به `update` هستند، نه init یا قطع برق.

## تست‌ها

بازاجرای نهایی شامل 144 تست است: تمام 117 تست checkpoint direct دوباره اجرا شد و 27 تست جدید برنامه اضافه شد؛ failure/error/skip صفر. 814 تست تاریخی در این عدد نیست.

در تست‌های جدید:

- مسیر CLI واقعی plan → update → status → export → update-noop اجرا شد.
- هر 9 failpoint از طریق فرمان CLI update با خروج 91 متوقف شد؛ اجرای بعدی committed شد، export دقیق به دست آمد و تکرار بعدی no-op بود.
- checksum خروجی، منع overwrite و export داخل ورودی، symlink، قفل برنامه، config خراب، آرشیو خراب، failure native read و race روی انتشار فایل کنترل شد.
- template برنامه و فایل‌های Portable در پایان تست‌ها از نظر identity تغییر نکردند.

سازنده workspace از CLI نیز قبل از runner با Portable واقعی اجرا و تأیید شد. runner برای جلوگیری از اسکن اضافی Encoding از template آماده استفاده می‌کند؛ init دوباره به‌طور خودکار اجرا یا دانلود نمی‌شود.

```bash
PYTHONPATH=. python -B research/sample-updater-9824/run_experiments.py \
  --workspace-template /absolute/source-only-sample-workspace \
  --snapshot-cycle-template /absolute/source-only-owned-snapshot-cycle \
  --direct-cycle-template /absolute/source-only-owned-direct-cycle \
  --real-payload-fixture /absolute/real-insert-probe-fixture \
  --insert-oracle /absolute/old-insert-native/archive_insert_oracle \
  --out-new /absolute/new-app-evidence
```

## باقی‌مانده تا اپدیتر بازی

این مرحله فقط شروع اجرایی مرحله سرتاسری است. موارد زیر **انجام نشده‌اند**:

- تشخیص نسخه نصب‌شده، برنامه update برای کل build و انتخاب sourceهای واقعی از نصب کاربر.
- انتقال شبکه، resume/range/retry دانلود، و fallback بررسی‌شده از patch به full object.
- پوشش تعداد زیادی object/ESpec و ظرفیت‌های واقعی archive/index.
- publication/SEH/locking واقعی Windows، native reader کامل، آزمون Windows و بسته اجرایی .exe.
- تحمل قطع برق یا اعتبارسنجی بازی کامل.

ترتیب ادامه: برنامه‌ریزی و ورودی‌های واقعی build در محیط جدا → دریافت و fallback با هویت‌سنجی → مقیاس چند object → اجرای Windows و آزمون نصب جدا. تا آن زمان از این CLI روی نصب اصلی استفاده نشود.
