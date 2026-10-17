# اتصال درج کش اصلی به نمونه واقعی Retail

این checkpoint آزمون constructor/درج جدول/استفاده مجدد کش را از داده مصنوعی به جفت واقعی source/target موجود در Portable-Retail-Sample منتقل می‌کند. محصول قابل نصب یا updater کامل نیست.

## ورودی تأییدشده

- فایل خصوصی انتشار `retail-research-2026101`: `Portable-Retail-Sample.zip`، اندازه 169779901 بایت.
- SHA-256: `9bd063f6dc6b8304df1fd939d24c01389abc0d4ff78f8c68463e4e0b2610bc0b`.
- 19 عضو ZIP؛ کنترل مسیر، عضو تکراری، symlink و سقف اندازه پیش از استخراج انجام شد.
- هیچ اسکریپت داخل ZIP اجرا نشد؛ اعتبارسنجی با ماژول‌های بازیابی‌شده مخزن انجام شد.
- manifest، ارتباط PA، کل هش Encoding ذخیره‌شده، صفحات منتخب، source و patch و target تأیید شدند.
- target با ESpec `b:{256K*=z}` دقیقاً EKey `faedca88d0a0ab30dae5519239582d31` و CKey `3d42bf2e42127f313b0ec64cb440cde9` را بازتولید کرد. zlib runtime برابر 1.2.11 بود.
- CKey منبع همچنان مشتق‌شده از decode است، نه یک مدرک مستقل دیگر.

## آزمایش

`retail_insert_probe.prepare` دو فایل جدید مستقل `data.000` و `data.001` می‌سازد. هر فایل 856 بایت و شامل prefix پژوهشی 480 بایتی، span منبع در offset=480 و span هدف در offset=668 است. هر span برابر 188 بایت است: هدر 30 بایتی و payload واقعی 158 بایتی. seed صریح پژوهشی است، نه هویت Windows کاربر. هدرها/چیدمان را fixture می‌سازد؛ payloadها واقعی‌اند.

فقط این پوشه جدید marker آزمون درج کش را می‌گیرد. ZIP، نمونه استخراج‌شده، بازی، Lab و `.build.info` نوشته نمی‌شوند. هیچ marker اضافی در چرخه‌های strict V8 قرار داده نمی‌شود.

هر case یک پردازش oracle و چهار خواندن در همان پردازش دارد:

| case | ترتیب خواندن | تعداد تجمعی open / constructor |
| --- | --- | --- |
| یک آرشیو | source0, target0, source0, target0 | 1, 1, 1, 1 |
| دو آرشیو | source0, source1, target0, target1 | 1, 2, 2, 2 |

- بایت‌های واقعی با خواندن مستقل فایل مقایسه شدند.
- پارسر اصلی Agent و getterهای اصلی آدرس، هدرهای همین بایت‌های خوانده‌شده را تأیید کردند.
- EKey، CKey، اندازه، SHA-256 payload و BLTE roundtrip با Python مستقل کنترل شدند.
- reference هنگام read برابر 2 و پس از read برابر 1 بود.
- hash فایل‌های آرشیو پیش و پس از probe یکسان بود.

## نتیجه تست

49 تست، بدون failure/error/skip: 31 تست قبلی درج مصنوعی دوباره اجرا شدند و 18 تست جدید payload واقعی اضافه شدند. تست‌های جدید فساد header/source/target، جابه‌جایی source و target، truncation، status=0 همراه EOF، خطاهای open/read، write mode، marker و آدرس غلط را پوشش می‌دهند. خطای open تزریق‌شده در دومین open برای cache hit فراخوانی نشد.

این عدد با 814 تست تاریخی جمع نشده است. ماتریس مصنوعی 1024-case checkpoint قبلی و مجموعه انتشار/بازیابی در این checkpoint دوباره اجرا نشده‌اند.

## بازتولید

از مسیر فیزیکی بدون symlink استفاده شود؛ در محیط فعلی `/data` یک symlink است. مسیرها را به محیط محلی خود تطبیق دهید. خروجی‌ها باید تازه و موجودنباشند.

```bash
cd downloader/patch_audit_lab
export PYTHONPATH=.
python -B research/archive-insert-9824/native/build.py \
  --agent /absolute/Agent.9824.exe --out-new /absolute/new-insert-native
python -B research/archive-span-reader-9824/native/build.py \
  --agent /absolute/Agent.9824.exe --out-new /absolute/new-span-native
python -B retail_insert_probe.py \
  --portable /absolute/Portable-Retail-Sample \
  --out-new /absolute/new-real-fixture \
  --insert-oracle /absolute/new-insert-native/archive_insert_oracle \
  --span-oracle /absolute/new-span-native/span_reader_oracle
export ARCHIVE_INSERT_ORACLE=/absolute/new-insert-native/archive_insert_oracle
export SPAN_ORACLE=/absolute/new-span-native/span_reader_oracle
export RETAIL_INSERT_FIXTURE=/absolute/new-real-fixture
python -B -m unittest discover -s tests -p 'test_*insert*.py' -v
```

## مرز اثبات و مرحله بعد

- این probe آدرس‌های source/target را صریح می‌دهد؛ آدرس از native index lookup دریافت نشده است.
- به gate چرخه V8/انتشار متصل نشده و هیچ ادعای جدیدی درباره recovery یا crash consistency ندارد.
- کد اصلی درج/کش و پارسر هدر اجرا شد، اما Windows API، SEH، قفل واقعی چندنخی، growth/eviction و allocator عمومی اجرا نشده‌اند. adapter سیستم‌عامل Linux فقط خواندنی است.
- BLTE و اعمال patch همچنان Python مستقل هستند، نه اجرای کامل مسیر خواندن سطح‌بالای Agent.
- قدم بعد، اتصال همین bridge به خروجی lookup اصلی و تکرار gateهای candidate/published و آزمون‌های recovery در پوشه چرخه جدید است؛ بدون تغییر بازی اصلی.
