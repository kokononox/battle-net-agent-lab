# ذخیره‌سازی CASC ساختگی و آزمون بازیابی تراکنش

## نتیجه و مرز اعتبار

این مرحله یک گام از «بازسازی bytes یک هدف Retail» به سمت «ساخت و اعتبارسنجی محل ذخیره‌سازی» است؛ **نصب‌کننده یا به‌روزرسان آمادهٔ WoW نیست**. تمام payloadهای این آزمایش رشته‌های تولیدشده در حافظه‌اند؛ فایل بازی، Lab و fixture آپلودشده ورودی این آزمایش نبوده‌اند. هیچ دانلود، اسکن نصب یا تغییر `.build.info` انجام نشد.

- ساخت span با پیش‌هدر ۳۰بایتی و BLTE، و ایندکس پیوستهٔ محلی v7 با کلید کوتاه ۹بایتی، مکان ۵بایتی و اندازهٔ little-endian انجام شد.
- یک ایندکس سه‌ورودی با bucket مشترک، توسط **خود توابع CaptureIndexHeader_V2 و CaptureGuardedBlock2 از CascLib** پذیرفته شد؛ سه نمونهٔ خراب‌شده رد شدند. این نتیجه فراخوانی کامل CascOpenStorage یا اجرای بازی نیست.
- الگوریتم Python برای Jenkins در ۲۱۰ بردار با کد C مرجع تطبیق یافت. این تطبیق دربارهٔ hash است، نه اثبات همهٔ معنای قالب CASC.
- بررسی کامل EKey، chunk و CKey علاوه بر کلید کوتاه ایندکس انجام می‌شود. برخورد prefix فعلاً رد می‌شود؛ حل عمومی برخورد پیاده نشده است.
- دو شیء ۲۵۰بایتی با ظرفیت مصنوعی ۵۱۲بایتی، در دو archive ذخیره و دوباره خوانده شدند.

## تراکنش آزمایشی

مدل اختصاصی از generationهای تغییرناپذیر، manifest دارای SHA256، journal و اشاره‌گر `active.json` استفاده می‌کند. **این اشاره‌گر و journal قرارداد Blizzard نیستند.** نوشتن در نسل قدیمی انجام نمی‌شود؛ هنگام بازیابی، مقصد rollback پیش از تغییر اشاره‌گر کاملاً اعتبارسنجی می‌شود. وضعیت متعارض بدون حدس‌زدن متوقف و شواهد حفظ می‌شود. orphanهای آماده‌سازی حذف نمی‌شوند.

۹ نقطهٔ مشخص، یک بار با exception و یک بار با خروج ناگهانی subprocess از طریق `os._exit(91)` آزمایش شدند. تا پیش از ثبت commit، بازگشایی به نسل قبلی برگشت؛ پس از ثبت commit، نسل جدید باقی ماند. هش نسل قبلی در ماتریس مستقل ثابت ماند و تکرار recovery پایدار بود. قفل واقعی بین دو پردازش نیز حالت busy و آزادشدن پس از خروج از lock را گذراند.

**۲۷۸ آزمون، بدون failure/error/skip** گذشت: ۲۳۴ آزمون قبلی و ۴۴ متد آزمون جدید. ماتریس ۹تایی درون آزمون‌هاست و نباید ۹ متد جداگانه شمرده شود. تعداد نقاط قطع، پوشش همهٔ دستورها یا همهٔ پنجره‌های شکست را نشان نمی‌دهد.

## موارد اثبات‌نشده

1. checksum-B پیش‌هدر از دستورالعمل جامعه برای Agent 8020 گرفته شده؛ سازگاری writer واقعی Agent 9824 اثبات نشده است. پذیرش ایندکس توسط CascLib، این پیش‌هدر را تأیید نمی‌کند.
2. activation واقعی، `shmem`، انتخاب نسل توسط بازی/Agent و سیاست `.build.info` هنوز پیاده یا آزمایش نشده‌اند.
3. این آزمون روی Linux است؛ Windows، قطع برق، خرابی دیسک و قطع حین خود recovery اثبات نشده‌اند. `fsync` و atomic rename جای آزمون قطع برق را نمی‌گیرند.
4. closure کامل یک build، همهٔ قالب‌های BLTE/patch، رمزگذاری و سیاست محصول/زبان/معماری هنوز دامنهٔ updater عمومی نشده‌اند.
5. مدل برای ابزارهای همکار و fixture اختصاصی است، نه دفاع کامل مقابل پردازش متخاصم که همزمان مسیرها را عوض می‌کند.
6. سقف‌های آزمایشی: ۳۲ شیء، ۲۵۶KiB decoded برای هر شیء و ۱۶MiB برای یک generation. این سقف‌ها ظرفیت نسخهٔ نهایی نیستند.

## بازتولید برای توسعه‌دهنده

این فایل‌ها افزونهٔ package موجود در مخزن هستند؛ لازم نیست کاربر آن‌ها را روی سیستم بازی اجرا کند. از ریشهٔ `downloader/patch_audit_lab` و با clone تمیز CascLib در commit زیر:

```sh
mkdir -p research/synthetic-casc-storage/native
sh research/synthetic-casc-storage/build_native.sh /path/to/CascLib research/synthetic-casc-storage/native
SYNTHETIC_NATIVE_DIR="$PWD/research/synthetic-casc-storage/native" python -B -m unittest discover -s tests -v
python -B research/synthetic-casc-storage/run_research.py research/synthetic-casc-storage/native/index_oracle
```

build script دانلود نمی‌کند و HEAD متفاوت یا تغییر tracked source را رد می‌کند. نبود مرجع native باعث skip دو آزمون مخصوص مرجع می‌شود؛ در اجرای گزارش‌شده هر دو اجرا شده‌اند و skip صفر بوده است. binary بومی در commit یا بستهٔ گزارش منتشر نشده است.

## شواهد و مرجع

- `TEST-RESULTS.json`: شمار آزمون‌ها، نسخهٔ Python و هش کد جدید.
- `ALL-TESTS.log`: خروجی واقعی مجموعهٔ کامل.
- `EXPERIMENT-RESULTS.json`: ماتریس قطع پردازش، نتایج native و rollover.
- `run_research.py`: سازندهٔ رسید مستقل از assertionهای unittest؛ از همان ماژول ذخیره‌سازی استفاده می‌کند و پیاده‌سازی مستقل تراکنش نیست.
- مرجع ثابت CascLib: commit `38a34665624b8775bb875274b36191b21c38d97b`، به‌ویژه `src/CascIndexFiles.cpp`، `src/CascStructs.h` و `src/jenkins/lookup3.c`.
- https://github.com/ladislav-zezula/CascLib/tree/38a34665624b8775bb875274b36191b21c38d97b
- https://wowdev.wiki/CASC — مرجع جامعه، نه تضمین رسمی قالب writer فعلی.

## گام بعدی فنی

پیش از هر writer واقعی: استخراج و اثبات قرارداد activation و binding نصب/هدف از شواهد واقعی، سپس validator فقط‌خواندنی برای همان قرارداد. این مدل rollback نباید به‌عنوان سازوکار واقعی Blizzard معرفی یا روی نصب واقعی اعمال شود.
