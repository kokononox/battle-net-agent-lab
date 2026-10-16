# چرخهٔ واقعی V8 با گیت اجباری bind، انتشار و بازیابی

> مرحلهٔ بعد: [lookup/iterator/merge اصلی](../lookup-merge-9824/README-fa.md) اکنون در مسیر عادی اجرا و به چرخه وصل شده است؛ offset/span واقعی source/target از خروجی اصلی آمده‌اند. suite فعلی ۶۴۶ آزمون است. رسید ۶۰۱تایی و hash آن متعلق به commit تاریخی `b0000b396ae15411cbc65ddf61778e4838373f58` است؛ چرخهٔ پایه در کد فعلی hook اضافی در نقاط locked گرفته، گیت bind قدیمی همچنان اجباری است. Windows و Agent archive I/O هنوز اثبات نشده‌اند.

## نتیجهٔ این مرحله

**V8 از یک نمونهٔ ایندکس پذیرفته‌شده به یک چرخهٔ به‌روزرسانی پژوهشیِ دارای بازیابی وصل شد.** نمونهٔ واقعی source حفظ می‌شود؛ target حاصل از پچ قبلاً تأییدشده به انتهای archive اضافه می‌شود؛ ایندکس V8 هدف ساخته و با تابع اصلی inner-bind/parser و full-key search Agent تأیید می‌شود؛ تنها پس از این گیت، control جدید منتشر می‌شود. بعد از انتشار هم همان گیت و بازخوانی مستقل داده‌ها دوباره اجرا می‌شوند.

**۶۰۱ آزمون، صفر failure/error/skip**، شامل ۵۶۳ قبلی + ۳۸ جدید. هر ۹ توقف سخت subprocess با exit=91 و resume موفق بررسی شد. در خطای mapping تزریقی، خود bind اصلی اجرا شد اما helper نگاشت خطای ۷۳ داد: کنترل قدیمی حفظ شد، journal در prepared ماند و ادامه با oracle واقعی موفق بود.

بازی، Lab، fixture اصلی، ZIP پرتابل و Release تغییر نکردند؛ خروجی فقط در owned store تازه ساخته شد. چرخهٔ V7 قبلی نیز فقط‌خواندنی ماند و hash فایل‌هایش پیش و پس یکسان بود. هیچ شبکه یا اسکن مجدد آرشیو بازی لازم نبود.

## ترتیب دقیق چرخه

۱. ورودی فقط owned cycle تکمیل‌شدهٔ مرحلهٔ قبلی است؛ marker/journal/identity/پچ و source/target آن کنترل می‌شوند. از source و prefix آن یک store تازهٔ V8 ساخته می‌شود؛ این مهاجرت یا ویرایش Lab اصلی نیست.
۲. ۱۶ ایندکس اولیهٔ V8 با ۱۷ رکورد (۱۶ prefix و یک source) ساخته و توسط binder اصلی پذیرفته می‌شوند. source در offset=480، span=188 و اندازهٔ archive=668 است.
۳. پیش از شروع یا resume، نمای فعلی با انتخاب sequence دقیقِ header، هر ۱۶ ایندکس و کلید کامل source/target مرئی تأیید می‌شود. بالاترین نام فایل ملاک نیست؛ فایل اضافی ناشناخته رد می‌شود.
۴. journal سفارشی با UUID/marker و hash دادهٔ نهایی bind می‌شود. target با append-only و کنترل پیشوندِ tail نیمه‌کاره افزوده می‌شود؛ archive نهایی ۸۵۶ بایت است. source/prefix و ۱۶ ایندکس اولیه تغییر نمی‌کنند.
۵. ایندکس جدید باکت target، با sequence=2، ابتدا در فایل موقت fsync و سپس با Linux renameat2(RENAME_NOREPLACE) نام‌گذاری می‌شود. تا اینجا header قدیمی باقی می‌ماند.
۶. **گیت اجباری پیش از انتشار:** ۱۶ ایندکس نمای candidate، strict V8 parser خودمان، inner-bind/parser اصلی Agent، جست‌وجوی اصلی full key16 برای source/target، و بازخوانی مستقل Python برای full EKey، checksumهای span، BLTE و CKey.
۷. control سفارشی در فایل موقت fsync و با os.replace و fsync پوشه منتشر می‌شود. در آرایهٔ sequence فقط باکت هدف ۱→۲ می‌شود؛ دادهٔ allocator سفارشی هم مطابق انتهای ۸۵۶بایتی تغییر می‌کند. این تعویض کل فایل در Linux است، نه store یک DWORD در mapping ویندوز.
۸. گیت واقعی و بازخوانی مستقل بعد از انتشار هم تکرار می‌شوند؛ سپس journal=committed. اجرای دوباره نیز **دوباره bind/readback می‌کند** و فقط پس از آن idempotent_noop می‌دهد؛ هیچ فایل عوض نمی‌شود.

API/CLI هیچ callback موفقِ پیش‌فرض یا مسیر Python-only برای دورزدن گیت ندارد. oracle باید رسید ساخت `agent-bind-contract-build-1` با digest دقیق Agent ثابت، ۳۴۴۲ بایت کد اصلیِ تأییدشده، NX/no-RWX و SHA256 مطابق ELF داشته باشد؛ نبود رسید یا دست‌کاری executable پیش از نوشتن رد می‌شود. این رسید محلی اعتماد به فرایند ساخت را ثبت می‌کند، امضای دیجیتال ناشر یا sandbox برای executable دلخواه نیست.

## آزمون خطا و resume

نقاط خروج: `prepared`، `target_half_appended`، `target_data_synced`، `index_temp_synced`، `index_named`، `index_bound`، `control_temp_synced`، `control_published` و `committed`. در هر ۹ کپی جدا، subprocess واقعاً با exit=91 قطع شد؛ ادامه با binder اصلی موفق بود؛ دادهٔ نهایی یکسان و اجرای مجدد بدون نوشتن بود.

در خطای نگاشت candidate، بایت‌های parser/bind اصلی جایگزین نشدند؛ فقط همان helper mock نگاشتِ harness خطای ۷۳ برگرداند. همهٔ ایندکس‌های نمای قدیم همچنان معتبر بودند. header جدید منتشر نشد، target/index آماده باقی ماند و اجرای بعدی بدون دانلود دوباره به committed رسید. این بررسی منطق caller خودمان است، نه اثبات handling لایهٔ بالاترِ خود Agent در ویندوز.

آزمون‌های دیگر: خرابی source/index، generation و فایل ناشناخته، marker/journal ناسازگار، symlink داده، خروجی موجود، oracle غایب/نامعتبر/دست‌کاری‌شده، حفظ source و ایندکس‌های اولیه و انتخاب sequence دقیق.

## معنی دو qword: یک قدم واقعی، نه ادعای کامل

تابع خالص اصلی `0x72d18f..0x72d1f8`، **۱۰۵ بایت بدون تغییر و بدون هیچ helper خارجی**، در ELF محدود Linux i386 اجرا شد. ورودی آن request(start64,length64)، value(base64,extent64) و outLength است. این primitive:

- start را با qword دوم value مقایسه می‌کند؛ start>extent رد می‌شود.
- length=0xffffffffffffffff را «از start تا انتهای extent» می‌گیرد.
- در غیر این صورت، start+length را به‌صورت ۶۴بیتی با extent مقایسه می‌کند.
- qword اول value را در این تابع نمی‌خواند. در caller `0x72c794..0x72c7bf` به‌صورت **استاتیک** دیده شد که qword اولِ مقدار iterator با request.start جمع می‌شود و همراه طول محاسبه‌شده به خروجی می‌رود. خود این caller/iterator و مسیر read/merge کامل در این مرحله اجرا نشدند.

۲۱۷۶ بردار مرزی/تصادفی با مدل مطابق بودند. مثلاً برای extent=188، start=30 و sentinel طول، خروجی ۱۵۸ است. در ورودی‌های افراطی، wrap جمع ۶۴بیتی یا overflowِ base می‌تواند به‌علت محدودبودن بررسی این primitive، از پذیرش آن عبور کند؛ سیاست مستقل ما هر wrap/overflow را رد می‌کند. **۴۱۵ بردارِ پذیرفته‌شده توسط primitive ولی مردودِ سیاست سخت‌گیرانه** ثبت شد. این شامل دو علتِ wrap نسبی و overflow آدرس مطلق است؛ ادعای آسیب‌پذیری یا رسیدن چنین ورودی‌هایی در محصول نیست، چون محدودیت callerهای دیگر و مسیر کامل بررسی نشده‌اند.

بنابراین شواهدِ base/extent بهتر شد، ولی اتصال کامل رکورد key16+value16 تا archive/BLTE توسط خود Agent همچنان اثبات نشده است. چرخهٔ ما هنوز offset/span برای archive صفر را به‌عنوان سیاست fixture صریح به کار می‌برد و EKey/CKey را با Python مستقل کنترل می‌کند؛ نباید آن را «Agent بازی را از archive خواند» نامید.

## شواهد دادهٔ واقعی

- source EKey: `914fcad4f4fcf4abb0ba52b197bb066f`، offset=480، span=188.
- target EKey: `faedca88d0a0ab30dae5519239582d31`، offset=668، span=188.
- target CKey مستقل از Encoding: `3d42bf2e42127f313b0ec64cb440cde9`.
- source CKey مشتق، نه مقدار مستقل موردانتظار: `98ad7b81687304aa0e99cf326200adfe`.
- archive نهایی SHA256: `0bc16095b26bc8d1e0c8d3aaba86502e9938f932ccf093e0c135531f1f2861b1`.
- نمونه نهایی: ۱۶ ایندکس انتخاب‌شده، ۱۸ رکورد، دو آبجکت decoded هر کدام ۳۳۹۴۰ بایت؛ فایل seq1 قدیمیِ باکت هدف هم حفظ می‌شود.

## بازتولید

از ریشهٔ `downloader/patch_audit_lab`، روی Linux دارای ELF i386 و GNU as/ld؛ oracle bind را مطابق [مرحلهٔ bind V8](../bind-contract-9824/README-fa.md) بسازید و رسید را کنار executable نگه دارید.

```bash
PYTHONPATH=. python research/retail-v8-cycle/native/build_value_range.py \
  --agent /path/to/pinned/Agent.9824.exe --out-new /new/value-native
PYTHONPATH=. python research/retail-v8-cycle/run_experiments.py \
  --prior-owned-cycle /path/to/completed/v7-owned-cycle \
  --bind-oracle /path/to/bind-native/bind_contract_oracle \
  --value-oracle /new/value-native/value_range_oracle \
  --out-new /new/v8-experiment
```

برای اجرای دستی چرخه، `retail_v8_cycle.py create/status/advance` است؛ `--oracle` در همهٔ حالت‌ها اجباری است. create فقط `--prior-v7-owned-cycle` و `--out-new` می‌پذیرد؛ status/advance با `--root` روی marker تازهٔ V8 کار می‌کنند. روی پوشهٔ بازی، Lab، fixture یا store قبلی اجرا نکنید؛ مسیر خروجی باید تازه باشد.

برای suite کامل، متغیرهای مراحل قبلی را همراه `BIND_CONTRACT_ORACLE`، `VALUE_RANGE_ORACLE` و `V8_PRIOR_CYCLE` تنظیم کنید. رسید ۶۰۱ آزمون بدون skip و hash کد در `TEST-RESULTS.json` و `ALL-TESTS.log` است. `CYCLE-EXPERIMENT.json`، `VALUE-MATRIX.json` و `VALUE-FRAGMENT-BUILD-RECEIPT.json` نتایج قابل‌بررسی‌اند. فقط source/گزارش/رسید منتشر می‌شوند؛ PE/ELF، raw fragment، ایندکس یا archive تازه آپلود نمی‌شوند.

## مرز نتیجه و گام بعد

این چرخه از milestone قبلی قوی‌تر است: هم V8 واقعی دارد، هم گیت اجباریِ binder اصلی، هم بازیابی خطای bind و ۹ قطع subprocess. اما journal/قفل/publication، **سفارشیِ Linux و برای پژوهش** هستند؛ قطع subprocess اثبات قطع برق یا durability ویندوز نیست. Windows Agent، SEH بیرونی، قفل‌های واقعی، نام/binding نصب کاربر، read/merge کامل و activation بازی هنوز اجرا نشده‌اند. writer نصب اصلی آماده نیست.

گام بعد، اجرای محدود iterator/merge و مسیر مصرف value با دادهٔ واقعی، سپس آزمون نگاشت/قفل و publication در کپی جداگانهٔ Windows است؛ هنوز نباید روی نصب اصلی چیزی بنویسیم.
