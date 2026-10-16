# از bind ایندکس تا lookup/iterator/merge اصلی و بازخوانی target واقعی

## نتیجهٔ اساسی

**این بار offset و طول داده را مسیر اصلیِ lookup خود Agent برگرداند؛ نه اینکه فقط دو qword را خودمان تفسیر کنیم.** ورودی V8 نمونهٔ واقعی از inner-bind/parser به key lookup، جمع‌آوری tail، iterator، اعمال عملیات، مرتب‌سازی/ادغام پوشش، بررسی محدوده و ساخت خروجی می‌رود. مسیر اصلی برای source مقدار `(480,188)` و برای target مقدار `(668,188)` برگرداند. همان خروجی به reader مستقل Python داده شد و full EKey، checksumهای span، BLTE و CKey هدف پچ‌شده تأیید شدند.

زنجیرهٔ محدودِ اکنون اثبات‌شده: **V8 index → bind اصلی → lookup/merge/range اصلی → offset/length برگشتی → خواندن و تأیید مستقل target واقعی → انتشار/بازیابی چرخهٔ پژوهشی**. بخش خواندن فایل archive و decode با خود Agent هنوز اجرا نشده‌اند؛ این اجرای WoW یا Windows Agent نیست.

**۶۴۶ آزمون، صفر failure/error/skip**: ۶۰۱ قبلی + ۴۵ تازه. ماتریس ۳۱۲۲ بردار همه با مدل مطابق بود؛ ۳۰۰۰ ترکیب تصادفی، ۱۱۲ حالتِ ۱۶ باکت × ۷ عملیات tail و ۱۰ سناریوی مشخص. statusهای lookup در این ماتریس: ۰ موفق (۴۵۶)، ۲ ناموجود (۱۱۸۴)، ۳ پوشش ناکافی (۲۲۶)، ۴ محدودهٔ نامعتبر (۱۲۵۶). این معنی‌ها متعلق به مسیر محدودِ مشاهده‌شده‌اند، نه فهرست جامع کدهای خطای محصول.

## چه کدی اجرا شد و چه چیزی mock ماند؟

۲۱ تابع/قطعهٔ اصلی، **۶۱۴۸ بایت کد بدون تغییر** و **۳۴۴ بایت جدول پرش اصلی**، در ELF محدود Linux i386 در VA اصلی قرار گرفتند. SHA256 PE و بایت‌های همهٔ قطعه‌ها داخل ELF تأیید شد؛ ۷۰ call مستقیم و جدول‌های پرش بررسی شدند. PE کامل اجرا نشد.

ده تابع bind/hash/key-search مرحلهٔ قبل حفظ شدند. توابع تازهٔ اصلی:

| نقش | شروع | انتهای خارج از بازه |
|---|---|---|
| lookup و ساخت خروجی base+start/length | 0x72c6fd | 0x72c80c |
| انتخاب primary و جمع‌آوری tail متناظر | 0x72c56e | 0x72c6fd |
| ساخت iterator با ظرفیت inline | 0x72e4f7 | 0x72e54a |
| بارگذاری رکوردها در iterator | 0x72f31b | 0x72f41c |
| اعمال operationهای ۱ تا ۷ | 0x72f0be | 0x72f1a9 |
| افزودن رویدادهای ابتدا/انتهای بازه | 0x72f280 | 0x72f31b |
| ادغام رویدادها/پوشش | 0x72e7de | 0x72e8ab |
| اعتبارسنجی request نسبت به extent | 0x72d18f | 0x72d1f8 |
| کنترل پوشش بازهٔ درخواستی | 0x72f41c | 0x72f4a7 |
| افزودن pointer به vector inline | 0x694bdc | 0x694c14 |
| sorter اصلی، مسیر کوچک insertion-sort | 0x718dcc | 0x7190ed |

**خود lookup، iterator، عملیات، sorter، merge، range و coverage با مدل جایگزین نشدند.** در مقابل، ۱۸ مقصد helper صریح mock یا trap هستند: file-length/map/unmap، logger/error/memcmp، prolog/epilog با frame عادیِ پژوهشی، دو destructor حافظه با کنترل inline بودن، warning و مسیرهای ممنوع رشد حافظه/مرتب‌سازی بزرگ. prolog/epilog، Windows SEH، FS registration، dispatch یا unwinding را پیاده نمی‌کنند. destructorها فقط وقتی pointer/capacity همان بافر inline باشد اجازهٔ ادامه می‌دهند؛ allocator واقعی یا heap ownership Agent اجرا نشد.

محدودهٔ ورودی: mode=1 و فایل غیرخالی حداکثر ۱MiB، تا ۱۰۲۴ رکورد primary، تا ۶۴ slot tail، **حداکثر ۷ رکورد matching برای کلید در هر درخواست**، رکوردهای مرتب و بازه‌های بدون overflow. این تعداد مسیر را داخل ظرفیت inline نگه می‌دارد؛ رشد حافظه و sorter بزرگ به توقف سخت harness می‌روند. ورودی فایل با mprotect فقط‌خواندنی، شیء با canary، stack غیرقابل‌اجرا، بدون dynamic linker و بدون segment هم‌زمان writable/executable است. این fuzz عمومی همهٔ مسیرهای PE یا اثبات رفتار در استثنا نیست.

## معنی value و پوشش: پیشرفت نسبت به مرحلهٔ قبل

در مرحلهٔ قبلی primitiveِ range اجرا شده بود، اما caller/iterator فقط استاتیک بررسی شده بودند. اکنون همان caller اصلی نیز در مسیر عادی اجرا شد: value از رکوردهای index به iterator رسید، qword اول در `base+request.start` مصرف شد و qword دوم حد نسبی request بود؛ طول sentinel تا انتهای extent محاسبه و خروجی ساخته شد. برای archive صفرِ همین fixture، اعداد خروجی دقیقاً به span درست source/target اشاره کردند.

همچنان چیزی را تعمیم نمی‌دهیم: unpack آدرس چند archive، انتخاب/بازکردن data.NNN، اجرای read فایل، decode با Agent، binding نصب کاربر و Windows هنوز اثبات نشده‌اند. اثرات integer overflow افراطی که در primitive قبلی بررسی شد، اینجا با سیاست ورودی nonwrapping کنار گذاشته می‌شوند.

همچنین «کلید پیدا شد» شرط کافی سلامت نبود:

- یک primary ساده، محدودهٔ کامل متناظر را قابل‌خواندن کرد.
- tail با operation=1 توانست رکورد را بسازد/جایگزین کند؛ operation=3 presence را پاک کرد.
- operation=7 در سناریوی کنترل‌شده حفرهٔ پوشش ایجاد کرد؛ lookup کل بازه را با status=3 رد کرد، ولی prefix/suffix پوشیده را پذیرفت.
- operation=6 در سناریوی تست، حفره را پر کرد و درخواست کامل پذیرفته شد.
- در primaryهای دارای full-key تکراری، اولین value به‌عنوان descriptor پایه مصرف شد و رکوردهای بعدی پوشش را ساختند؛ دو تکهٔ گسسته برای درخواست کامل status=3 دادند.
- کلیدهایی با ۹ بایت آغازین یکسان و ۷ بایت پایانی متفاوت درست تفکیک شدند. tail متناظر پس از ۲۶ رکورد نامرتبط و عبور از مرز صفحه نیز پیدا شد.

این‌ها نام‌گذاری پژوهشیِ رفتار مشاهده‌شده‌اند؛ هنوز ثابت نکرده‌ایم تمام این عملیات در همهٔ workflowهای محصول چگونه تولید می‌شوند.

## اتصال به چرخهٔ واقعی و بازیابی

ورودی جدید `retail_lookup_cycle.py`، هم `--bind-oracle` و هم `--lookup-oracle` را الزام می‌کند و digest executable و رسید ساخت pinned را کنترل می‌کند. از callback موفقِ پیش‌فرض برای bypass گیت lookup استفاده نمی‌کند. چرخهٔ V8 پایه فقط hook اضافیِ صریح در همان نقاط locked دریافت کرده؛ گیت bind قبلی همیشه فعال است و همهٔ ۶۰۱ تست قبلی نیز دوباره اجرا شدند.

گیت تکمیلی در نمای اولیه/پیش از ادامه، روی candidate **قبل از انتشار control**، پس از انتشار و حتی no-op تکرار می‌شود. status صفر bind به‌تنهایی کافی نیست: lookup باید واقعاً اجرا شده و صفر بدهد، offset/length به محدودهٔ موردانتظار fixture اشاره کند و خواندن مستقل از همان range، EKey/checksum/CKey را تأیید کند.

هر ۹ خروج سخت subprocess با exit=91 روی چرخهٔ تقویت‌شده هم آزمایش شد؛ همه با گیت اصلی lookup resume شدند و اجرای بعدی بدون تغییر فایل ماند. source/prefix و ۱۶ ایندکس اولیه حفظ شدند؛ archive نهایی ۸۵۶ بایت و SHA256 آن `0bc16095b26bc8d1e0c8d3aaba86502e9938f932ccf093e0c135531f1f2861b1` است.

**خطای پوشش واقعی در تست caller:** فقط در مرز ورودیِ lookupِ candidate، یک ایندکس synthetic سالم با tail حفره‌ساز به oracle داده شد؛ فایل واقعی candidate یا بازی دست‌کاری نشد. توابع semantic اصلی status=3 برگرداندند؛ caller پژوهشی control قدیمی و journal=prepared را حفظ کرد. پس از حذف این تزریق ورودی و استفاده از ایندکس واقعی، ادامه موفق شد. این اثبات handling در کد چرخهٔ خودمان است، نه handling همهٔ لایه‌های Windows Agent.

source EKey `914fcad4f4fcf4abb0ba52b197bb066f` و target EKey `faedca88d0a0ab30dae5519239582d31` هستند؛ target CKey مستقل Encoding برابر `3d42bf2e42127f313b0ec64cb440cde9` است. CKey source همچنان مشتق از نمونه است و مقدار مستقل موردانتظار نیست. خروجی decoded هر آبجکت ۳۳۹۴۰ بایت تأیید شد.

## شواهد و بازتولید

رسیدها: `FRAGMENT-BUILD-RECEIPT.json`، `MATRIX-RESULTS.json`، `CYCLE-EXPERIMENT.json`، `TEST-RESULTS.json` و `ALL-TESTS.log`. فقط کد، disassembly متنی و رسیدها منتشر می‌شوند؛ PE، ELF، raw fragment، index یا archive تازه به مخزن آپلود نمی‌شود. فایل‌های Lab، بازی، fixture اصلی، پرتابل و Release تغییر نکردند و hash فایل‌های owned cycle قبلی نیز ثابت بود.

از ریشهٔ `downloader/patch_audit_lab` در Linux دارای ELF i386 و GNU as/ld؛ bind oracle را مطابق [مرحلهٔ bind V8](../bind-contract-9824/README-fa.md) بسازید:

```bash
PYTHONPATH=. python research/lookup-merge-9824/native/build.py \
  --agent /path/to/pinned/Agent.9824.exe --out-new /new/lookup-native
PYTHONPATH=. python research/lookup-merge-9824/run_experiments.py \
  --prior-owned-cycle /path/to/completed/v7-owned-cycle \
  --bind-oracle /path/to/bind-native/bind_contract_oracle \
  --lookup-oracle /new/lookup-native/lookup_merge_oracle \
  --out-new /new/lookup-experiment
```

برای suite کامل، متغیرهای native/fixture قبلی را همراه `LOOKUP_MERGE_ORACLE` تنظیم کنید. رسید ۶۴۶ آزمون بدون skip و hash کد فعلی ثبت است. گزارش ۶۰۱تایی و hash کد آن checkpoint تاریخیِ commit قبلی است؛ فایل چرخهٔ پایه اکنون فقط hookهای گیت اضافی گرفته است.

## مرز نتیجه و گام بعد

این گام، شکاف واقعی میان «ایندکس پذیرفته شد» و «مسیر اصلی، محل و پوشش آبجکت را مشخص کرد» را در نمونهٔ محدود بست. **هنوز updater آمادهٔ نوشتن روی نصب اصلی نداریم.** Journal، قفل و publication همچنان Linux سفارشی‌اند؛ توقف subprocess اثبات قطع برق یا durability نیست. SEH/قفل/نگاشت ویندوز، heap و مسیرهای بزرگ، read فایل archive و decode توسط خود Agent، نصب چندآرشیوی و activation واقعی اجرا نشده‌اند.

گام بعد ردیابی مصرف range در مسیر archive-open/read خود Agent و قرارداد archive شماره‌دار، سپس اجرای Windows mapping/locking/publication روی کپی جدا است؛ نصب اصلی همچنان نباید مقصد writer پژوهشی باشد.
